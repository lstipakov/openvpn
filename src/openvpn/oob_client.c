/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2026 OpenVPN Inc <sales@openvpn.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "syshead.h"

#include "oob_client.h"
#include "openvpn.h"
#include "oob.h"
#include "init.h"
#include "ssl.h"
#include "ssl_pkt.h"
#include "session_id.h"
#include "socket.h"
#include "socket_util.h"
#include "otime.h"
#include "fdmisc.h"
#include "crypto.h"
#include "dco.h"
#include "error.h"

#include "memdbg.h"

/* Total time we wait for probe replies before giving up and connecting. */
#define OOB_PROBE_WINDOW_MS 1000

/* Number of times an unanswered probe is resent within the window, to ride out
 * UDP packet loss. With this set to 1, each remote is probed up to 2 times,
 * which removes the single-packet-loss false negative; further retries give
 * sharply diminishing returns for a low-stakes selection. */
#define OOB_PROBE_RETRIES 1

/* Where we sent a probe, so a reply's source address can be matched back to the
 * connection-list entry it belongs to. A remote may resolve to several
 * addresses, all of which are probed; a reply from any of them counts. The
 * dests / destlens arrays are gc-allocated, sized to the remote's resolved
 * address count. */
struct probe_target
{
    struct sockaddr_storage *dests;
    socklen_t *destlens;
    int n_dests;
    bool is_tcp;            /* probed over per-address TCP connections instead of the
                             * shared UDP sockets; excluded from UDP resend/addr-match */
    int outstanding;        /* TCP: addresses still queued or in flight; the target
                             * settles (as a non-responder) when this reaches 0 */
    bool sent;
    struct timeval sent_at; /* when the probe was sent, for RTT measurement */
};

/* The probe uses one native socket per address family, so every remote is probed
 * on an AF-native socket (no IPv4-mapped addresses). The winning remote's socket
 * can then be reused as its connection socket, presenting the same source
 * IP+port the server bound its handshake cookie to. */
#define PROBE_AF_V4    0
#define PROBE_AF_V6    1
#define PROBE_AF_COUNT 2

/* A TCP remote is probed with a full connection per resolved address: connect,
 * send the length-prefixed probe, read the length-prefixed reply, close. The
 * connects are non-blocking and run in parallel with each other and with the
 * UDP probes, inside the same select loop and probe window. RTT is measured
 * probe-to-reply (the connect is not counted), so TCP and UDP measurements are
 * comparable.
 *
 * This caps concurrency, not coverage: at most this many connections are in
 * flight at once (the fd set must stay below every platform's select() limit:
 * 64 sockets per set on Windows, fd values < FD_SETSIZE elsewhere), and the
 * remaining addresses wait in a queue, each started as soon as a connection
 * settles and frees its slot. The queue is ordered round-robin by remote --
 * every remote's first address before any remote's second -- so no remote is
 * starved by an earlier one that resolves to many addresses. */
#define OOB_TCP_PROBE_MAX_CONNS 32

/* One queued TCP probe: an address (by index) of a target still to be tried. */
struct oob_tcp_pending
{
    int target; /* index into targets[]/results[] */
    int addr;   /* index into that target's dests[] */
};

enum oob_tcp_state
{
    OOB_TCP_CONNECTING,  /* non-blocking connect in flight: watch writable/except */
    OOB_TCP_SENDING,     /* connected, framed probe not fully written: watch writable */
    OOB_TCP_AWAIT_REPLY, /* probe sent: watch readable */
    OOB_TCP_CLOSED,      /* settled (replied, failed or refused); sd closed */
};

struct oob_tcp_conn
{
    socket_descriptor_t sd;
    enum oob_tcp_state state;
    int target;                   /* index into targets[]/results[] */
    struct sockaddr_storage dest; /* the one address this connection probes */
    int tx_off;                   /* bytes of the framed probe already written */
    struct timeval sent_at;       /* probe fully written -> RTT start */
    struct oob_frame_reader rd;   /* exact-read reassembly of the framed reply */
};

struct probe_ctx
{
    socket_descriptor_t sd[PROBE_AF_COUNT]; /* SOCKET_UNDEFINED if that AF is unavailable */
    struct oob_tcp_conn *tcp;               /* gc array of OOB_TCP_PROBE_MAX_CONNS slots */
    int n_tcp;                              /* slot high watermark; closed slots are reused */
    struct oob_tcp_pending *queue;          /* gc array: addresses not yet connected */
    int queue_len;
    int queue_head;                         /* next queue entry to start */
};

/* af is an int (not sa_family_t) so callers can pass addrinfo::ai_family
 * directly without a narrowing conversion (-Werror=conversion). */
static int
probe_af_index(int af)
{
    return (af == AF_INET6) ? PROBE_AF_V6 : PROBE_AF_V4;
}

/* Build a standalone control-channel wrapping context for the probe, mirroring
 * the tls_auth_standalone the server uses to answer it. With neither tls-auth
 * nor tls-crypt configured the context stays in TLS_WRAP_NONE and the probe is
 * sent in plaintext, exactly as before; with either configured the probe is
 * authenticated/encrypted like any other control packet. Returns NULL (and
 * logs) for configurations the probe cannot wrap yet, in which case the caller
 * skips probing and keeps the configured remote order. */
static struct tls_auth_standalone *
oob_probe_init_tls_auth_standalone(struct context *c, struct gc_arena *gc)
{
    /* The probe runs before next_connection_entry() maps a connection entry
     * into options.ce, so take the wrapping config from the first connection
     * entry directly. A global --tls-auth/--tls-crypt is copied into every
     * connection-list entry by options_postprocess_mutate_ce(), so the first
     * entry carries it even though options.ce does not yet. (Probing wraps a
     * single packet for all remotes, so per-connection-block keys are not
     * supported; the first entry's wrapping is used for all.) */
    const struct connection_entry *ce = c->options.connection_list->array[0];

    /* Load the tls-auth/tls-crypt(-v2) key material into c->c1.ks (a no-op if
     * none is configured). This is run again per-connection later; calling it
     * early here is harmless. */
    do_init_tls_wrap_key(c, ce);

    struct tls_options to;
    CLEAR(to);
    init_tls_wrap_ctx(&to.tls_wrap, ce, c->options.tls_client, &c->c1.ks, &c->c1.pid_persist);
    to.replay_window = c->options.replay_window;
    to.replay_time = c->options.replay_time;

    /* tls-crypt-v2 wraps with a per-client key the server learns from the
     * wrapped client key (WKc). init_tls_wrap_ctx() loaded the per-client key
     * into the wrap context; make the WKc available too so the probe can append
     * it (as a P_CONTROL_OOB_WKC_V1 message), mirroring init_instance(). */
    if (ce->tls_crypt_v2_file)
    {
        to.tls_wrap.tls_crypt_v2_wkc = &c->c1.ks.tls_crypt_v2_wkc;
    }

    struct tls_auth_standalone *tas = tls_auth_standalone_init(&to, gc);

    /* Control-channel frame and work buffers, mirroring do_init_frame_tls(). */
    tls_init_control_channel_frame_parameters(&tas->frame, ce->tls_mtu);
    tas->tls_wrap.work = alloc_buf_gc(BUF_SIZE(&tas->frame), gc);
    tas->workbuf = alloc_buf_gc(BUF_SIZE(&tas->frame), gc);

    return tas;
}

/* Open one native UDP probe socket per address family (v4 and v6). Each is
 * AF-native (the v6 socket is set IPV6_V6ONLY so no IPv4-mapped traffic crosses
 * it), so a remote is always probed on a socket that can later serve as its
 * connection socket. Unavailable families are left SOCKET_UNDEFINED. Returns the
 * number of sockets opened. */
static int
oob_probe_sockets_open(struct probe_ctx *pc)
{
    int opened = 0;

    pc->sd[PROBE_AF_V4] = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (pc->sd[PROBE_AF_V4] != SOCKET_UNDEFINED)
    {
        set_cloexec(pc->sd[PROBE_AF_V4]);
        opened++;
    }

    pc->sd[PROBE_AF_V6] = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (pc->sd[PROBE_AF_V6] != SOCKET_UNDEFINED)
    {
        set_cloexec(pc->sd[PROBE_AF_V6]);
        int on = 1;
        if (setsockopt(pc->sd[PROBE_AF_V6], IPPROTO_IPV6, IPV6_V6ONLY, (void *)&on, sizeof(on)) != 0)
        {
            msg(D_LOW, "server-probe: could not set IPV6_V6ONLY on probe socket");
        }
        opened++;
    }

    return opened;
}

static void
oob_probe_sockets_close(struct probe_ctx *pc)
{
    for (int i = 0; i < PROBE_AF_COUNT; i++)
    {
        if (pc->sd[i] != SOCKET_UNDEFINED)
        {
            openvpn_close_socket(pc->sd[i]);
            pc->sd[i] = SOCKET_UNDEFINED;
        }
    }
    /* TCP probe connections are never handed off -- always closed */
    for (int k = 0; k < pc->n_tcp; k++)
    {
        if (pc->tcp[k].sd != SOCKET_UNDEFINED)
        {
            openvpn_close_socket(pc->tcp[k].sd);
            pc->tcp[k].sd = SOCKET_UNDEFINED;
        }
        pc->tcp[k].state = OOB_TCP_CLOSED;
    }
    pc->n_tcp = 0;
}

/* Send the probe to every resolved address of t, each on the socket matching
 * its address family. Returns true if at least one send succeeded. */
static bool
oob_probe_send_target(const struct probe_ctx *pc, const struct buffer *probe,
                      const struct probe_target *t)
{
    bool any_sent = false;
    for (int k = 0; k < t->n_dests; k++)
    {
        socket_descriptor_t sd = pc->sd[probe_af_index(t->dests[k].ss_family)];
        if (sd == SOCKET_UNDEFINED)
        {
            continue;
        }
        if (sendto(sd, (const char *)BPTR(probe), (int)BLEN(probe), 0,
                   (const struct sockaddr *)&t->dests[k], t->destlens[k])
            >= 0)
        {
            any_sent = true;
        }
    }
    return any_sent;
}

/* Parse one received packet as a PROBE_REPLY, shared by the UDP (datagram) and
 * TCP (deframed stream packet) receive paths.
 *
 * The reply's own session id (the server's stateless SYN-cookie) follows the
 * opcode byte; it is captured into @p server_sid before read_control_auth()
 * strips it, since a client may reuse it to skip to the third handshake packet
 * (the connect_lifetime shortcut). The reply is unwrapped with the same
 * control-channel path the server used to wrap it: this verifies the tls-auth
 * HMAC / decrypts tls-crypt, and (in all modes) strips the opcode + server
 * session id. With no tls-auth/tls-crypt it just strips those header bytes.
 * read_control_auth() mutates the wrapping context, so a per-packet copy is
 * used (as tls_pre_decrypt_lite() does on the server).
 *
 * @return true if the packet is a well-formed reply that echoes our probe's
 *         session id (spoofed replies are rejected), false otherwise
 */
static bool
oob_probe_reply_parse(uint8_t *data, int len, const struct session_id *client_sid,
                      const struct tls_wrap_ctx *base_wrap, struct oob_probe_reply *reply,
                      struct session_id *server_sid)
{
    /* Need at least the opcode byte and the session id. */
    if (len < 1 + (int)SID_SIZE || (data[0] >> P_OPCODE_SHIFT) != P_CONTROL_OOB_V1)
    {
        return false;
    }

    /* The reply's own session id (the server's stateless SYN-cookie) follows the
     * opcode byte. Capture it before read_control_auth() strips it: a client may
     * reuse it to start the handshake from this reply (the connect_lifetime
     * advertisement). */
    memcpy(server_sid->id, data + 1, SID_SIZE);

    struct buffer buf;
    buf_set_read(&buf, data, (size_t)len);

    /* Unwrap the reply with the same control-channel path the server used to
     * wrap it: this verifies the tls-auth HMAC / decrypts tls-crypt, and (in all
     * modes) strips the opcode + server session id, leaving buf at the TLV
     * payload. read_control_auth() mutates the wrapping context, so we work on a
     * per-packet copy (as tls_pre_decrypt_lite() does on the server). The peer
     * address is only used for log messages, and tls_options only for
     * tls-crypt-v2 metadata checks, so both are passed as NULL. */
    struct tls_wrap_ctx wrap = *base_wrap;
    if (!read_control_auth(&buf, &wrap, NULL, NULL))
    {
        return false; /* not for us, or failed authentication */
    }

    if (!oob_client_reply_read(&buf, reply))
    {
        return false;
    }

    return session_id_equal(&reply->peer_session_id, client_sid);
}

/* Fill @p res from a validated reply: RTT measured from @p sent_at, and the
 * address that answered pinned for the connection (and the UDP shortcut). */
static void
oob_probe_record_result(struct oob_probe_result *res, const struct oob_probe_reply *reply,
                        const struct session_id *server_sid, const struct timeval *sent_at,
                        const struct sockaddr_storage *responder)
{
    struct timeval rcv;
    openvpn_gettimeofday(&rcv, NULL);
    long ms = (long)(rcv.tv_sec - sent_at->tv_sec) * 1000 + (rcv.tv_usec - sent_at->tv_usec) / 1000;

    res->responded = true;
    res->rtt_ms = (ms > 0) ? (unsigned int)ms : 0;
    res->server_sid = *server_sid;
    res->responder = *responder;
    res->reply = *reply;
}

/* Parse one received datagram as a PROBE_REPLY and, if valid and matching one
 * of the UDP probes we sent, record the reply in results. */
static void
oob_probe_handle_reply(uint8_t *data, int len, const struct session_id *client_sid,
                       const struct tls_wrap_ctx *base_wrap, const struct sockaddr_storage *from,
                       const struct probe_target *targets, struct oob_probe_result *results, int n)
{
    struct oob_probe_reply reply;
    struct session_id server_sid;
    if (!oob_probe_reply_parse(data, len, client_sid, base_wrap, &reply, &server_sid))
    {
        return;
    }

    /* Match the reply's source address to one of the addresses we probed for a
     * remote. The first reply for a remote wins (a remote with several addresses
     * may answer from more than one). TCP targets never match: their replies
     * arrive on their own connections, and a UDP source may coincide with a
     * TCP target's address when a server offers both protocols on one port. */
    for (int i = 0; i < n; i++)
    {
        if (!targets[i].sent || targets[i].is_tcp || results[i].responded)
        {
            continue;
        }

        bool match = false;
        for (int k = 0; k < targets[i].n_dests && !match; k++)
        {
            match = addr_port_match((const struct openvpn_sockaddr *)(const void *)from,
                                    (const struct openvpn_sockaddr *)(const void *)&targets[i].dests[k]);
        }
        if (!match)
        {
            continue;
        }

        oob_probe_record_result(&results[i], &reply, &server_sid, &targets[i].sent_at, from);
        break;
    }
}

/* Did the last socket call fail only because it would have blocked? */
static bool
oob_sock_would_block(void)
{
    const int err = openvpn_errno();
#ifdef _WIN32
    return err == WSAEWOULDBLOCK;
#else
    return err == EAGAIN || err == EWOULDBLOCK;
#endif
}

static void
oob_tcp_conn_close(struct oob_tcp_conn *conn)
{
    if (conn->sd != SOCKET_UNDEFINED)
    {
        openvpn_close_socket(conn->sd);
        conn->sd = SOCKET_UNDEFINED;
    }
    conn->state = OOB_TCP_CLOSED;
}

/* A connection settled without recording a reply (or after recording one):
 * close it and account for it, so its target can settle and its slot can
 * host the next queued address. */
static void
oob_tcp_conn_settle(struct oob_tcp_conn *conn, struct probe_target *targets)
{
    targets[conn->target].outstanding--;
    oob_tcp_conn_close(conn);
}

/* Begin one non-blocking probe connect to @p dest for target @p target_idx,
 * in connection slot @p slot. Returns true if the connection is now in flight
 * (or already connected), false on socket/connect failure. */
static bool
oob_probe_tcp_connect_start(struct probe_ctx *pc, int slot, int target_idx,
                            const struct sockaddr *dest, socklen_t destlen)
{
    socket_descriptor_t sd = socket(dest->sa_family, SOCK_STREAM, IPPROTO_TCP);
    if (sd == SOCKET_UNDEFINED)
    {
        return false;
    }
#ifndef _WIN32
    if (sd >= FD_SETSIZE)
    {
        /* select() cannot watch this fd value; the probe runs at startup, so
         * this only triggers in fd-exhausted environments */
        openvpn_close_socket(sd);
        return false;
    }
#endif
    set_cloexec(sd);
    set_nonblock(sd);

    struct oob_tcp_conn *conn = &pc->tcp[slot];
    CLEAR(*conn);
    conn->sd = sd;
    conn->target = target_idx;
    memcpy(&conn->dest, dest, destlen);

    if (connect(sd, dest, destlen) == 0)
    {
        conn->state = OOB_TCP_SENDING; /* connected instantly; send on first writable */
    }
    else
    {
        const int err = openvpn_errno();
        if (
#ifdef _WIN32
            err != WSAEWOULDBLOCK
#else
            err != EINPROGRESS
#endif
        )
        {
            /* The slot was claimed before connect(); a reused slot left in
             * OOB_TCP_CONNECTING (== 0, the CLEAR state) with a closed fd
             * would be armed into select() forever. */
            conn->state = OOB_TCP_CLOSED;
            conn->sd = SOCKET_UNDEFINED;
            openvpn_close_socket(sd);
            return false;
        }
        conn->state = OOB_TCP_CONNECTING;
    }

    if (slot >= pc->n_tcp)
    {
        pc->n_tcp = slot + 1;
    }
    return true;
}

/* Start queued probe connects in free (closed or never-used) slots, keeping at
 * most OOB_TCP_PROBE_MAX_CONNS connections in flight. Queued addresses of
 * targets that have answered in the meantime are dropped, and an address whose
 * connect cannot even start settles immediately -- in both cases the target's
 * outstanding count is consumed. */
static void
oob_probe_tcp_refill(struct probe_ctx *pc, struct probe_target *targets,
                     const struct oob_probe_result *results)
{
    int slot = 0;
    while (pc->queue_head < pc->queue_len)
    {
        while (slot < OOB_TCP_PROBE_MAX_CONNS && slot < pc->n_tcp
               && pc->tcp[slot].state != OOB_TCP_CLOSED)
        {
            slot++;
        }
        if (slot >= OOB_TCP_PROBE_MAX_CONNS)
        {
            return; /* every slot busy; retry when one settles */
        }

        const struct oob_tcp_pending *p = &pc->queue[pc->queue_head++];
        struct probe_target *t = &targets[p->target];

        if (results[p->target].responded)
        {
            t->outstanding--; /* already answered: no need to probe further addresses */
            continue;
        }
        if (!oob_probe_tcp_connect_start(pc, slot, p->target,
                                         (const struct sockaddr *)&t->dests[p->addr],
                                         t->destlens[p->addr]))
        {
            t->outstanding--; /* could not start: this address settles */
            continue;
        }
    }
}

/* The connection became writable: complete the connect if one was in flight
 * (checking its outcome via SO_ERROR, as openvpn_connect() does), then write
 * the framed probe, resuming after a short write. Once the probe is fully
 * written the RTT clock starts and the connection waits for the reply. */
static void
oob_probe_tcp_writable(struct oob_tcp_conn *conn, const struct buffer *framed_probe,
                       struct probe_target *targets)
{
    if (conn->state == OOB_TCP_CONNECTING)
    {
        int val = 0;
        socklen_t len = sizeof(val);
        if (getsockopt(conn->sd, SOL_SOCKET, SO_ERROR, (void *)&val, &len) != 0 || val != 0)
        {
            oob_tcp_conn_settle(conn, targets); /* refused/unreachable: no responder */
            return;
        }
        conn->state = OOB_TCP_SENDING;
    }

    const int total = (int)BLEN(framed_probe);
    while (conn->tx_off < total)
    {
        int n = (int)send(conn->sd, (const char *)BPTR(framed_probe) + conn->tx_off,
                          total - conn->tx_off, 0);
        if (n <= 0)
        {
            if (n < 0 && oob_sock_would_block())
            {
                return; /* stay in OOB_TCP_SENDING, resume on next writable */
            }
            oob_tcp_conn_settle(conn, targets);
            return;
        }
        conn->tx_off += n;
    }

    openvpn_gettimeofday(&conn->sent_at, NULL);
    conn->state = OOB_TCP_AWAIT_REPLY;
}

/* The connection became readable: collect the next chunk of the framed reply.
 * On a complete frame, record the reply (first reply per target wins) and
 * close -- one probe, one reply. A peer close, socket error or malformed frame
 * settles the connection as a non-responder. */
static void
oob_probe_tcp_readable(struct oob_tcp_conn *conn, const struct session_id *client_sid,
                       const struct tls_wrap_ctx *base_wrap, struct probe_target *targets,
                       struct oob_probe_result *results)
{
    uint8_t *dst;
    int want = oob_frame_reader_want(&conn->rd, &dst);
    int n = (int)recv(conn->sd, (char *)dst, want, 0);
    if (n <= 0)
    {
        if (n < 0 && oob_sock_would_block())
        {
            return;
        }
        oob_tcp_conn_settle(conn, targets); /* peer closed (e.g. no probe support) or error */
        return;
    }

    switch (oob_frame_reader_advance(&conn->rd, n))
    {
        case OOB_FRAME_NEED_MORE:
            return;

        case OOB_FRAME_COMPLETE:
        {
            struct oob_probe_reply reply;
            struct session_id server_sid;
            if (!results[conn->target].responded
                && oob_probe_reply_parse(conn->rd.pkt, (int)conn->rd.pkt_len, client_sid, base_wrap,
                                         &reply, &server_sid))
            {
                oob_probe_record_result(&results[conn->target], &reply, &server_sid,
                                        &conn->sent_at, &conn->dest);
            }
            oob_tcp_conn_settle(conn, targets);
            return;
        }

        case OOB_FRAME_ERROR:
        default:
            oob_tcp_conn_settle(conn, targets);
            return;
    }
}

/* Has every probed target settled? A UDP target settles only by answering
 * (datagrams may be lost, so we keep waiting for the window/retries); a TCP
 * target also settles when its outstanding count -- addresses still queued or
 * in flight -- reaches 0 (the transport is reliable: a refused or reset
 * connection will not answer later). */
static bool
oob_probe_all_settled(const struct probe_target *targets, const struct oob_probe_result *results,
                      int n)
{
    for (int i = 0; i < n; i++)
    {
        if (!targets[i].sent || results[i].responded)
        {
            continue;
        }
        if (!targets[i].is_tcp || targets[i].outstanding > 0)
        {
            return false;
        }
    }
    return true;
}

/* Receive replies for one time slice (until deadline), recording each that
 * matches a probe we sent: datagrams on the UDP sockets, and connect/send/read
 * progress on every live TCP probe connection, starting queued connects as
 * slots free up. Returns true once every probed target has settled (see
 * oob_probe_all_settled). */
static bool
oob_probe_receive_slice(struct probe_ctx *pc, const struct timeval *deadline,
                        const struct session_id *client_sid, const struct tls_wrap_ctx *wrap,
                        const struct buffer *framed_probe, struct probe_target *targets,
                        struct oob_probe_result *results, int n)
{
    while (true)
    {
        if (oob_probe_all_settled(targets, results, n))
        {
            return true;
        }

        /* fill freed connection slots from the queue before arming the fd sets */
        oob_probe_tcp_refill(pc, targets, results);

        struct timeval tnow, timeout;
        openvpn_gettimeofday(&tnow, NULL);
        timeout.tv_sec = deadline->tv_sec - tnow.tv_sec;
        timeout.tv_usec = deadline->tv_usec - tnow.tv_usec;
        if (timeout.tv_usec < 0)
        {
            timeout.tv_sec -= 1;
            timeout.tv_usec += 1000000;
        }
        if (timeout.tv_sec < 0)
        {
            return false; /* slice elapsed */
        }

        fd_set readfds, writefds, exceptfds;
        FD_ZERO(&readfds);
        FD_ZERO(&writefds);
        FD_ZERO(&exceptfds);
        socket_descriptor_t maxsd = 0;
        for (int i = 0; i < PROBE_AF_COUNT; i++)
        {
            if (pc->sd[i] != SOCKET_UNDEFINED)
            {
                openvpn_fd_set(pc->sd[i], &readfds);
                if (pc->sd[i] > maxsd)
                {
                    maxsd = pc->sd[i];
                }
            }
        }
        for (int k = 0; k < pc->n_tcp; k++)
        {
            struct oob_tcp_conn *conn = &pc->tcp[k];
            switch (conn->state)
            {
                case OOB_TCP_CONNECTING:
                    /* Winsock reports a failed non-blocking connect on the
                     * except set, not the write set */
                    openvpn_fd_set(conn->sd, &writefds);
                    openvpn_fd_set(conn->sd, &exceptfds);
                    break;

                case OOB_TCP_SENDING:
                    openvpn_fd_set(conn->sd, &writefds);
                    break;

                case OOB_TCP_AWAIT_REPLY:
                    openvpn_fd_set(conn->sd, &readfds);
                    break;

                case OOB_TCP_CLOSED:
                    continue;
            }
            if (conn->sd > maxsd)
            {
                maxsd = conn->sd;
            }
        }

        if (openvpn_select((int)maxsd + 1, &readfds, &writefds, &exceptfds, &timeout) <= 0)
        {
            return false; /* slice timed out, or error */
        }

        for (int i = 0; i < PROBE_AF_COUNT; i++)
        {
            if (pc->sd[i] == SOCKET_UNDEFINED || !FD_ISSET(pc->sd[i], &readfds))
            {
                continue;
            }
            uint8_t data[256];
            struct sockaddr_storage from;
            socklen_t fromlen = sizeof(from);
            int len = (int)recvfrom(pc->sd[i], (char *)data, (int)sizeof(data), 0,
                                    (struct sockaddr *)&from, &fromlen);
            if (len > 0)
            {
                oob_probe_handle_reply(data, len, client_sid, wrap, &from, targets, results, n);
            }
        }

        for (int k = 0; k < pc->n_tcp; k++)
        {
            struct oob_tcp_conn *conn = &pc->tcp[k];
            if (conn->state == OOB_TCP_CLOSED)
            {
                continue;
            }
            if (FD_ISSET(conn->sd, &writefds) || FD_ISSET(conn->sd, &exceptfds))
            {
                /* on except, the SO_ERROR check inside settles the failure */
                oob_probe_tcp_writable(conn, framed_probe, targets);
            }
            else if (FD_ISSET(conn->sd, &readfds))
            {
                oob_probe_tcp_readable(conn, client_sid, wrap, targets, results);
            }
        }
    }
}

/* Resend the probe to every UDP remote that we probed but that has not
 * answered. TCP targets are excluded: the transport retransmits on its own,
 * and their connections simply stay armed across slice boundaries. */
static void
oob_probe_resend_unanswered(const struct probe_ctx *pc, const struct buffer *probe,
                            const struct probe_target *targets,
                            const struct oob_probe_result *results, int n)
{
    for (int i = 0; i < n; i++)
    {
        if (targets[i].sent && !targets[i].is_tcp && !results[i].responded)
        {
            oob_probe_send_target(pc, probe, &targets[i]);
        }
    }
}

/* Collect replies over the probe window, resending unanswered UDP probes up to
 * OOB_PROBE_RETRIES times (UDP is lossy and a probe carries no retransmission
 * of its own). The window is split into equal slices, one per send round; after
 * each slice but the last we resend to whoever has not answered yet. Returns
 * once the window elapses or every probed target has settled. */
static void
oob_probe_collect(struct probe_ctx *pc, const struct buffer *probe,
                  const struct session_id *client_sid, const struct tls_wrap_ctx *wrap,
                  const struct buffer *framed_probe, struct probe_target *targets,
                  struct oob_probe_result *results, int n)
{
    const int slices = 1 + OOB_PROBE_RETRIES;
    const long slice_ms = OOB_PROBE_WINDOW_MS / slices;

    for (int slice = 0; slice < slices; slice++)
    {
        struct timeval deadline;
        openvpn_gettimeofday(&deadline, NULL);
        deadline.tv_sec += slice_ms / 1000;
        deadline.tv_usec += (slice_ms % 1000) * 1000;
        if (deadline.tv_usec >= 1000000)
        {
            deadline.tv_sec += 1;
            deadline.tv_usec -= 1000000;
        }

        if (oob_probe_receive_slice(pc, &deadline, client_sid, wrap, framed_probe, targets, results,
                                    n))
        {
            return; /* every target settled */
        }

        if (slice + 1 < slices)
        {
            oob_probe_resend_unanswered(pc, probe, targets, results, n);
        }
    }
}

/* Permute the connection list so entries appear in ranked order. */
static void
oob_apply_order(struct connection_list *l, const struct oob_probe_result *ranked,
                struct gc_arena *gc)
{
    struct connection_entry **reordered = gc_malloc(sizeof(*reordered) * l->len, false, gc);
    for (int i = 0; i < l->len; i++)
    {
        reordered[i] = l->array[ranked[i].index];
    }
    memcpy(l->array, reordered, sizeof(*l->array) * l->len);
}

void
client_probe_and_order_remotes(struct context *c)
{
    /* Probe only once, before the first connection attempt. */
    if (!c->options.server_probe || !c->first_time)
    {
        return;
    }

    struct connection_list *l = c->options.connection_list;
    if (!l || l->len <= 1)
    {
        return; /* nothing to choose between */
    }

    struct gc_arena gc = gc_new();

    /* Wrapping context for the probe (tls-auth/tls-crypt, or plaintext if
     * neither). NULL means this configuration cannot be probed; keep the
     * configured order. */
    struct tls_auth_standalone *tas = oob_probe_init_tls_auth_standalone(c, &gc);
    if (!tas)
    {
        gc_free(&gc);
        return;
    }

    /* A single random session id identifies all of our probes; servers echo it
     * back in the reply's peer_session_id, letting us reject spoofed replies. */
    struct session_id client_sid;
    session_id_random(&client_sid);

    struct probe_ctx pc = { .sd = { SOCKET_UNDEFINED, SOCKET_UNDEFINED } };
    pc.tcp = gc_malloc(sizeof(*pc.tcp) * OOB_TCP_PROBE_MAX_CONNS, true, &gc);
    if (oob_probe_sockets_open(&pc) == 0)
    {
        msg(D_LOW, "server-probe: could not open probe socket; using configured order");
        tls_auth_standalone_free(tas);
        gc_free(&gc);
        return;
    }

    struct probe_target *targets = gc_malloc(sizeof(*targets) * l->len, true, &gc);
    struct oob_probe_result *results = gc_malloc(sizeof(*results) * l->len, true, &gc);

    /* Build the probe once and reuse the same bytes for every remote and for
     * resends: the SERVER_PROBE payload is a single probe_parameter TLV, wrapped
     * (or sent in plaintext) like any other control packet. The client session
     * id is prepended as the sender session id. */
    struct buffer payload = alloc_buf_gc(64, &gc);
    const struct oob_probe_parameter param = {
        .timestamp = (uint64_t)now,
        .flags = 0,
    };
    if (!oob_server_probe_write(&payload, &param))
    {
        msg(D_LOW, "server-probe: could not build probe payload; using configured order");
        oob_probe_sockets_close(&pc);
        tls_auth_standalone_free(tas);
        gc_free(&gc);
        return;
    }

    /* With tls-crypt-v2 the probe must carry the wrapped client key so the
     * server can recover the per-client key; that is a P_CONTROL_OOB_WKC_V1
     * message. Otherwise (tls-crypt v1, tls-auth, or plaintext) it is a plain
     * P_CONTROL_OOB_V1. */
    const bool is_v2 = (tas->tls_wrap.tls_crypt_v2_wkc != NULL);
    const int probe_opcode = is_v2 ? P_CONTROL_OOB_WKC_V1 : P_CONTROL_OOB_V1;

    struct buffer probe =
        tls_wrap_oob_standalone(&tas->tls_wrap, tas, &client_sid, &payload, probe_opcode);
    if (!BLEN(&probe))
    {
        msg(D_LOW, "server-probe: could not wrap probe packet; using configured order");
        oob_probe_sockets_close(&pc);
        tls_auth_standalone_free(tas);
        gc_free(&gc);
        return;
    }

    /* On TCP the same wrapped packet is preceded by the standard 16-bit length
     * prefix (as link_socket_write_tcp() would). Frame a copy once; the
     * unframed buffer stays untouched for UDP sends and resends. */
    struct buffer framed_probe = alloc_buf_gc(BLEN(&probe) + (int)sizeof(uint16_t), &gc);
    buf_write_u16(&framed_probe, (uint16_t)BLEN(&probe));
    buf_copy(&framed_probe, &probe);

    const char *wrap_name = is_v2                                    ? "tls-crypt-v2"
                            : (tas->tls_wrap.mode == TLS_WRAP_CRYPT) ? "tls-crypt"
                            : (tas->tls_wrap.mode == TLS_WRAP_AUTH)  ? "tls-auth"
                                                                     : "none (plaintext)";
    msg(D_LOW, "server-probe: probing %d remote(s) with a %d ms window, control-channel wrapping: %s",
        l->len, OOB_PROBE_WINDOW_MS, wrap_name);

    /* Send a probe to each configured remote. */
    int sent_count = 0;
    for (int i = 0; i < l->len; i++)
    {
        results[i].index = i;
        results[i].responded = false;

        const struct connection_entry *ce = l->array[i];
        if (!ce->remote)
        {
            continue; /* nothing to probe (e.g. a connection block with no --remote) */
        }
        const bool is_tcp = (ce->proto == PROTO_TCP_CLIENT);
        if (!proto_is_udp(ce->proto) && !is_tcp)
        {
            msg(D_LOW, "server-probe: %s:%s: skipping (protocol cannot be probed)", ce->remote,
                ce->remote_port);
            continue;
        }
        if (is_tcp && (ce->http_proxy_options || ce->socks_proxy_server))
        {
            msg(D_LOW, "server-probe: %s:%s: skipping (probing through a proxy is not supported)",
                ce->remote, ce->remote_port);
            continue;
        }

        struct addrinfo *ai = NULL;
        const unsigned int ga_flags =
            GETADDR_RESOLVE | GETADDR_TRY_ONCE | (is_tcp ? 0 : GETADDR_DATAGRAM);
        int status = openvpn_getaddrinfo(ga_flags, ce->remote, ce->remote_port, 0, NULL, AF_UNSPEC,
                                         &ai);
        if (status != 0 || !ai)
        {
            msg(D_LOW, "server-probe: %s:%s: could not resolve", ce->remote, ce->remote_port);
            continue;
        }

        struct probe_target *t = &targets[i];
        t->is_tcp = is_tcp;

        if (is_tcp)
        {
            /* Store every resolved address; the addresses are queued after this
             * loop and each is probed on its own non-blocking connection, started
             * inside the collect loop as connection slots become free. */
            int n_tcp_addr = 0;
            for (const struct addrinfo *a = ai; a; a = a->ai_next)
            {
                n_tcp_addr++;
            }
            t->dests = gc_malloc(sizeof(*t->dests) * n_tcp_addr, true, &gc);
            t->destlens = gc_malloc(sizeof(*t->destlens) * n_tcp_addr, true, &gc);
            for (const struct addrinfo *a = ai; a; a = a->ai_next)
            {
                memcpy(&t->dests[t->n_dests], a->ai_addr, a->ai_addrlen);
                t->destlens[t->n_dests] = (socklen_t)a->ai_addrlen;
                t->n_dests++;
            }
            freeaddrinfo(ai);

            t->outstanding = t->n_dests;
            t->sent = true;
            sent_count++;
            continue;
        }

        /* Collect every resolved address whose address family has a probe socket.
         * Each address is stored natively (no IPv4-mapping) and later probed on
         * its AF socket. Storage is sized to the resolved address count. */
        int n_addr = 0;
        for (const struct addrinfo *a = ai; a; a = a->ai_next)
        {
            n_addr++;
        }
        t->dests = gc_malloc(sizeof(*t->dests) * n_addr, true, &gc);
        t->destlens = gc_malloc(sizeof(*t->destlens) * n_addr, true, &gc);
        for (const struct addrinfo *a = ai; a; a = a->ai_next)
        {
            if (pc.sd[probe_af_index(a->ai_family)] == SOCKET_UNDEFINED)
            {
                continue; /* no socket for this address family */
            }
            memcpy(&t->dests[t->n_dests], a->ai_addr, a->ai_addrlen);
            t->destlens[t->n_dests] = (socklen_t)a->ai_addrlen;
            t->n_dests++;
        }
        freeaddrinfo(ai);

        if (t->n_dests == 0)
        {
            msg(D_LOW, "server-probe: %s:%s: not reachable by the probe socket", ce->remote,
                ce->remote_port);
            continue;
        }

        if (!oob_probe_send_target(&pc, &probe, t))
        {
            msg(D_LOW, "server-probe: %s:%s: probe send failed", ce->remote, ce->remote_port);
            continue;
        }

        openvpn_gettimeofday(&t->sent_at, NULL);
        t->sent = true;
        sent_count++;
    }

    /* Queue the TCP addresses round-robin by remote -- every remote's first
     * address before any remote's second -- so a remote resolving to many
     * addresses cannot starve the ones behind it. The collect loop dequeues
     * into free connection slots. */
    int total_tcp = 0;
    int max_dests = 0;
    for (int i = 0; i < l->len; i++)
    {
        if (targets[i].is_tcp && targets[i].sent)
        {
            total_tcp += targets[i].n_dests;
            max_dests = (targets[i].n_dests > max_dests) ? targets[i].n_dests : max_dests;
        }
    }
    if (total_tcp > 0)
    {
        pc.queue = gc_malloc(sizeof(*pc.queue) * total_tcp, false, &gc);
        for (int r = 0; r < max_dests; r++)
        {
            for (int i = 0; i < l->len; i++)
            {
                if (targets[i].is_tcp && targets[i].sent && r < targets[i].n_dests)
                {
                    pc.queue[pc.queue_len].target = i;
                    pc.queue[pc.queue_len].addr = r;
                    pc.queue_len++;
                }
            }
        }
    }

    if (sent_count > 0)
    {
        oob_probe_collect(&pc, &probe, &client_sid, &tas->tls_wrap, &framed_probe, targets, results,
                          l->len);
    }

    /* Log each remote's outcome while results[i] still maps to array[i]. */
    int responded = 0;
    for (int i = 0; i < l->len; i++)
    {
        const struct connection_entry *ce = l->array[i];
        if (results[i].responded)
        {
            responded++;
            /* Effective candidate-band margin and where it came from: the
             * client's own setting wins, else the server's advertised value,
             * else the built-in default. */
            int client_margin = c->options.server_probe_latency_margin;
            int margin = oob_effective_margin(&results[i], client_margin);
            const char *margin_src = client_margin >= 0                      ? "client"
                                     : results[i].reply.max_latency_diff > 0 ? "server-advertised"
                                                                             : "default";
            msg(D_LOW,
                "server-probe: %s:%s answered (priority %d, weight %d, connect-lifetime %d s,"
                " rtt %u ms; latency margin %d ms [%s])",
                ce->remote, ce->remote_port, results[i].reply.priority, results[i].reply.weight,
                results[i].reply.connect_lifetime, results[i].rtt_ms, margin, margin_src);
        }
        else
        {
            msg(D_LOW, "server-probe: %s:%s did not answer", ce->remote, ce->remote_port);
        }
    }

    /* Rank best-first and reorder the connection list accordingly. */
    oob_rank_probe_results(results, l->len, c->options.server_probe_latency_margin, get_random, &gc);
    oob_apply_order(l, results, &gc);

    msg(D_LOW, "server-probe: connecting in this order:");
    for (int i = 0; i < l->len; i++)
    {
        msg(D_LOW, "server-probe:   %d. %s:%s", i + 1, l->array[i]->remote,
            l->array[i]->remote_port);
    }

    msg(M_INFO, "server-probe: %d of %d remote(s) answered; connecting best-first", responded,
        l->len);

    /* If the winner advertised a connect_lifetime, its reply also served as the
     * server's reset: hand its probe socket and the captured cookie to the
     * connection, which then starts the handshake from that reply (see
     * session_skip_to_pre_start_client). Reusing that socket keeps the source
     * IP+port the cookie is bound to. dco-win cannot hand a socket to the
     * kernel, so it only gets the probe ordering. */

    /* Single-use, so the RFC's connect_lifetime expiry check is not needed yet:
     * we probe once (c->first_time) and arm only results[0]. */

    /* UDP only: the cookie is bound to a datagram source IP+port and the socket
     * adopted below is the UDP probe socket. A TCP winner always does a full
     * reset exchange -- its server advertises connect_lifetime 0 anyway, so this
     * is defence in depth against a misbehaving server. */
    bool probe_start = results[0].responded && results[0].reply.connect_lifetime > 0
                       && proto_is_udp(l->array[0]->proto);
    bool dco_win_gate = false;
#if defined(_WIN32)
    if (dco_enabled(&c->options))
    {
        probe_start = false;
        dco_win_gate = true;
    }
#endif
    if (probe_start)
    {
        const int af_idx = probe_af_index(results[0].responder.ss_family);
        c->c2.oob_probe_sd = pc.sd[af_idx];
        pc.sd[af_idx] = SOCKET_UNDEFINED; /* relinquish: the connection owns it now */

        CLEAR(c->c2.oob_probe_remote);
        if (results[0].responder.ss_family == AF_INET)
        {
            c->c2.oob_probe_remote.addr.in4 = *(struct sockaddr_in *)(void *)&results[0].responder;
        }
        else
        {
            c->c2.oob_probe_remote.addr.in6 = *(struct sockaddr_in6 *)(void *)&results[0].responder;
        }
        c->c2.oob_probe_client_sid = client_sid;
        c->c2.oob_probe_server_sid = results[0].server_sid;
        c->c2.oob_probe_resend_wkc =
            (results[0].reply.flags & OOB_PROBE_REPLY_FLAG_RESEND_WKC) != 0;
        c->c2.oob_probe_adopt = true;

        msg(D_LOW, "server-probe: starting handshake from probe reply of %s:%s"
                   " (connect-lifetime %d s)",
            l->array[0]->remote, l->array[0]->remote_port, results[0].reply.connect_lifetime);
    }
    else if (results[0].responded)
    {
        /* A server answered but we won't start the handshake from it -- say why. */
        if (dco_win_gate)
        {
            msg(D_LOW, "server-probe: cannot start the handshake from a probe reply"
                       " with dco-win;"
                       " using a full handshake");
        }
        else if (!proto_is_udp(l->array[0]->proto))
        {
            msg(D_LOW, "server-probe: a TCP remote cannot start the handshake from a probe"
                       " reply; using a full handshake");
        }
        else if (results[0].reply.connect_lifetime == 0)
        {
            msg(D_LOW, "server-probe: %s:%s did not advertise a connect-lifetime"
                       " (connect-lifetime 0); using a full handshake",
                l->array[0]->remote, l->array[0]->remote_port);
        }
    }

    /* Close any probe sockets we did not hand off to the connection. */
    oob_probe_sockets_close(&pc);

    tls_auth_standalone_free(tas);
    gc_free(&gc);
}
