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

struct probe_ctx
{
    socket_descriptor_t sd[PROBE_AF_COUNT]; /* SOCKET_UNDEFINED if that AF is unavailable */
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

    /* tls-crypt-v2 wraps with a per-client key the server only learns from the
     * wrapped client key (WKc) carried in the TLS handshake. An out-of-band
     * probe carries no WKc, so the server cannot unwrap it; skip probing rather
     * than send something unverifiable. */
    if (ce->tls_crypt_v2_file)
    {
        msg(D_LOW, "server-probe: not supported with tls-crypt-v2; using configured order");
        return NULL;
    }

    /* Load the tls-auth/tls-crypt key material into c->c1.ks (a no-op if neither
     * is configured). This is run again per-connection later; calling it early
     * here is harmless. */
    do_init_tls_wrap_key(c, ce);

    struct tls_options to;
    CLEAR(to);
    init_tls_wrap_ctx(&to.tls_wrap, ce, c->options.tls_client, &c->c1.ks, &c->c1.pid_persist);
    to.replay_window = c->options.replay_window;
    to.replay_time = c->options.replay_time;

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

/* Parse one received datagram as a PROBE_REPLY and, if valid and matching one
 * of the probes we sent, record the reply in results. */
static void
oob_probe_handle_reply(uint8_t *data, int len, const struct session_id *client_sid,
                       const struct tls_wrap_ctx *base_wrap, const struct sockaddr_storage *from,
                       const struct probe_target *targets, struct oob_probe_result *results, int n)
{
    /* Need at least the opcode byte and the session id. */
    if (len < 1 + (int)SID_SIZE || (data[0] >> P_OPCODE_SHIFT) != P_CONTROL_OOB_V1)
    {
        return;
    }

    struct buffer buf;
    buf_set_read(&buf, data, (size_t)len);

    /* Unwrap the reply with the same control-channel path the server used to
     * wrap it: this verifies the tls-auth HMAC / decrypts tls-crypt, and (in all
     * modes) strips the opcode + server session id, leaving buf at the TLV
     * payload. With no tls-auth/tls-crypt it just strips those header bytes, as
     * before. read_control_auth() mutates the wrapping context, so we work on a
     * per-packet copy (as tls_pre_decrypt_lite() does on the server). The peer
     * address is only used for log messages, and tls_options only for
     * tls-crypt-v2 metadata checks, so both are passed as NULL. */
    struct tls_wrap_ctx wrap = *base_wrap;
    if (!read_control_auth(&buf, &wrap, NULL, NULL))
    {
        return; /* not for us, or failed authentication */
    }

    struct oob_probe_reply reply;
    if (!oob_client_reply_read(&buf, &reply))
    {
        return;
    }

    /* Reject spoofed replies: the reply must echo our probe's session id. */
    if (!session_id_equal(&reply.peer_session_id, client_sid))
    {
        return;
    }

    /* Match the reply's source address to one of the addresses we probed for a
     * remote. The first reply for a remote wins (a remote with several addresses
     * may answer from more than one). */
    for (int i = 0; i < n; i++)
    {
        if (!targets[i].sent || results[i].responded)
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

        struct timeval rcv;
        openvpn_gettimeofday(&rcv, NULL);
        long ms = (long)(rcv.tv_sec - targets[i].sent_at.tv_sec) * 1000
                  + (rcv.tv_usec - targets[i].sent_at.tv_usec) / 1000;

        results[i].responded = true;
        results[i].rtt_ms = (ms > 0) ? (unsigned int)ms : 0;
        results[i].reply = reply;
        break;
    }
}

/* Count how many of the probes we sent have been answered so far. */
static int
oob_count_answered(const struct probe_target *targets, const struct oob_probe_result *results,
                   int n)
{
    int answered = 0;
    for (int i = 0; i < n; i++)
    {
        answered += (targets[i].sent && results[i].responded) ? 1 : 0;
    }
    return answered;
}

/* Receive replies for one time slice (until deadline), recording each that
 * matches a probe we sent. Returns true if every sent probe has been answered. */
static bool
oob_probe_receive_slice(const struct probe_ctx *pc, const struct timeval *deadline,
                        const struct session_id *client_sid, const struct tls_wrap_ctx *wrap,
                        const struct probe_target *targets, struct oob_probe_result *results, int n,
                        int outstanding)
{
    while (true)
    {
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

        fd_set readfds;
        FD_ZERO(&readfds);
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
        if (openvpn_select((int)maxsd + 1, &readfds, NULL, NULL, &timeout) <= 0)
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
        if (oob_count_answered(targets, results, n) >= outstanding)
        {
            return true; /* every probe we sent has been answered */
        }
    }
}

/* Resend the probe to every remote that we probed but that has not answered. */
static void
oob_probe_resend_unanswered(const struct probe_ctx *pc, const struct buffer *probe,
                            const struct probe_target *targets,
                            const struct oob_probe_result *results, int n)
{
    for (int i = 0; i < n; i++)
    {
        if (targets[i].sent && !results[i].responded)
        {
            oob_probe_send_target(pc, probe, &targets[i]);
        }
    }
}

/* Collect replies over the probe window, resending unanswered probes up to
 * OOB_PROBE_RETRIES times (UDP is lossy and a probe carries no retransmission
 * of its own). The window is split into equal slices, one per send round; after
 * each slice but the last we resend to whoever has not answered yet. Returns
 * once the window elapses or every sent probe has been answered. */
static void
oob_probe_collect(const struct probe_ctx *pc, const struct buffer *probe,
                  const struct session_id *client_sid, const struct tls_wrap_ctx *wrap,
                  const struct probe_target *targets, struct oob_probe_result *results, int n)
{
    /* number of probes we actually sent: stop early once they all answer */
    int want = 0;
    for (int i = 0; i < n; i++)
    {
        want += targets[i].sent ? 1 : 0;
    }

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

        if (oob_probe_receive_slice(pc, &deadline, client_sid, wrap, targets, results, n, want))
        {
            return; /* all answered */
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

    struct buffer probe =
        tls_wrap_oob_standalone(&tas->tls_wrap, tas, &client_sid, &payload, P_CONTROL_OOB_V1);
    if (!BLEN(&probe))
    {
        msg(D_LOW, "server-probe: could not wrap probe packet; using configured order");
        oob_probe_sockets_close(&pc);
        tls_auth_standalone_free(tas);
        gc_free(&gc);
        return;
    }

    const char *wrap_name = (tas->tls_wrap.mode == TLS_WRAP_CRYPT)  ? "tls-crypt"
                            : (tas->tls_wrap.mode == TLS_WRAP_AUTH) ? "tls-auth"
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
        if (!proto_is_udp(ce->proto))
        {
            msg(D_LOW, "server-probe: %s:%s: skipping (not a UDP remote)", ce->remote,
                ce->remote_port);
            continue;
        }

        struct addrinfo *ai = NULL;
        int status = openvpn_getaddrinfo(GETADDR_RESOLVE | GETADDR_TRY_ONCE | GETADDR_DATAGRAM,
                                         ce->remote, ce->remote_port, 0, NULL, AF_UNSPEC, &ai);
        if (status != 0 || !ai)
        {
            msg(D_LOW, "server-probe: %s:%s: could not resolve", ce->remote, ce->remote_port);
            continue;
        }

        /* Collect every resolved address whose address family has a probe socket.
         * Each address is stored natively (no IPv4-mapping) and later probed on
         * its AF socket. Storage is sized to the resolved address count. */
        struct probe_target *t = &targets[i];
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

    if (sent_count > 0)
    {
        oob_probe_collect(&pc, &probe, &client_sid, &tas->tls_wrap, targets, results, l->len);
    }
    oob_probe_sockets_close(&pc);

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
                "server-probe: %s:%s answered (priority %d, weight %d, rtt %u ms;"
                " latency margin %d ms [%s])",
                ce->remote, ce->remote_port, results[i].reply.priority, results[i].reply.weight,
                results[i].rtt_ms, margin, margin_src);
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

    tls_auth_standalone_free(tas);
    gc_free(&gc);
}
