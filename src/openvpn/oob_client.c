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

/* The probe uses one socket per address family, each set up and bound like the
 * connection socket, so every remote is probed on a socket of its own family and
 * the winning remote's socket can be reused as its connection socket, presenting
 * the same source IP+port the server bound its handshake cookie to. */
#define PROBE_AF_V4    0
#define PROBE_AF_V6    1
#define PROBE_AF_COUNT 2

struct probe_ctx
{
    socket_descriptor_t sd[PROBE_AF_COUNT]; /* SOCKET_UNDEFINED if that AF is unavailable */
    /* Addresses probed so far in the current send round: an address several
     * entries resolve to is probed once, and its reply is credited to each. */
    struct openvpn_sockaddr *probed;
    int n_probed;
};

/* af is an int (not sa_family_t) so callers can pass addrinfo::ai_family
 * directly without a narrowing conversion (-Werror=conversion). */
static int
probe_af_index(int af)
{
    return (af == AF_INET6) ? PROBE_AF_V6 : PROBE_AF_V4;
}

/* Build a plaintext SERVER_PROBE packet:
 *   [opcode | key_id=0] [client session id] [SERVER_PROBE message]
 * This is the unauthenticated OOB wire format; adding tls-auth/tls-crypt
 * wrapping for the probe is a follow-up (it only works against a server with
 * no control-channel wrapping for now). */
static bool
oob_probe_build_packet(struct buffer *buf, const struct session_id *client_sid)
{
    const struct oob_probe_parameter param = {
        .timestamp = (uint64_t)now,
        .flags = 0,
    };
    uint8_t header = (uint8_t)(P_CONTROL_OOB_V1 << P_OPCODE_SHIFT);
    return buf_write_u8(buf, header) && session_id_write(client_sid, buf)
           && oob_server_probe_write(buf, &param);
}

/* The local address and port ce's connection socket binds: its first --local,
 * with --lport taking precedence in client mode, as link_socket_init_phase1()
 * picks them for socket 0. */
static void
oob_probe_bind_target(const struct connection_entry *ce, const struct options *o,
                      const char **host, const char **port)
{
    *host = NULL;
    *port = ce->local_port;
    if (ce->local_list && ce->local_list->len)
    {
        *host = ce->local_list->array[0]->local;
        *port = ce->local_list->array[0]->port;
    }
    if (o->mode == MODE_POINT_TO_POINT && ce->local_port_defined)
    {
        *port = ce->local_port;
    }
}

/* Equal strings, or both absent. */
static bool
str_equal_or_both_null(const char *a, const char *b)
{
    return (!a && !b) || (a && b && strcmp(a, b) == 0);
}

/* Can this entry be probed at all? Only a direct UDP remote can answer and
 * hand its socket to the connection. */
static bool
oob_probe_eligible(const struct connection_entry *ce)
{
    return ce->remote && proto_is_udp(ce->proto) && !ce->socks_proxy_server;
}

/* Do a and b bind their connection socket the same way (--bind/--nobind,
 * --local, --lport, --bind ipv6only)? One probe socket set serves all probed
 * remotes, so each must agree with the first of them, whose socket is adopted. */
static bool
oob_probe_same_bind(const struct connection_entry *a, const struct connection_entry *b,
                    const struct options *o)
{
    if (a->bind_local != b->bind_local)
    {
        return false;
    }
    if (!a->bind_local)
    {
        return true;
    }
    const char *host_a, *port_a, *host_b, *port_b;
    oob_probe_bind_target(a, o, &host_a, &port_a);
    oob_probe_bind_target(b, o, &host_b, &port_b);
    return a->bind_ipv6_only == b->bind_ipv6_only && str_equal_or_both_null(host_a, host_b)
           && str_equal_or_both_null(port_a, port_b);
}

/* Resolve the local bind address of ce's connection socket; NULL with --nobind.
 * Fatal on failure, like the link socket. */
static struct addrinfo *
oob_probe_bind_addrinfo(const struct connection_entry *ce, const struct options *o)
{
    if (!ce->bind_local)
    {
        return NULL;
    }
    const char *host, *port;
    oob_probe_bind_target(ce, o, &host, &port);

    struct addrinfo *ai = NULL;
    const unsigned int flags = GETADDR_RESOLVE | GETADDR_WARN_ON_SIGNAL | GETADDR_FATAL
                               | GETADDR_PASSIVE | GETADDR_DATAGRAM;
    openvpn_getaddrinfo(flags, host, port, 0, NULL, AF_UNSPEC, &ai); /* fatal on failure */
    return ai;
}

/* Does the address list hold an entry of family af? */
static bool
addrinfo_has_family(const struct addrinfo *ai, int af)
{
    for (; ai; ai = ai->ai_next)
    {
        if (ai->ai_family == af)
        {
            return true;
        }
    }
    return false;
}

/* Open the probe socket of each address family in use, set up and bound exactly
 * as the connection socket (create_socket_udp_configured()), so the winner's
 * socket can become that connection socket unchanged. A family with no --local
 * address to bind is left SOCKET_UNDEFINED and its remotes are not probed, as the
 * connection could not reach them either. Returns the number of sockets opened. */
static int
oob_probe_sockets_open(struct probe_ctx *pc, const bool need[PROBE_AF_COUNT],
                       struct addrinfo *bind_local, const struct connection_entry *ce,
                       const struct options *o)
{
    static const int families[PROBE_AF_COUNT] = { AF_INET, AF_INET6 };
    const struct socket_buffer_size sbs = { .rcvbuf = o->rcvbuf, .sndbuf = o->sndbuf };
    int opened = 0;

    for (int i = 0; i < PROBE_AF_COUNT; i++)
    {
        if (!need[i])
        {
            continue;
        }
        if (bind_local && !addrinfo_has_family(bind_local, families[i]))
        {
            msg(D_LOW, "server-probe: no %s address to bind, not probing %s remotes",
                addr_family_name(families[i]), addr_family_name(families[i]));
            continue;
        }
        /* Both probe sockets bind the same port, and a dual-stack IPv6 wildcard
         * collides with the IPv4 one; the connection socket never has this
         * problem as it binds one family only. */
        const bool v6only = ce->bind_ipv6_only
                            || (bind_local && families[i] == AF_INET6
                                && pc->sd[PROBE_AF_V4] != SOCKET_UNDEFINED);
        pc->sd[i] = create_socket_udp_configured((sa_family_t)families[i], o->sockflags, &sbs,
                                                 o->mark, o->bind_dev, bind_local, v6only, true);
        if (pc->sd[i] == SOCKET_UNDEFINED)
        {
            msg(D_LOW, "server-probe: no usable %s socket, not probing %s remotes",
                addr_family_name(families[i]), addr_family_name(families[i]));
            continue;
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

/* Parse one received datagram as a PROBE_REPLY and, if valid and matching one
 * of the probes we sent, record the reply in results. */
static void
oob_probe_handle_reply(const uint8_t *data, int len, const struct session_id *client_sid,
                       const struct openvpn_sockaddr *from, const struct oob_probe_target *targets,
                       struct oob_probe_result *results, int n)
{
    /* Need at least the opcode byte and the session id. */
    if (len < 1 + (int)SID_SIZE || (data[0] >> P_OPCODE_SHIFT) != P_CONTROL_OOB_V1)
    {
        return;
    }

    struct buffer buf;
    buf_set_read(&buf, data, (size_t)len);
    buf_advance(&buf, 1 + SID_SIZE); /* skip opcode + server session id */

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

    /* Credit the reply to every still-unanswered remote probed at its source
     * address: several entries can resolve to the same address, and each takes
     * the first reply for it. */
    struct timeval rcv;
    openvpn_gettimeofday(&rcv, NULL);
    int i = oob_probe_next_target_at(from, targets, results, n, 0);
    while (i >= 0)
    {
        long ms = (long)(rcv.tv_sec - targets[i].sent_at.tv_sec) * 1000
                  + (rcv.tv_usec - targets[i].sent_at.tv_usec) / 1000;

        results[i].responded = true;
        results[i].rtt_ms = (ms > 0) ? (unsigned int)ms : 0;
        results[i].reply = reply;

        i = oob_probe_next_target_at(from, targets, results, n, i + 1);
    }
}

/* Count how many of the probes we sent have been answered so far. */
static int
oob_count_answered(const struct oob_probe_target *targets, const struct oob_probe_result *results,
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
                        const struct session_id *client_sid, const struct oob_probe_target *targets,
                        struct oob_probe_result *results, int n, int outstanding)
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
        if (openvpn_select(maxsd + 1, &readfds, NULL, NULL, &timeout) <= 0)
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
            struct openvpn_sockaddr from;
            socklen_t fromlen = sizeof(from);
            int len = (int)recvfrom(pc->sd[i], (char *)data, (int)sizeof(data), 0,
                                    (struct sockaddr *)&from, &fromlen);
            if (len > 0)
            {
                oob_probe_handle_reply(data, len, client_sid, &from, targets, results, n);
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
oob_probe_resend_unanswered(struct probe_ctx *pc, const struct buffer *probe,
                            const struct oob_probe_target *targets,
                            const struct oob_probe_result *results, int n)
{
    pc->n_probed = 0; /* a new round: probe each unanswered address once again */
    for (int i = 0; i < n; i++)
    {
        if (!targets[i].sent || results[i].responded
            || oob_addr_list_contains(pc->probed, pc->n_probed, &targets[i].dest))
        {
            continue;
        }
        socket_descriptor_t sd = pc->sd[probe_af_index(targets[i].dest.addr.sa.sa_family)];
        if (sd != SOCKET_UNDEFINED
            && sendto(sd, (const char *)BPTR(probe), (int)BLEN(probe), 0,
                      (const struct sockaddr *)&targets[i].dest, targets[i].destlen)
                   >= 0)
        {
            pc->probed[pc->n_probed++] = targets[i].dest;
        }
    }
}

/* Collect replies over the probe window, resending unanswered probes up to
 * OOB_PROBE_RETRIES times (UDP is lossy and a probe carries no retransmission
 * of its own). The window is split into equal slices, one per send round; after
 * each slice but the last we resend to whoever has not answered yet. Returns
 * once the window elapses or every sent probe has been answered. */
static void
oob_probe_collect(struct probe_ctx *pc, const struct buffer *probe,
                  const struct session_id *client_sid, const struct oob_probe_target *targets,
                  struct oob_probe_result *results, int n,
                  const struct signal_info *sig)
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

        if (oob_probe_receive_slice(pc, &deadline, client_sid, targets, results, n, want)
            || sig->signal_received)
        {
            return; /* all answered, or we are being told to stop */
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

    /* A single random session id identifies all of our probes; servers echo it
     * back in the reply's peer_session_id, letting us reject spoofed replies. */
    struct session_id client_sid;
    session_id_random(&client_sid);

    /* The probe sockets are set up like the connection socket of the first
     * remote we can probe, whose socket the winner adopts; probing cannot serve
     * remotes that bind differently. */
    const struct connection_entry *tmpl = NULL;
    for (int i = 0; i < l->len; i++)
    {
        const struct connection_entry *ce = l->array[i];
        if (!oob_probe_eligible(ce))
        {
            continue;
        }
        if (!tmpl)
        {
            tmpl = ce;
            continue;
        }
        if (!oob_probe_same_bind(tmpl, ce, &c->options))
        {
            msg(D_LOW, "server-probe: %s:%s binds differently from %s:%s;"
                       " not probing, using configured order",
                ce->remote, ce->remote_port, tmpl->remote, tmpl->remote_port);
            gc_free(&gc);
            return;
        }
    }
    if (!tmpl)
    {
        msg(D_LOW, "server-probe: no remote can be probed; using configured order");
        gc_free(&gc);
        return;
    }

    struct probe_ctx pc = { .sd = { SOCKET_UNDEFINED, SOCKET_UNDEFINED } };
    struct oob_probe_target *targets = gc_malloc(sizeof(*targets) * l->len, true, &gc);
    struct oob_probe_result *results = gc_malloc(sizeof(*results) * l->len, true, &gc);

    struct buffer probe = alloc_buf_gc(256, &gc);
    if (!oob_probe_build_packet(&probe, &client_sid))
    {
        msg(D_LOW, "server-probe: could not build probe packet; using configured order");
        oob_probe_sockets_close(&pc);
        gc_free(&gc);
        return;
    }

    msg(D_LOW, "server-probe: probing %d remote(s) with a %d ms window", l->len,
        OOB_PROBE_WINDOW_MS);

    /* Resolve every remote first, so only the address families actually in use
     * get a probe socket. */
    bool need_af[PROBE_AF_COUNT] = { false, false };
    for (int i = 0; i < l->len; i++)
    {
        results[i].index = i;
        results[i].responded = false;

        const struct connection_entry *ce = l->array[i];
        if (!oob_probe_eligible(ce))
        {
            if (ce->remote)
            {
                msg(D_LOW, "server-probe: %s:%s: skipping (not a direct UDP remote)", ce->remote,
                    ce->remote_port);
            }
            continue;
        }

        /* ce->af honours a udp4/udp6 remote, as the connection does */
        struct addrinfo *ai = NULL;
        int status = openvpn_getaddrinfo(GETADDR_RESOLVE | GETADDR_TRY_ONCE | GETADDR_DATAGRAM,
                                         ce->remote, ce->remote_port, 0, NULL, ce->af, &ai);
        if (status != 0 || !ai)
        {
            msg(D_LOW, "server-probe: %s:%s: could not resolve", ce->remote, ce->remote_port);
            continue;
        }

        /* Store the first resolved address natively (no IPv4-mapping); it is
         * later probed on its family's socket. */
        memcpy(&targets[i].dest, ai->ai_addr, ai->ai_addrlen);
        targets[i].destlen = (socklen_t)ai->ai_addrlen;
        need_af[probe_af_index(ai->ai_family)] = true;
        freeaddrinfo(ai);
    }

    struct addrinfo *bind_local = oob_probe_bind_addrinfo(tmpl, &c->options);
    if (oob_probe_sockets_open(&pc, need_af, bind_local, tmpl, &c->options) == 0)
    {
        msg(D_LOW, "server-probe: nothing to probe; using configured order");
        if (bind_local)
        {
            freeaddrinfo(bind_local);
        }
        gc_free(&gc);
        return;
    }

    /* Send a probe to each resolved remote, on the socket of its address family.
     * An address several entries resolve to is probed once; its reply is
     * credited to each of them. */
    pc.probed = gc_malloc(sizeof(*pc.probed) * l->len, false, &gc);
    pc.n_probed = 0;

    int sent_count = 0;
    for (int i = 0; i < l->len; i++)
    {
        const struct connection_entry *ce = l->array[i];
        if (!targets[i].destlen)
        {
            continue;
        }
        socket_descriptor_t sd = pc.sd[probe_af_index(targets[i].dest.addr.sa.sa_family)];
        if (sd == SOCKET_UNDEFINED)
        {
            continue; /* family not probed, see oob_probe_sockets_open() */
        }
        if (!oob_addr_list_contains(pc.probed, pc.n_probed, &targets[i].dest))
        {
            if (sendto(sd, (const char *)BPTR(&probe), (int)BLEN(&probe), 0,
                       (struct sockaddr *)&targets[i].dest, targets[i].destlen)
                < 0)
            {
                msg(D_LOW, "server-probe: %s:%s: probe send failed", ce->remote, ce->remote_port);
                continue;
            }
            pc.probed[pc.n_probed++] = targets[i].dest;
        }
        openvpn_gettimeofday(&targets[i].sent_at, NULL);
        targets[i].sent = true;
        sent_count++;
    }

    if (sent_count > 0)
    {
        oob_probe_collect(&pc, &probe, &client_sid, targets, results, l->len,
                          c->sig);
    }
    oob_probe_sockets_close(&pc);
    if (bind_local)
    {
        freeaddrinfo(bind_local);
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
             * client's own setting wins, else the server's advertised value. */
            int client_margin = c->options.server_probe_latency_margin;
            int margin = oob_effective_margin(&results[i], client_margin);
            const char *margin_src = client_margin >= 0 ? "client" : "server-advertised";
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

    gc_free(&gc);
}
