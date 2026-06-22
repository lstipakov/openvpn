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

/* Where we sent a probe, so a reply's source address can be matched back to the
 * connection-list entry it belongs to. */
struct probe_target
{
    struct sockaddr_storage dest;
    socklen_t destlen;
    bool sent;
};

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

/* Open a UDP socket for probing. Prefer a dual-stack IPv6 socket (so a single
 * socket reaches both IPv6 and IPv4-mapped remotes, matching OpenVPN's default
 * IPV6_V6ONLY=0 behaviour); fall back to IPv4 if IPv6 is unavailable. *af is
 * set to the socket's address family. */
static socket_descriptor_t
oob_probe_socket_open(sa_family_t *af)
{
    socket_descriptor_t sd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (sd != SOCKET_UNDEFINED)
    {
        set_cloexec(sd);
        int off = 0;
        if (setsockopt(sd, IPPROTO_IPV6, IPV6_V6ONLY, (void *)&off, sizeof(off)) != 0)
        {
            /* Not fatal: on a v6-only stack we simply cannot reach v4 remotes. */
            msg(D_LOW, "server-probe: could not enable dual-stack on probe socket");
        }
        *af = AF_INET6;
        return sd;
    }

    /* No IPv6 available: fall back to an IPv4-only probe socket. */
    sd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sd != SOCKET_UNDEFINED)
    {
        set_cloexec(sd);
        *af = AF_INET;
    }
    return sd;
}

/* Fill @p dst from a resolved address, converting IPv4 to an IPv4-mapped IPv6
 * address when we are sending through a dual-stack v6 socket. Returns the
 * address length, or 0 if the address cannot be reached by this socket. */
static socklen_t
oob_probe_make_dest(const struct addrinfo *ai, sa_family_t sock_af, struct sockaddr_storage *dst)
{
    memset(dst, 0, sizeof(*dst));

    if (ai->ai_family == sock_af)
    {
        memcpy(dst, ai->ai_addr, ai->ai_addrlen);
        return (socklen_t)ai->ai_addrlen;
    }

    if (sock_af == AF_INET6 && ai->ai_family == AF_INET)
    {
        /* IPv4 -> IPv4-mapped IPv6 (::ffff:a.b.c.d) for the dual-stack socket. */
        const struct sockaddr_in *s4 = (const struct sockaddr_in *)(const void *)ai->ai_addr;
        struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)dst;
        s6->sin6_family = AF_INET6;
        s6->sin6_port = s4->sin_port;
        s6->sin6_addr.s6_addr[10] = 0xff;
        s6->sin6_addr.s6_addr[11] = 0xff;
        memcpy(&s6->sin6_addr.s6_addr[12], &s4->sin_addr, 4);
        return sizeof(struct sockaddr_in6);
    }

    /* e.g. an IPv6 remote reached only via a v4-only fallback socket */
    return 0;
}

/* Parse one received datagram as a PROBE_REPLY and, if valid and matching one
 * of the probes we sent, record the reply in @p results. */
static void
oob_probe_handle_reply(const uint8_t *data, int len, const struct session_id *client_sid,
                       const struct sockaddr_storage *from, const struct probe_target *targets,
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

    /* Match the reply's source address to the remote we probed. */
    for (int i = 0; i < n; i++)
    {
        if (targets[i].sent
            && addr_port_match((const struct openvpn_sockaddr *)(const void *)from,
                               (const struct openvpn_sockaddr *)(const void *)&targets[i].dest))
        {
            results[i].responded = true;
            results[i].priority = reply.priority;
            results[i].weight = reply.weight;
            results[i].max_latency_diff = reply.max_latency_diff;
            break;
        }
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

/* Receive replies for one time slice (until @p deadline), recording each that
 * matches a probe we sent. Returns true if every sent probe has been answered. */
static bool
oob_probe_receive_slice(socket_descriptor_t sd, const struct timeval *deadline,
                        const struct session_id *client_sid, const struct probe_target *targets,
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
        openvpn_fd_set(sd, &readfds);
        if (openvpn_select((int)sd + 1, &readfds, NULL, NULL, &timeout) <= 0)
        {
            return false; /* slice timed out, or error */
        }

        uint8_t data[256];
        struct sockaddr_storage from;
        socklen_t fromlen = sizeof(from);
        int len = (int)recvfrom(sd, (char *)data, (int)sizeof(data), 0,
                                (struct sockaddr *)&from, &fromlen);
        if (len > 0)
        {
            oob_probe_handle_reply(data, len, client_sid, &from, targets, results, n);
            if (oob_count_answered(targets, results, n) >= outstanding)
            {
                return true; /* every probe we sent has been answered */
            }
        }
    }
}

/* Resend the probe to every remote that we probed but that has not answered. */
static void
oob_probe_resend_unanswered(socket_descriptor_t sd, const struct buffer *probe,
                            const struct probe_target *targets,
                            const struct oob_probe_result *results, int n)
{
    for (int i = 0; i < n; i++)
    {
        if (targets[i].sent && !results[i].responded)
        {
            sendto(sd, (const char *)BPTR(probe), (int)BLEN(probe), 0,
                   (const struct sockaddr *)&targets[i].dest, targets[i].destlen);
        }
    }
}

/* Collect replies over the probe window, resending unanswered probes up to
 * OOB_PROBE_RETRIES times (UDP is lossy and a probe carries no retransmission
 * of its own). The window is split into equal slices, one per send round; after
 * each slice but the last we resend to whoever has not answered yet. Returns
 * once the window elapses or every sent probe has been answered. */
static void
oob_probe_collect(socket_descriptor_t sd, const struct buffer *probe,
                  const struct session_id *client_sid, const struct probe_target *targets,
                  struct oob_probe_result *results, int n)
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

        if (oob_probe_receive_slice(sd, &deadline, client_sid, targets, results, n, want))
        {
            return; /* all answered */
        }

        if (slice + 1 < slices)
        {
            oob_probe_resend_unanswered(sd, probe, targets, results, n);
        }
    }
}

/* Permute the connection list so entries appear in @p ranked order. */
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

    sa_family_t sock_af = AF_UNSPEC;
    socket_descriptor_t sd = oob_probe_socket_open(&sock_af);
    if (sd == SOCKET_UNDEFINED)
    {
        msg(D_LOW, "server-probe: could not open probe socket; using configured order");
        gc_free(&gc);
        return;
    }

    struct probe_target *targets = gc_malloc(sizeof(*targets) * l->len, true, &gc);
    struct oob_probe_result *results = gc_malloc(sizeof(*results) * l->len, true, &gc);

    struct buffer probe = alloc_buf_gc(256, &gc);
    if (!oob_probe_build_packet(&probe, &client_sid))
    {
        msg(D_LOW, "server-probe: could not build probe packet; using configured order");
        openvpn_close_socket(sd);
        gc_free(&gc);
        return;
    }

    msg(D_LOW, "server-probe: probing %d remote(s) with a %d ms window", l->len,
        OOB_PROBE_WINDOW_MS);

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

        socklen_t destlen = oob_probe_make_dest(ai, sock_af, &targets[i].dest);
        if (destlen == 0)
        {
            msg(D_LOW, "server-probe: %s:%s: not reachable by the probe socket", ce->remote,
                ce->remote_port);
        }
        else if (sendto(sd, (const char *)BPTR(&probe), (int)BLEN(&probe), 0,
                        (struct sockaddr *)&targets[i].dest, destlen)
                 < 0)
        {
            msg(D_LOW, "server-probe: %s:%s: probe send failed", ce->remote, ce->remote_port);
        }
        else
        {
            targets[i].destlen = destlen;
            targets[i].sent = true;
            sent_count++;
        }
        freeaddrinfo(ai);
    }

    if (sent_count > 0)
    {
        oob_probe_collect(sd, &probe, &client_sid, targets, results, l->len);
    }
    openvpn_close_socket(sd);

    /* Log each remote's outcome while results[i] still maps to array[i]. */
    int responded = 0;
    for (int i = 0; i < l->len; i++)
    {
        const struct connection_entry *ce = l->array[i];
        if (results[i].responded)
        {
            responded++;
            msg(D_LOW, "server-probe: %s:%s answered (priority %d, weight %d)", ce->remote,
                ce->remote_port, results[i].priority, results[i].weight);
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
