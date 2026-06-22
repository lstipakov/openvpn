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

#include "oob.h"
#include "control_msg.h"

bool
oob_probe_parameter_write(struct buffer *buf, const struct oob_probe_parameter *p)
{
    return ctrl_msg_tlv_write_header(buf, OOB_TLV_PROBE_PARAMETER, false, OOB_PROBE_PARAMETER_LEN)
           && buf_write_u64(buf, p->timestamp)
           && buf_write_u32(buf, p->flags);
}

bool
oob_probe_parameter_read(struct buffer *buf, struct oob_probe_parameter *p)
{
    /* One bounds check covers the whole value: every field read below then fits
     * by construction (OOB_PROBE_PARAMETER_LEN is the sum of their sizes), so
     * none of them needs its own error handling. Trailing bytes this version
     * does not understand are simply left unread. */
    if (buf_len(buf) < OOB_PROBE_PARAMETER_LEN)
    {
        return false;
    }
    p->timestamp = buf_read_u64(buf, NULL);
    p->flags = buf_read_u32(buf, NULL);
    return true;
}

bool
oob_probe_reply_write(struct buffer *buf, const struct oob_probe_reply *r)
{
    return ctrl_msg_tlv_write_header(buf, OOB_TLV_PROBE_REPLY, false, OOB_PROBE_REPLY_LEN)
           && session_id_write(&r->peer_session_id, buf)
           && buf_write_u16(buf, r->priority)
           && buf_write_u16(buf, r->weight)
           && buf_write_u16(buf, r->max_latency_diff)
           && buf_write_u16(buf, r->connect_lifetime)
           && buf_write_u32(buf, r->flags);
}

bool
oob_probe_reply_read(struct buffer *buf, struct oob_probe_reply *r)
{
    /* One bounds check for the whole value, as in oob_probe_parameter_read(). */
    if (buf_len(buf) < OOB_PROBE_REPLY_LEN)
    {
        return false;
    }
    session_id_read(&r->peer_session_id, buf);
    r->priority = (uint16_t)buf_read_u16(buf);
    r->weight = (uint16_t)buf_read_u16(buf);
    r->max_latency_diff = (uint16_t)buf_read_u16(buf);
    r->connect_lifetime = (uint16_t)buf_read_u16(buf);
    r->flags = buf_read_u32(buf, NULL);
    return true;
}

bool
oob_server_probe_write(struct buffer *buf, const struct oob_probe_parameter *param)
{
    return buf_write_u16(buf, OOB_MSG_SERVER_PROBE) && oob_probe_parameter_write(buf, param);
}

bool
oob_server_probe_read(struct buffer *payload, struct oob_probe_parameter *param)
{
    if (!ctrl_msg_read_header(payload, OOB_MSG_SERVER_PROBE))
    {
        return false;
    }

    struct buffer value;
    if (!ctrl_msg_find_tlv(payload, OOB_TLV_PROBE_PARAMETER, &value))
    {
        return false;
    }

    return oob_probe_parameter_read(&value, param);
}

bool
oob_client_reply_write(struct buffer *buf, const struct oob_probe_reply *reply)
{
    return buf_write_u16(buf, OOB_MSG_PROBE_REPLY) && oob_probe_reply_write(buf, reply);
}

bool
oob_client_reply_read(struct buffer *payload, struct oob_probe_reply *reply)
{
    if (!ctrl_msg_read_header(payload, OOB_MSG_PROBE_REPLY))
    {
        return false;
    }

    struct buffer value;
    if (!ctrl_msg_find_tlv(payload, OOB_TLV_PROBE_REPLY, &value))
    {
        return false;
    }

    return oob_probe_reply_read(&value, reply);
}

bool
oob_timestamp_in_window(uint64_t probe_ts, uint64_t now, uint64_t window_secs)
{
    uint64_t diff = (now > probe_ts) ? (now - probe_ts) : (probe_ts - now);
    return diff <= window_secs;
}

bool
oob_server_probe_accept(struct buffer *probe_payload, uint64_t now, uint64_t window_secs)
{
    struct oob_probe_parameter param;
    if (!oob_server_probe_read(probe_payload, &param))
    {
        return false;
    }

    /* Drop replayed or implausibly-timed probes before doing any more work. */
    return oob_timestamp_in_window(param.timestamp, now, window_secs);
}

int
oob_probe_next_target_at(const struct openvpn_sockaddr *from, const struct oob_probe_target *targets,
                         const struct oob_probe_result *results, int n, int start)
{
    for (int i = start; i < n; i++)
    {
        if (targets[i].sent && !results[i].responded && addr_port_match(from, &targets[i].dest))
        {
            return i;
        }
    }
    return -1;
}

bool
oob_addr_list_contains(const struct openvpn_sockaddr *list, int n, const struct openvpn_sockaddr *addr)
{
    for (int i = 0; i < n; i++)
    {
        if (addr_port_match(&list[i], addr))
        {
            return true;
        }
    }
    return false;
}

/* Base ordering: responders before non-responders, then by priority (lower
 * first), then by RTT (lower first), then by original index for determinism.
 * This groups responders into priority runs pre-sorted by RTT, which the
 * candidate-band step below relies on (run[0] is the fastest in its group). */
static int
oob_probe_result_compare(const void *a, const void *b)
{
    const struct oob_probe_result *ra = a;
    const struct oob_probe_result *rb = b;

    if (ra->responded && rb->responded)
    {
        /* both answered: lowest priority first, then lowest RTT */
        if (ra->reply.priority != rb->reply.priority)
        {
            return ra->reply.priority < rb->reply.priority ? -1 : 1;
        }
        if (ra->rtt_ms != rb->rtt_ms)
        {
            return ra->rtt_ms < rb->rtt_ms ? -1 : 1;
        }
    }
    else if (ra->responded)
    {
        return -1; /* only a answered: it ranks first */
    }
    else if (rb->responded)
    {
        return 1; /* only b answered */
    }

    /* neither answered, or all keys equal: keep the configured order */
    return ra->index - rb->index;
}

int
oob_effective_margin(const struct oob_probe_result *r, int client_margin)
{
    if (client_margin >= 0)
    {
        return client_margin;              /* the client's own setting is authoritative */
    }
    return (int)r->reply.max_latency_diff; /* else the server's advertised value */
}

/* Reorder the index list idx[0..m) into DNS-SRV (RFC 2782) weighted-random
 * order by results[idx[k]].reply.weight: each position is filled by a remaining entry
 * chosen with probability proportional to its weight. When all remaining
 * weights are 0 the current (RTT-sorted) order is kept. */
static void
oob_weighted_order(const struct oob_probe_result *results, int *idx, int m, int64_t (*rng)(void))
{
    for (int pos = 0; pos < m; pos++)
    {
        long sum = 0;
        for (int k = pos; k < m; k++)
        {
            sum += results[idx[k]].reply.weight;
        }
        int chosen = pos;
        if (sum > 0)
        {
            int64_t r = rng() % sum; /* uniform in [0, sum) */
            long acc = 0;
            for (int k = pos; k < m; k++)
            {
                acc += results[idx[k]].reply.weight;
                if (acc > r)
                {
                    chosen = k;
                    break;
                }
            }
        }
        int t = idx[pos];
        idx[pos] = idx[chosen];
        idx[chosen] = t;
    }
}

/* Reorder one priority run (run[0..m), already RTT-sorted) in place:
 * candidates (RTT within the band of the fastest) first, ordered by weighted
 * random; then non-candidates in RTT order. */
static void
oob_order_priority_run(struct oob_probe_result *run, int m, int client_margin, int64_t (*rng)(void),
                       struct gc_arena *gc)
{
    if (m <= 1)
    {
        return;
    }

    unsigned int best_rtt = run[0].rtt_ms; /* run is RTT-sorted: [0] is fastest */

    int *cand = gc_malloc(sizeof(int) * m, false, gc);
    int *non = gc_malloc(sizeof(int) * m, false, gc);
    int nc = 0;
    int nn = 0;
    for (int k = 0; k < m; k++)
    {
        /* "no more than their max_latency_diff larger than the lowest RTT", so the
         * comparison includes the margin itself. That also keeps the fastest of
         * the run a candidate when it advertises 0: announcing 0 asks not to be
         * compared on weight, not to be ranked behind a slower server. */
        unsigned int gap = run[k].rtt_ms - best_rtt;
        if (gap <= (unsigned int)oob_effective_margin(&run[k], client_margin))
        {
            cand[nc++] = k;
        }
        else
        {
            non[nn++] = k;
        }
    }

    oob_weighted_order(run, cand, nc, rng);

    struct oob_probe_result *tmp = gc_malloc(sizeof(*tmp) * m, false, gc);
    int t = 0;
    for (int k = 0; k < nc; k++)
    {
        tmp[t++] = run[cand[k]];
    }
    for (int k = 0; k < nn; k++)
    {
        tmp[t++] = run[non[k]];
    }
    memcpy(run, tmp, sizeof(*run) * m);
}

void
oob_rank_probe_results(struct oob_probe_result *results, int n, int client_margin,
                       int64_t (*rng)(void), struct gc_arena *gc)
{
    if (n <= 1)
    {
        return;
    }

    /* Base order: responders first, grouped by priority, RTT-sorted within. */
    qsort(results, (size_t)n, sizeof(*results), oob_probe_result_compare);

    /* Reorder each priority run of responders by candidate-band + weight. */
    int i = 0;
    while (i < n && results[i].responded)
    {
        int j = i;
        while (j < n && results[j].responded
               && results[j].reply.priority == results[i].reply.priority)
        {
            j++;
        }
        oob_order_priority_run(results + i, j - i, client_margin, rng, gc);
        i = j;
    }
}
