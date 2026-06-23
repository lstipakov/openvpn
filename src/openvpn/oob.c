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

/* Consume @p value_len bytes of TLV value, of which @p consumed have already
 * been read, ignoring (skipping) any trailing bytes that this version does not
 * understand. Fails if fewer than @p consumed bytes were declared. */
static bool
oob_skip_trailing(struct buffer *buf, uint16_t value_len, int consumed)
{
    if (value_len < consumed)
    {
        return false;
    }
    return buf_advance(buf, value_len - consumed);
}

bool
oob_msg_write_header(struct buffer *buf, uint16_t msg_type)
{
    return buf_write_u16(buf, msg_type);
}

bool
oob_msg_read_header(struct buffer *buf, uint16_t expected_msg_type)
{
    int msg_type = buf_read_u16(buf);
    return msg_type >= 0 && (uint16_t)msg_type == expected_msg_type;
}

bool
oob_tlv_write_header(struct buffer *buf, uint16_t type, bool optional, uint16_t value_len)
{
    uint16_t field = type & OOB_TLV_TYPE_MASK;
    if (optional)
    {
        field |= OOB_TLV_OPTIONAL_FLAG;
    }
    return buf_write_u16(buf, field) && buf_write_u16(buf, value_len);
}

bool
oob_tlv_read_header(struct buffer *buf, uint16_t *type, bool *optional, uint16_t *value_len)
{
    int field = buf_read_u16(buf);
    if (field < 0)
    {
        return false;
    }
    int len = buf_read_u16(buf);
    if (len < 0)
    {
        return false;
    }
    *type = (uint16_t)(field & OOB_TLV_TYPE_MASK);
    *optional = (field & OOB_TLV_OPTIONAL_FLAG) != 0;
    *value_len = (uint16_t)len;
    return true;
}

bool
oob_probe_parameter_write(struct buffer *buf, const struct oob_probe_parameter *p)
{
    return oob_tlv_write_header(buf, OOB_TLV_PROBE_PARAMETER, false, OOB_PROBE_PARAMETER_LEN)
           && buf_write_u64(buf, p->timestamp)
           && buf_write_u32(buf, p->flags);
}

bool
oob_probe_parameter_read(struct buffer *buf, struct oob_probe_parameter *p, uint16_t value_len)
{
    if (value_len < OOB_PROBE_PARAMETER_LEN)
    {
        return false;
    }
    bool ok = true;
    p->timestamp = buf_read_u64(buf, &ok);
    p->flags = buf_read_u32(buf, &ok);
    if (!ok)
    {
        return false;
    }
    return oob_skip_trailing(buf, value_len, OOB_PROBE_PARAMETER_LEN);
}

bool
oob_probe_reply_write(struct buffer *buf, const struct oob_probe_reply *r)
{
    return oob_tlv_write_header(buf, OOB_TLV_PROBE_REPLY, false, OOB_PROBE_REPLY_LEN)
           && session_id_write(&r->peer_session_id, buf)
           && buf_write_u16(buf, r->priority)
           && buf_write_u16(buf, r->weight)
           && buf_write_u16(buf, r->connect_lifetime)
           && buf_write_u32(buf, r->flags)
           && buf_write_u16(buf, r->max_latency_diff);
}

bool
oob_probe_reply_read(struct buffer *buf, struct oob_probe_reply *r, uint16_t value_len)
{
    if (value_len < OOB_PROBE_REPLY_LEN)
    {
        return false;
    }
    if (!session_id_read(&r->peer_session_id, buf))
    {
        return false;
    }
    int priority = buf_read_u16(buf);
    int weight = buf_read_u16(buf);
    int connect_lifetime = buf_read_u16(buf);
    if (priority < 0 || weight < 0 || connect_lifetime < 0)
    {
        return false;
    }
    bool ok = true;
    r->flags = buf_read_u32(buf, &ok);
    int max_latency_diff = buf_read_u16(buf);
    if (!ok || max_latency_diff < 0)
    {
        return false;
    }
    r->priority = (uint16_t)priority;
    r->weight = (uint16_t)weight;
    r->connect_lifetime = (uint16_t)connect_lifetime;
    r->max_latency_diff = (uint16_t)max_latency_diff;
    return oob_skip_trailing(buf, value_len, OOB_PROBE_REPLY_LEN);
}

bool
oob_server_probe_write(struct buffer *buf, const struct oob_probe_parameter *param)
{
    return oob_msg_write_header(buf, OOB_MSG_SERVER_PROBE)
           && oob_probe_parameter_write(buf, param);
}

/* Scan @p payload for the first TLV of type @p wanted_type, skipping any other
 * (e.g. future) TLV types. On success @p payload is left positioned at that
 * TLV's value and *value_len is its declared length. Returns false if the TLV
 * is not found or a header/length is malformed. */
static bool
oob_find_tlv(struct buffer *payload, uint16_t wanted_type, uint16_t *value_len)
{
    /* A TLV header is 4 bytes (type + length). */
    while (BLEN(payload) >= 4)
    {
        uint16_t type;
        bool optional;
        if (!oob_tlv_read_header(payload, &type, &optional, value_len))
        {
            return false;
        }
        if (type == wanted_type)
        {
            return true;
        }
        /* not the TLV we want: skip its value and keep scanning */
        if (!buf_advance(payload, *value_len))
        {
            return false;
        }
    }
    return false;
}

bool
oob_server_probe_read(struct buffer *payload, struct oob_probe_parameter *param)
{
    uint16_t value_len;
    return oob_msg_read_header(payload, OOB_MSG_SERVER_PROBE)
           && oob_find_tlv(payload, OOB_TLV_PROBE_PARAMETER, &value_len)
           && oob_probe_parameter_read(payload, param, value_len);
}

bool
oob_client_reply_write(struct buffer *buf, const struct oob_probe_reply *reply)
{
    return oob_msg_write_header(buf, OOB_MSG_PROBE_REPLY) && oob_probe_reply_write(buf, reply);
}

bool
oob_client_reply_read(struct buffer *payload, struct oob_probe_reply *reply)
{
    uint16_t value_len;
    return oob_msg_read_header(payload, OOB_MSG_PROBE_REPLY)
           && oob_find_tlv(payload, OOB_TLV_PROBE_REPLY, &value_len)
           && oob_probe_reply_read(payload, reply, value_len);
}

bool
oob_timestamp_in_window(uint64_t probe_ts, uint64_t now, uint64_t window_secs)
{
    uint64_t diff = (now > probe_ts) ? (now - probe_ts) : (probe_ts - now);
    return diff <= window_secs;
}

bool
oob_build_probe_reply(struct buffer *probe_payload, uint64_t now, uint64_t window_secs,
                      const struct session_id *peer_sid, uint16_t priority, uint16_t weight,
                      uint16_t max_latency_diff, struct oob_probe_reply *reply)
{
    struct oob_probe_parameter param;
    if (!oob_server_probe_read(probe_payload, &param))
    {
        return false;
    }

    /* Drop replayed or implausibly-timed probes before doing any more work. */
    if (!oob_timestamp_in_window(param.timestamp, now, window_secs))
    {
        return false;
    }

    memset(reply, 0, sizeof(*reply));
    reply->peer_session_id = *peer_sid;
    reply->priority = priority;
    reply->weight = weight;
    reply->max_latency_diff = max_latency_diff;
    /* connect_lifetime/flags left at 0 for now */
    return true;
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

    if (ra->responded != rb->responded)
    {
        return ra->responded ? -1 : 1;
    }
    if (ra->responded)
    {
        if (ra->priority != rb->priority)
        {
            return ra->priority < rb->priority ? -1 : 1;
        }
        if (ra->rtt_ms != rb->rtt_ms)
        {
            return ra->rtt_ms < rb->rtt_ms ? -1 : 1;
        }
    }
    return ra->index - rb->index;
}

int
oob_effective_margin(const struct oob_probe_result *r, int client_margin)
{
    if (client_margin >= 0)
    {
        return client_margin; /* the client's own setting is authoritative */
    }
    if (r->max_latency_diff > 0)
    {
        return (int)r->max_latency_diff; /* else the server's advertised value */
    }
    return OOB_DEFAULT_LATENCY_MARGIN_MS;
}

/* Reorder the index list @p idx[0..m) into DNS-SRV (RFC 2782) weighted-random
 * order by results[idx[k]].weight: each position is filled by a remaining entry
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
            sum += results[idx[k]].weight;
        }
        int chosen = pos;
        if (sum > 0)
        {
            int64_t r = rng() % sum; /* uniform in [0, sum) */
            long acc = 0;
            for (int k = pos; k < m; k++)
            {
                acc += results[idx[k]].weight;
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

/* Reorder one priority run (@p run[0..m), already RTT-sorted) in place:
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
        if (run[k].rtt_ms - best_rtt < (unsigned int)oob_effective_margin(&run[k], client_margin))
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
        while (j < n && results[j].responded && results[j].priority == results[i].priority)
        {
            j++;
        }
        oob_order_priority_run(results + i, j - i, client_margin, rng, gc);
        i = j;
    }
}
