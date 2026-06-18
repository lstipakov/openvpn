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
oob_probe_request_write(struct buffer *buf, const struct oob_probe_request *r)
{
    return ctrl_msg_tlv_write_header(buf, TLV_TYPE_PROBE_REQUEST, false, OOB_PROBE_REQUEST_LEN)
           && buf_write_u32(buf, r->request_id)
           && buf_write_u64(buf, r->timestamp)
           && buf_write_u32(buf, r->flags);
}

bool
oob_probe_request_read(struct buffer *buf, struct oob_probe_request *r)
{
    /* One bounds check covers the whole value: every field read below then fits
     * by construction (OOB_PROBE_REQUEST_LEN is the sum of their sizes), so
     * none of them needs its own error handling. Trailing bytes this version
     * does not understand are simply left unread. */
    if (buf_len(buf) < OOB_PROBE_REQUEST_LEN)
    {
        return false;
    }
    r->request_id = buf_read_u32(buf, NULL);
    r->timestamp = buf_read_u64(buf, NULL);
    r->flags = buf_read_u32(buf, NULL);
    return true;
}

bool
oob_probe_reply_write(struct buffer *buf, const struct oob_probe_reply *r)
{
    return ctrl_msg_tlv_write_header(buf, TLV_TYPE_PROBE_REPLY, false, OOB_PROBE_REPLY_LEN)
           && buf_write_u32(buf, r->request_id)
           && buf_write_u16(buf, r->priority)
           && buf_write_u16(buf, r->weight)
           && buf_write_u16(buf, r->max_latency_diff)
           && buf_write_u16(buf, r->connect_lifetime)
           && buf_write_u16(buf, r->flags);
}

bool
oob_probe_reply_read(struct buffer *buf, struct oob_probe_reply *r)
{
    /* One bounds check for the whole value, as in oob_probe_request_read(). */
    if (buf_len(buf) < OOB_PROBE_REPLY_LEN)
    {
        return false;
    }
    r->request_id = buf_read_u32(buf, NULL);
    r->priority = (uint16_t)buf_read_u16(buf);
    r->weight = (uint16_t)buf_read_u16(buf);
    r->max_latency_diff = (uint16_t)buf_read_u16(buf);
    r->connect_lifetime = (uint16_t)buf_read_u16(buf);
    r->flags = (uint16_t)buf_read_u16(buf);
    return true;
}

bool
oob_probe_request_find(struct buffer *payload, struct oob_probe_request *req)
{
    struct buffer value;
    return ctrl_msg_find_tlv(payload, TLV_TYPE_PROBE_REQUEST, &value)
           && oob_probe_request_read(&value, req);
}

bool
oob_timestamp_in_window(uint64_t probe_ts, uint64_t now, uint64_t window_secs)
{
    uint64_t diff = (now > probe_ts) ? (now - probe_ts) : (probe_ts - now);
    return diff <= window_secs;
}

enum oob_probe_verdict
oob_probe_request_check(struct buffer *probe_payload, uint64_t now, uint64_t window_secs,
                        struct oob_probe_request *req)
{
    if (!oob_probe_request_find(probe_payload, req))
    {
        return OOB_PROBE_INVALID;
    }
    return oob_timestamp_in_window(req->timestamp, now, window_secs) ? OOB_PROBE_OK
                                                                     : OOB_PROBE_STALE;
}
