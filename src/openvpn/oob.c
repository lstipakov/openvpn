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
