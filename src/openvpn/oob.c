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
