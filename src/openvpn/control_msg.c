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

#include "control_msg.h"

bool
ctrl_msg_read_header(struct buffer *buf, uint16_t expected_msg_type)
{
    int msg_type = buf_read_u16(buf);
    return msg_type >= 0 && (uint16_t)msg_type == expected_msg_type;
}

bool
ctrl_msg_tlv_write_header(struct buffer *buf, uint16_t type, bool optional, uint16_t value_len)
{
    uint16_t field = type & CTRL_MSG_TLV_TYPE_MASK;
    if (optional)
    {
        field |= CTRL_MSG_TLV_OPTIONAL_FLAG;
    }
    return buf_write_u16(buf, field) && buf_write_u16(buf, value_len);
}

bool
ctrl_msg_tlv_read_header(struct buffer *buf, struct ctrl_msg_tlv_header *hdr)
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
    hdr->type = (uint16_t)(field & CTRL_MSG_TLV_TYPE_MASK);
    hdr->optional = (field & CTRL_MSG_TLV_OPTIONAL_FLAG) != 0;
    hdr->value_len = (uint16_t)len;
    return true;
}

bool
ctrl_msg_find_tlv(struct buffer *payload, uint16_t wanted_type, struct buffer *value)
{
    struct ctrl_msg_tlv_header hdr;
    bool found = false;
    while (BLEN(payload) > 0)
    {
        if (!ctrl_msg_tlv_read_header(payload, &hdr))
        {
            /* bytes remain but too few for a header: truncated */
            return false;
        }
        /* Take the value out of payload. This validates that the header's
         * length is really there and advances past it in one step, so the TLV
         * we are looking for and the ones we skip are bounds-checked alike. */
        uint8_t *v = buf_read_alloc(payload, hdr.value_len);
        if (!v)
        {
            return false;
        }
        if (hdr.type == wanted_type)
        {
            if (!found)
            {
                buf_set_read(value, v, hdr.value_len);
                found = true;
            }
        }
        else if (!hdr.optional)
        {
            /* A TLV we do not understand that the sender did not mark optional
             * carries something it requires us to act on, so the message as a
             * whole is not ours to interpret. This is why the scan continues
             * past the wanted type: such a TLV invalidates the message wherever
             * in the sequence it sits. */
            return false;
        }
    }
    return found;
}
