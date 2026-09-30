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

/**
 * @file
 * TLV framing shared by the TLV-based control messages of the wire protocol.
 *
 * Such a message payload is a sequence of TLV entries. Each TLV starts with a
 * 4-byte header: a 16-bit field whose most significant bit is the "optional"
 * flag and whose remaining 15 bits are the type, followed by a 16-bit length
 * giving the size of the value that follows the header.
 *
 * All of these messages share one TLV type space, so the TLV types are all
 * defined here. Only the framing is handled here: what a message does with a
 * TLV type it does not know, marked optional or not, is up to its parser.
 */

#ifndef CONTROL_MSG_H
#define CONTROL_MSG_H

#include "buffer.h"

/* TLV types */
#define TLV_TYPE_EARLY_NEG_FLAGS 0x0001 /* early negotiation, in the reset packets */

/* TLV header bit layout of the first 16-bit field */
#define CTRL_MSG_TLV_OPTIONAL_FLAG 0x8000
#define CTRL_MSG_TLV_TYPE_MASK     0x7fff

/* The header every TLV carries: the 15-bit type and optional flag packed into
 * the first 16-bit field, then the length of the value that follows. */
struct ctrl_msg_tlv_header
{
    uint16_t type;      /**< the 15-bit TLV type */
    bool optional;      /**< value of the optional flag */
    uint16_t value_len; /**< length of the value following the header */
};

/**
 * Write a TLV header (type + optional flag + value length) to buf.
 * type must fit in the 15 bits of the type field.
 *
 * @return true on success, false if buf has insufficient space.
 */
bool ctrl_msg_tlv_write_header(struct buffer *buf, uint16_t type, bool optional,
                               uint16_t value_len);

/**
 * Write a complete TLV whose value is a single 16-bit integer to buf.
 *
 * @return true on success, false if buf has insufficient space.
 */
bool ctrl_msg_tlv_write_u16(struct buffer *buf, uint16_t type, bool optional, uint16_t value);

/**
 * Read a TLV header from buf, advancing past it.
 *
 * @param buf  buffer positioned at the TLV header
 * @param hdr  filled with the type, optional flag and value length on success
 * @return true on success, false if there are not enough bytes for a header.
 */
bool ctrl_msg_tlv_read_header(struct buffer *buf, struct ctrl_msg_tlv_header *hdr);

/**
 * Read the next TLV from buf, advancing past its header and value. Call it
 * while BLEN(buf) > 0 to walk a whole payload.
 *
 * The length from the header is validated against buf, so on success the
 * whole value is present: a header claiming more bytes than buf holds is
 * rejected.
 *
 * @param buf    buffer positioned at a TLV header
 * @param hdr    filled with the TLV's type, optional flag and value length
 * @param value  set to a buffer covering exactly the TLV's value; it points
 *               into buf and owns no storage
 * @return true on success, false if the header or the value is truncated; buf
 *         may then be left partly consumed.
 */
bool ctrl_msg_tlv_next(struct buffer *buf, struct ctrl_msg_tlv_header *hdr, struct buffer *value);

#endif /* ifndef CONTROL_MSG_H */
