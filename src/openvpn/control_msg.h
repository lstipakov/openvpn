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
 * Framing shared by the TLV-based control messages of the wire protocol.
 *
 * Such a message payload starts with a header -- a 16-bit message type, a
 * 32-bit message id and a 32-bit response id -- followed by a sequence of TLV
 * entries. Each TLV starts with a 4-byte header: a 16-bit field
 * whose most significant bit is the "optional" flag and whose remaining 15 bits
 * are the type, followed by a 16-bit length giving the size of the value that
 * follows the header.
 *
 * The message-type and TLV-type values themselves are specific to the message
 * family carried (out-of-band messages define theirs in oob.h), so only the
 * framing lives here.
 */

#ifndef CONTROL_MSG_H
#define CONTROL_MSG_H

#include "buffer.h"

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

/* The header at the start of every message payload. 0 is not a valid
 * message_id, so a response_id of 0 marks a message that answers none. */
struct ctrl_msg_header
{
    uint16_t type;        /**< message type */
    uint32_t message_id;  /**< chosen by the sender, nonzero */
    uint32_t response_id; /**< message_id of the message answered, or 0 */
};

/**
 * Write a message header to buf.
 *
 * @return true on success, false if buf has insufficient space.
 */
bool ctrl_msg_write_header(struct buffer *buf, const struct ctrl_msg_header *hdr);

/**
 * Read and verify a message header from buf, advancing past it.
 *
 * @param buf                buffer positioned at the message payload
 * @param expected_msg_type  the message type the payload must carry
 * @param hdr                filled with the header on success
 * @return true if a header was read, its type equals expected_msg_type and its
 *         message_id is nonzero; false otherwise.
 */
bool ctrl_msg_read_header(struct buffer *buf, uint16_t expected_msg_type,
                          struct ctrl_msg_header *hdr);

/**
 * Write a TLV header (type + optional flag + value length) to buf.
 *
 * @return true on success, false if buf has insufficient space.
 */
bool ctrl_msg_tlv_write_header(struct buffer *buf, uint16_t type, bool optional,
                               uint16_t value_len);

/**
 * Read a TLV header from buf, advancing past it.
 *
 * @param buf  buffer positioned at the TLV header
 * @param hdr  filled with the type, optional flag and value length on success
 * @return true on success, false if there are not enough bytes for a header.
 */
bool ctrl_msg_tlv_read_header(struct buffer *buf, struct ctrl_msg_tlv_header *hdr);

/**
 * Scan payload for the TLV of type wanted_type, skipping any other (e.g.
 * future) TLV type that is marked optional.
 *
 * This is for messages that carry exactly one mandatory TLV, which matches the
 * currently supported OOB messages: any other TLV that is not marked optional
 * invalidates the message wherever it is present, so the whole sequence is
 * walked. A message with several mandatory TLVs would need a scan that knows
 * all of them.
 *
 * On success value covers exactly the found TLV's value bytes. The length from
 * each TLV header is validated against payload as the scan goes, so the whole
 * value is guaranteed to be present; a header claiming more bytes than payload
 * holds is rejected rather than reported as found. payload is consumed as it is
 * read.
 *
 * @param payload      buffer positioned at a TLV header
 * @param wanted_type  the TLV type to look for
 * @param value        set to a buffer covering the found TLV's value; it points
 *                     into payload and owns no storage
 * @return true if the TLV was found, false if it is not present, a TLV header
 *         or value is malformed or truncated, or a TLV we do not understand is
 *         not marked optional.
 */
bool ctrl_msg_find_tlv(struct buffer *payload, uint16_t wanted_type, struct buffer *value);

#endif /* ifndef CONTROL_MSG_H */
