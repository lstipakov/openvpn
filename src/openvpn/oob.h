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
 * Encoding/decoding of out-of-band (P_CONTROL_OOB_V1) control messages.
 *
 * An OOB message payload starts with a 16-bit message type (the 0x1xx space:
 * SERVER_PROBE, PROBE_REPLY, ...) followed by a sequence of TLV entries.
 *
 * Each TLV starts with a 4-byte header: a 16-bit field whose most significant
 * bit is the "optional" flag and whose remaining 15 bits are the type (the
 * 0x2xx space), followed by a 16-bit length giving the size of the value that
 * follows the header.
 *
 * This slice implements the SERVER_PROBE / PROBE_REPLY pair used for server
 * latency checks. Other message/TLV types are added as the feature grows.
 */

#ifndef OOB_H
#define OOB_H

#include "buffer.h"
#include "session_id.h"

/* OOB message types: the 16-bit value at the start of an OOB payload, before
 * its TLV entries. Distinct from the TLV-type space (0x2xx); see the "Messages"
 * table in the OOB section of the wire protocol spec. */
#define OOB_MSG_SERVER_PROBE 0x100
#define OOB_MSG_PROBE_REPLY  0x101

/* TLV header bit layout of the first 16-bit field */
#define OOB_TLV_OPTIONAL_FLAG 0x8000
#define OOB_TLV_TYPE_MASK     0x7fff

/* TLV types (see the OOB control message section of the wire protocol spec) */
#define OOB_TLV_PROBE_PARAMETER 0x200
#define OOB_TLV_PROBE_REPLY     0x201

/* Minimum on-wire value length (excluding the 4-byte TLV header) of each TLV.
 * The value may be longer for forward compatibility; trailing bytes that are
 * not understood are ignored on read. */
#define OOB_PROBE_PARAMETER_LEN 12
#define OOB_PROBE_REPLY_LEN     20

/* probe parameter TLV (sent by the client in a SERVER_PROBE) */
struct oob_probe_parameter
{
    uint64_t timestamp; /**< client clock as a UNIX timestamp */
    uint32_t flags;     /**< client capability flags, currently must be 0 */
};

/* probe reply TLV (sent by the server in a PROBE_REPLY) */
struct oob_probe_reply
{
    struct session_id peer_session_id; /**< echoes the session id of the request */
    uint16_t priority;                 /**< DNS-SRV style priority (lower is preferred) */
    uint16_t weight;                   /**< DNS-SRV style weight */
    uint16_t connect_lifetime;         /**< seconds the probe stays valid as a handshake shortcut */
    uint32_t flags;                    /**< server behaviour flags */
    uint16_t max_latency_diff;         /**< advertised candidate-band margin in ms;
                                        *   0 means "defer to the client's setting" */
};

/**
 * Write an OOB message-type header (the 16-bit message type preceding the
 * TLVs) to @p buf.
 *
 * @return true on success, false if @p buf has insufficient space.
 */
bool oob_msg_write_header(struct buffer *buf, uint16_t msg_type);

/**
 * Read and verify an OOB message-type header from @p buf, advancing past it.
 *
 * @param buf                buffer positioned at the OOB message payload
 * @param expected_msg_type  the message type the payload must carry
 * @return true if a message type was read and equals @p expected_msg_type,
 *         false on a short buffer or a mismatching type.
 */
bool oob_msg_read_header(struct buffer *buf, uint16_t expected_msg_type);

/**
 * Write a TLV header (type + optional flag + value length) to @p buf.
 *
 * @return true on success, false if @p buf has insufficient space.
 */
bool oob_tlv_write_header(struct buffer *buf, uint16_t type, bool optional, uint16_t value_len);

/**
 * Read a TLV header from @p buf, advancing past it.
 *
 * @param buf        buffer positioned at the TLV header
 * @param type       set to the 15-bit TLV type
 * @param optional   set to the value of the optional flag
 * @param value_len  set to the declared value length
 * @return true on success, false if there are not enough bytes for a header.
 */
bool oob_tlv_read_header(struct buffer *buf, uint16_t *type, bool *optional, uint16_t *value_len);

/**
 * Write a complete probe parameter TLV (header + value) to @p buf.
 */
bool oob_probe_parameter_write(struct buffer *buf, const struct oob_probe_parameter *p);

/**
 * Read a probe parameter TLV value of @p value_len bytes from @p buf.
 *
 * The TLV header must already have been consumed (e.g. via
 * oob_tlv_read_header()). @p value_len bytes are always consumed on success,
 * including any trailing bytes beyond the fields understood here.
 *
 * @return true on success, false if @p value_len is too short or @p buf is
 *         truncated.
 */
bool oob_probe_parameter_read(struct buffer *buf, struct oob_probe_parameter *p,
                              uint16_t value_len);

/**
 * Write a complete probe reply TLV (header + value) to @p buf.
 */
bool oob_probe_reply_write(struct buffer *buf, const struct oob_probe_reply *r);

/**
 * Read a probe reply TLV value of @p value_len bytes from @p buf. See
 * oob_probe_parameter_read() for the calling convention.
 */
bool oob_probe_reply_read(struct buffer *buf, struct oob_probe_reply *r, uint16_t value_len);

/**
 * Write a complete SERVER_PROBE message (message-type header + probe_parameter
 * TLV) to @p buf. Sent by the client.
 */
bool oob_server_probe_write(struct buffer *buf, const struct oob_probe_parameter *param);

/**
 * Read a received OOB SERVER_PROBE: verify its message-type header, then scan
 * for the probe_parameter TLV. TLV types other than probe_parameter are
 * skipped, so the scan tolerates additional/future TLVs. @p payload is consumed
 * as it is read.
 *
 * @param payload  buffer positioned at the start of the OOB message payload
 * @param param    filled with the parsed probe_parameter on success
 * @return true if the header matched and a well-formed probe_parameter was
 *         found, false otherwise
 */
bool oob_server_probe_read(struct buffer *payload, struct oob_probe_parameter *param);

/**
 * Write a complete PROBE_REPLY message (message-type header + probe_reply TLV)
 * to @p buf. Sent by the server.
 */
bool oob_client_reply_write(struct buffer *buf, const struct oob_probe_reply *reply);

/**
 * Check whether a probe timestamp is within an acceptable window around the
 * current time. Used to cheaply drop replayed or implausibly-timed probes
 * before doing any further work (see the probe_parameter timestamp rationale
 * in the wire protocol specification).
 *
 * @param probe_ts     timestamp from the probe_parameter (UNIX seconds)
 * @param now          current time (UNIX seconds)
 * @param window_secs  maximum allowed difference, in either direction
 * @return true if |now - probe_ts| <= window_secs
 */
bool oob_timestamp_in_window(uint64_t probe_ts, uint64_t now, uint64_t window_secs);

/**
 * Process the TLV payload of a received SERVER_PROBE and decide whether to
 * answer it. Combines oob_server_probe_read() and oob_timestamp_in_window():
 * the probe is dropped (false returned) if it has no valid probe_parameter or
 * its timestamp is outside the acceptable window. On success @p reply is
 * populated with the peer's session id echoed back and the remaining fields
 * zeroed, ready to be wrapped and sent.
 *
 * This is the transport-agnostic decision step; the caller performs the send.
 *
 * @param probe_payload  TLV payload of the received OOB SERVER_PROBE
 * @param now            current time (UNIX seconds)
 * @param window_secs    acceptable timestamp skew, in either direction
 * @param peer_sid       session id of the requesting peer (echoed in the reply)
 * @param reply          filled with the reply to send on success
 * @return true if a reply should be sent, false to silently drop the probe
 */
bool oob_build_probe_reply(struct buffer *probe_payload, uint64_t now, uint64_t window_secs,
                           const struct session_id *peer_sid, struct oob_probe_reply *reply);

#endif /* OOB_H */
