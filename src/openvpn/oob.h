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
 * An OOB message payload is a sequence of TLV entries; the TLVs it carries say
 * what the message is: a client probes a server with a probe request TLV, and
 * the server answers with a probe reply TLV. The TLV framing and the TLV types
 * are shared with the other TLV-based control messages and live in
 * control_msg.h; this file defines the values of the OOB TLVs and the
 * OOB-specific decisions taken on them.
 */

#ifndef OOB_H
#define OOB_H

#include "buffer.h"
#include "control_msg.h"
#include "session_id.h"

/* Minimum on-wire value length (excluding the 4-byte TLV header) of each TLV:
 * the sizes of its fixed fields in wire order (see the structs below). The
 * value may be longer for forward compatibility; trailing bytes that are not
 * understood are ignored on read.
 *
 * probe request: request_id (u32), timestamp (u64), flags (u32)
 * probe reply: request_id (u32), then priority, weight, max_latency_diff,
 * connect_lifetime and flags (u16 each) */
#define OOB_PROBE_REQUEST_LEN ((uint16_t)(sizeof(uint32_t) + sizeof(uint64_t) + sizeof(uint32_t)))
#define OOB_PROBE_REPLY_LEN   ((uint16_t)(sizeof(uint32_t) + 5 * sizeof(uint16_t)))

/* probe request TLV (sent by the client to probe a server) */
struct oob_probe_request
{
    uint32_t request_id; /**< chosen by the client, echoed in the reply */
    uint64_t timestamp;  /**< client clock as a UNIX timestamp */
    uint32_t flags;      /**< client capability flags, currently must be 0 */
};

/* probe reply TLV (sent by the server to answer a probe request) */
struct oob_probe_reply
{
    uint32_t request_id;       /**< echoes the request_id of the request */
    uint16_t priority;         /**< DNS-SRV style priority (lower is preferred) */
    uint16_t weight;           /**< DNS-SRV style weight */
    uint16_t max_latency_diff; /**< advertised candidate-band margin in ms;
                                *   used unless the client configured its own */
    uint16_t connect_lifetime; /**< seconds the reply stays valid as the handshake reset */
    uint16_t flags;            /**< server behaviour flags */
};

/**
 * Write a complete probe request TLV (header + value) to buf. It is the whole
 * payload of the OOB message probing a server.
 */
bool oob_probe_request_write(struct buffer *buf, const struct oob_probe_request *r);

/**
 * Read a probe request TLV value from buf.
 *
 * buf must cover exactly the TLV's value, as returned by ctrl_msg_find_tlv().
 * Trailing bytes beyond the fields understood here are ignored, so a longer
 * value from a future version still parses.
 *
 * @return true on success, false if buf is shorter than the mandatory fields.
 */
bool oob_probe_request_read(struct buffer *buf, struct oob_probe_request *r);

/**
 * Write a complete probe reply TLV (header + value) to buf. It is the whole
 * payload of the OOB message answering a probe request.
 */
bool oob_probe_reply_write(struct buffer *buf, const struct oob_probe_reply *r);

/**
 * Read a probe reply TLV value from buf. See oob_probe_request_read() for the
 * calling convention.
 */
bool oob_probe_reply_read(struct buffer *buf, struct oob_probe_reply *r);

/**
 * Scan the payload of a received OOB message for the probe request TLV.
 * Unknown TLV types marked optional are skipped; an unknown mandatory one
 * rejects the message. payload is consumed as it is read.
 *
 * @param payload  buffer positioned at the start of the OOB message payload
 * @param req      filled with the parsed probe request on success
 * @return true if a well-formed probe request was found, false otherwise
 */
bool oob_probe_request_find(struct buffer *payload, struct oob_probe_request *req);

/**
 * Check whether a probe timestamp is within an acceptable window around the
 * current time. Used to cheaply drop replayed or implausibly-timed probes
 * before doing any further work (see the probe request timestamp rationale
 * in the wire protocol specification).
 *
 * @param probe_ts     timestamp from the probe request (UNIX seconds)
 * @param now          current time (UNIX seconds)
 * @param window_secs  maximum allowed difference, in either direction
 * @return true if |now - probe_ts| <= window_secs
 */
bool oob_timestamp_in_window(uint64_t probe_ts, uint64_t now, uint64_t window_secs);

enum oob_probe_verdict
{
    OOB_PROBE_INVALID, /**< no valid probe request: drop */
    OOB_PROBE_STALE,   /**< well-formed, timestamp outside the window */
    OOB_PROBE_OK,      /**< well-formed, timestamp within the window */
};

/**
 * Classify a received probe request. Combines oob_probe_request_find() and
 * oob_timestamp_in_window(). This is the transport-agnostic decision step;
 * the caller decides what to do with a stale probe and builds the reply.
 *
 * @param probe_payload  payload of the received OOB message, consumed
 * @param now            current time (UNIX seconds)
 * @param window_secs    acceptable timestamp skew, in either direction
 * @param req            filled with the probe request unless the verdict is
 *                       OOB_PROBE_INVALID, for the reply to echo its request_id
 */
enum oob_probe_verdict oob_probe_request_check(struct buffer *probe_payload, uint64_t now,
                                               uint64_t window_secs, struct oob_probe_request *req);

#endif /* OOB_H */
