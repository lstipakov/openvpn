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
 * SERVER_PROBE, PROBE_REPLY, ...) followed by a sequence of TLV entries in the
 * 0x2xx type space. The framing itself is shared with the other TLV-based
 * control messages of the wire protocol and lives in control_msg.h; this file
 * defines the OOB message and TLV types, their values, and the OOB-specific
 * decisions taken on them.
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

/* TLV types (see the OOB control message section of the wire protocol spec) */
#define OOB_TLV_PROBE_PARAMETER 0x200
#define OOB_TLV_PROBE_REPLY     0x201

/* Minimum on-wire value length (excluding the 4-byte TLV header) of each TLV:
 * the sizes of its fixed fields in wire order (see the structs below). The
 * value may be longer for forward compatibility; trailing bytes that are not
 * understood are ignored on read. */
#define OOB_PROBE_PARAMETER_LEN \
    ((uint16_t)(sizeof(uint64_t) /* timestamp */ + sizeof(uint32_t) /* flags */))
#define OOB_PROBE_REPLY_LEN                                   \
    ((uint16_t)(SID_SIZE               /* peer_session_id */  \
                + 4 * sizeof(uint16_t) /* priority, weight,   \
                                        * max_latency_diff,   \
                                        * connect_lifetime */ \
                + sizeof(uint32_t)))   /* flags */

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
    uint16_t max_latency_diff;         /**< advertised candidate-band margin in ms;
                                        *   used unless the client configured its own */
    uint16_t connect_lifetime;         /**< seconds the reply stays valid as the handshake reset */
    uint32_t flags;                    /**< server behaviour flags */
};

/**
 * Write a complete probe parameter TLV (header + value) to buf.
 */
bool oob_probe_parameter_write(struct buffer *buf, const struct oob_probe_parameter *p);

/**
 * Read a probe parameter TLV value from buf.
 *
 * buf must cover exactly the TLV's value, as returned by ctrl_msg_find_tlv().
 * Trailing bytes beyond the fields understood here are ignored, so a longer
 * value from a future version still parses.
 *
 * @return true on success, false if buf is shorter than the mandatory fields.
 */
bool oob_probe_parameter_read(struct buffer *buf, struct oob_probe_parameter *p);

/**
 * Write a complete probe reply TLV (header + value) to buf.
 */
bool oob_probe_reply_write(struct buffer *buf, const struct oob_probe_reply *r);

/**
 * Read a probe reply TLV value from buf. See oob_probe_parameter_read() for the
 * calling convention.
 */
bool oob_probe_reply_read(struct buffer *buf, struct oob_probe_reply *r);

/**
 * Write a complete SERVER_PROBE message (message-type header + probe_parameter
 * TLV) to buf. Sent by the client.
 */
bool oob_server_probe_write(struct buffer *buf, const struct oob_probe_parameter *param);

/**
 * Read a received OOB SERVER_PROBE: verify its message-type header, then scan
 * for the probe_parameter TLV. Unknown TLV types marked optional are skipped;
 * an unknown mandatory one rejects the probe. payload is consumed as it is
 * read.
 *
 * @param payload  buffer positioned at the start of the OOB message payload
 * @param param    filled with the parsed probe_parameter on success
 * @return true if the header matched and a well-formed probe_parameter was
 *         found, false otherwise
 */
bool oob_server_probe_read(struct buffer *payload, struct oob_probe_parameter *param);

/**
 * Write a complete PROBE_REPLY message (message-type header + probe_reply TLV)
 * to buf. Sent by the server.
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
 * Decide whether a received SERVER_PROBE is answered. Combines
 * oob_server_probe_read() and oob_timestamp_in_window(): the probe is dropped
 * if its payload has no valid probe_parameter or the timestamp is outside the
 * acceptable window. This is the transport-agnostic decision step; the caller
 * builds and sends the reply.
 *
 * @param probe_payload  TLV payload of the received OOB SERVER_PROBE, consumed
 * @param now            current time (UNIX seconds)
 * @param window_secs    acceptable timestamp skew, in either direction
 * @return true if a reply should be sent, false to silently drop the probe
 */
bool oob_server_probe_accept(struct buffer *probe_payload, uint64_t now, uint64_t window_secs);

#endif /* OOB_H */
