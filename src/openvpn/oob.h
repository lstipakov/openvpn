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
                                        *   0 means "defer to the client's setting" */
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
 * for the probe_parameter TLV. TLV types other than probe_parameter are
 * skipped. payload is consumed as it is read.
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
 * Read a received OOB PROBE_REPLY: verify its message-type header, then scan
 * for the probe_reply TLV; the client-side counterpart of
 * oob_server_probe_read(). TLV types other than probe_reply are skipped.
 * payload is consumed as it is read.
 *
 * @param payload  buffer positioned at the start of the OOB message payload
 * @param reply    filled with the parsed probe_reply on success
 * @return true if the header matched and a well-formed probe_reply was found,
 *         false otherwise
 */
bool oob_client_reply_read(struct buffer *payload, struct oob_probe_reply *reply);

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

/* probe_reply flags (the reply TLV's 32-bit flags field) */
/* bit 0: the client must resend the wrapped client key (via P_CONTROL_WKC_V1)
 * when it completes the handshake started from this reply. Set
 * by a tls-crypt-v2 server, which is stateless and discarded the WKc. */
#define OOB_PROBE_REPLY_FLAG_RESEND_WKC 0x1

/**
 * Process the TLV payload of a received SERVER_PROBE and decide whether to
 * answer it. Combines oob_server_probe_read() and oob_timestamp_in_window():
 * the probe is dropped (false returned) if it has no valid probe_parameter or
 * its timestamp is outside the acceptable window.
 *
 * reply carries the values the server advertises (priority, weight,
 * max_latency_diff, connect_lifetime, flags) in, and is deliberately not
 * cleared: on success only the peer's session id is filled in, leaving the
 * reply ready to be wrapped and sent.
 *
 * This is the transport-agnostic decision step; the caller performs the send.
 *
 * @param probe_payload  TLV payload of the received OOB SERVER_PROBE
 * @param now            current time (UNIX seconds)
 * @param window_secs    acceptable timestamp skew, in either direction
 * @param peer_sid       session id of the requesting peer (echoed in the reply)
 * @param reply          in: the values to advertise; out: the reply to send
 * @return true if a reply should be sent, false to silently drop the probe
 */
bool oob_build_probe_reply(struct buffer *probe_payload, uint64_t now, uint64_t window_secs,
                           const struct session_id *peer_sid, struct oob_probe_reply *reply);

/* Candidate-band margin (ms) used when neither the client nor the server
 * specifies one. */
#define OOB_DEFAULT_LATENCY_MARGIN_MS 10

/* Outcome of probing one remote, used to order remotes best-first. @index is
 * the caller's identifier for the remote (e.g. its position in the connection
 * list); priority/weight are only meaningful when @responded is true. */
struct oob_probe_result
{
    int index;
    bool responded;
    unsigned int rtt_ms; /* probe round-trip time in ms (responders only) */
    /* Captured from the packet and its reply TLV (responders only): */
    struct session_id server_sid;      /* the packet's own session id = server SYN-cookie */
    struct sockaddr_storage responder; /* address that answered (pin the connection to it) */
    struct oob_probe_reply reply;      /* the values the server advertised */
};

/**
 * Order results best-first, in place, per the server-probe selection policy:
 *   - remotes that responded rank before those that did not (non-responders keep
 *     their original relative order, last);
 *   - responders are grouped by priority, lowest priority value first (an
 *     absolute ordering, never overridden by latency or weight);
 *   - within a priority group, the "candidates" are the responders whose RTT is
 *     within a margin of the fastest in the group (see oob_effective_margin()).
 *     Candidates are ordered ahead of non-candidates;
 *   - candidates are ordered by DNS-SRV (RFC 2782) weighted-random selection by
 *     weight, so a server is chosen first with probability proportional to its
 *     weight (load distribution). Non-candidates follow, ordered by RTT.
 *
 * @param results        results to reorder in place
 * @param n              number of results
 * @param client_margin  client's candidate-band margin in ms, or < 0 if the
 *                        client did not set one (see oob_effective_margin())
 * @param rng            returns a non-negative random value (e.g. get_random);
 *                       injected so this module stays free of the crypto layer
 *                       and the weighted ordering is deterministically testable
 * @param gc             arena for scratch allocation
 */
void oob_rank_probe_results(struct oob_probe_result *results, int n, int client_margin,
                            int64_t (*rng)(void), struct gc_arena *gc);

/**
 * The candidate-band margin (ms) that applies to one probed remote. The client's
 * own setting is authoritative: when client_margin >= 0 (the client set
 * --server-probe with a value) it is used for every remote. Otherwise the
 * server's advertised max_latency_diff is used when non-zero, falling back to
 * OOB_DEFAULT_LATENCY_MARGIN_MS.
 */
int oob_effective_margin(const struct oob_probe_result *r, int client_margin);

#endif /* OOB_H */
