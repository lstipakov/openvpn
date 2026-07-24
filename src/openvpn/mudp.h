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

/*
 * UDP specific code for --mode server
 */

#ifndef MUDP_H
#define MUDP_H

struct context;
struct multi_context;
struct tls_pre_decrypt_state;

void multi_process_io_udp(struct multi_context *m, struct link_socket *sock, unsigned int rwflags);

/**
 * Answer a SERVER_PROBE whose wrapping has already been validated by
 * tls_pre_decrypt_lite() (an OOB verdict), without creating any session state.
 * Shared by the UDP pre-decrypt path and the TCP first-packet interception.
 *
 * The caller is responsible for rate limiting: the UDP path checks
 * reflect_filter_rate_limit_check() with the reset verdicts, the TCP path
 * before it intercepts.
 *
 * @param m                 the server's multi_context
 * @param c                 the context that read the probe (m->top for UDP,
 *                          the instance context for TCP): supplies the peer
 *                          address (c2.from) and the reply buffer
 * @param state             pre-decrypt state of the probe packet
 * @param sock              the socket to send the reply on
 * @param verdict           the OOB verdict; VERDICT_VALID_OOB_WKC_V1 makes the
 *                          reply ask the client to resend its WKc
 * @param connect_lifetime  seconds the reply stays valid as a handshake
 *                          shortcut; 0 advertises "no shortcut offered"
 *
 * @return true if a reply was sent, false if the probe was dropped
 *         (malformed or stale)
 */
bool multi_answer_server_probe(struct multi_context *m, struct context *c,
                               struct tls_pre_decrypt_state *state, struct link_socket *sock,
                               enum first_packet_verdict verdict, uint16_t connect_lifetime);
/**************************************************************************/
/**
 * Get, and if necessary create, the multi_instance associated with a
 * packet's source address.
 * @ingroup external_multiplexer
 *
 * This function extracts the source address of a recently read packet
 * from \c m->top.c2.from and uses that source address as a hash key for
 * the hash table \c m->hash.  If an entry exists, this function returns
 * it.  If no entry exists, this function handles its creation, and if
 * successful, returns the newly created instance.
 *
 * @param m            The single multi_context structure.
 * @param[out] floated Returns whether the client has floated.
 * @param sock         Listening socket where this instance is connecting to
 *
 * @return A pointer to a multi_instance if one already existed for the
 *     packet's source address or if one was a newly created successfully.
 *     NULL if one did not yet exist and a new one was not created.
 */
struct multi_instance *multi_get_create_instance_udp(struct multi_context *m, bool *floated,
                                                     struct link_socket *sock);

#endif /* ifndef MUDP_H */
