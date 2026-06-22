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
 * Client-side server-probe phase: before connecting, optionally probe all
 * configured remotes with an out-of-band SERVER_PROBE and order them
 * best-first, so the connection loop tries the most suitable server first.
 */

#ifndef OOB_CLIENT_H
#define OOB_CLIENT_H

struct context;

/**
 * Probe all configured remotes and reorder the connection list best-first.
 *
 * Does nothing unless --server-probe is enabled. On any failure (or if no
 * server answers), the configured remote order is left unchanged and the
 * normal connection sequence proceeds.
 */
void client_probe_and_order_remotes(struct context *c);

#endif /* OOB_CLIENT_H */
