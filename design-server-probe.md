Out-of-band server probing (`--server-probe`)
=============================================

How `--server-probe` works, where the code lives, what it costs, and the
questions that came up building it.


The problem
-----------

A client with several `--remote` entries tries them in configured order. It has
no idea which one is closest or least loaded until it has completed a handshake
with it. Picking a badly placed one costs a full connection attempt. Between
equally reachable servers, the order in the config file decides, or
`--remote-random` shuffles it.

We want the client to learn, before it connects, which servers are up, how far
away they are, and which ones the admin wants it to use.


How it works
------------

The first part is probing. Before the first connection attempt the client sends
one small UDP message to every resolved address of every UDP remote and waits
up to one second. A server that answers reports the priority and weight its
admin configured, and the client measures how long the reply took. The client
reorders its remote list from that and connects as usual.

The second part is the handshake shortcut. The reply carries the same stateless
cookie a server would put in its reset packet, so a client that got one can
start the handshake from the reply instead of sending its own reset. That saves
a round trip. It is optional, and falls back to a normal handshake.

Probing is useful on its own; the shortcut only works on top of it.


Packet flow
-----------

Today, connecting to one server:

    client                                server
      |                                     |
      |-- P_CONTROL_HARD_RESET_CLIENT_V2 -->|
      |                                     |
      |<-- P_CONTROL_HARD_RESET_SERVER_V2 --|   carries a SYN-cookie
      |                                     |
      |-- P_CONTROL_V1 (ClientHello) ------>|
      |                                     |

With probing, two remotes, ordering only. Both answer, both advertise priority
10 and the default 10 ms margin, so B is out of the candidate band and A is
tried first:

    client                    server A                  server B
      |                         |                         |
      |----- SERVER_PROBE ----->|                         |
      |------------------ SERVER_PROBE ------------------>|
      |                         |                         |
      |<----- PROBE_REPLY ------|                         |   20 ms
      |<------------------ PROBE_REPLY -------------------|   80 ms
      |                         |                         |
      |- HARD_RESET_CLIENT_V2 ->|                         |
      |< HARD_RESET_SERVER_V2 --|                         |
      |------ ClientHello ----->|                         |

An address that stays quiet is probed once more after 500 ms; that round is not
drawn here.

With the shortcut, the reply stands in for the server reset:

    client                                server A
      |                                     |
      |-- SERVER_PROBE -------------------->|
      |                                     |
      |<-- PROBE_REPLY ---------------------|   cookie + connect_lifetime
      |                                     |
      |-- P_CONTROL_V1 (ClientHello) ------>|   ACKs id 0, echoes the cookie
      |                                     |

The probe and its reply take the place of the two reset packets, so compared
with probing and then connecting normally the shortcut saves one round trip.
Compared with not probing at all it pays back part of what probing cost. It
does not shorten the TLS handshake itself.


Wire format
-----------

This follows the OOB section of the OpenVPN wire protocol document
([openvpn-rfc PR #30](https://github.com/OpenVPN/openvpn-rfc/pull/30), merged
2026-09-01).

Two new opcodes:

    P_CONTROL_OOB_V1      12    probe and reply
    P_CONTROL_OOB_WKC_V1  13    probe with a wrapped client key (tls-crypt-v2)

Neither opcode is legal on an established session; both are answered
statelessly, before one exists. An OOB payload is chosen by the sender, so on
the session path it would be parsed as an ACK array, and accepting one would let
an attacker forge ACKs into a live control channel.

A packet is the usual control-channel frame — opcode byte, sender session id,
then the payload, with whatever `--tls-auth` or `--tls-crypt` wrapping the
config uses. The OOB payload carries no ACK array and no control packet id. The
tls-auth or tls-crypt wrapper still has its own replay packet id, but this path
does not check it.

The whole packet, with the control-channel wrapping shown:

    +---------------------------------------------------------------+
    | opcode (5 bits) + key id (3 bits)                       1 byte |
    +---------------------------------------------------------------+
    | sender session id                                      8 bytes |
    +---------------------------------------------------------------+
    | tls-auth:   HMAC, 16-64 bytes, then replay packet id, 8 bytes  |
    | tls-crypt:  replay packet id, 8 bytes, then auth tag, 32 bytes |
    |             -- everything below is encrypted                   |
    | neither:    nothing here                                       |
    +---------------------------------------------------------------+
    | OOB payload: message type, then TLVs (below)                   |
    +---------------------------------------------------------------+
    | wrapped client key, on P_CONTROL_OOB_WKC_V1 only               |
    +---------------------------------------------------------------+

The payload is a message type followed by one or more TLVs:

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-------------------------------+-+-----------------------------+
    |         message type          |O|          TLV type           |
    +-------------------------------+-+-----------------------------+
    |          TLV length           |                               |
    +-------------------------------+                               |
    |                          TLV value                            |
    +---------------------------------------------------------------+
    |                     further TLVs, if any                      |
    +---------------------------------------------------------------+

The O bit marks a TLV optional. An unknown optional TLV is skipped, while an
unknown mandatory one makes the whole message invalid, so an old peer refuses a
message it cannot fully read and new fields can be added later as optional ones.

Message types and TLV types are separate spaces — messages are 0x1xx, TLVs are
0x2xx:

    message SERVER_PROBE   0x100   carries TLV PROBE_PARAMETER  0x200
    message PROBE_REPLY    0x101   carries TLV PROBE_REPLY      0x201

PROBE_REPLY names both a message and a TLV; they are different numbers in
different spaces.

TLV PROBE_PARAMETER, value at least 12 bytes, after a 4-byte TLV header:

    timestamp   u64   client clock, seconds
    flags       u32   none defined yet

TLV PROBE_REPLY, value at least 20 bytes, after a 4-byte TLV header:

    peer_session_id    8 bytes   echo of the probe session id
    priority           u16       lower is preferred
    weight             u16       share within one priority
    max_latency_diff   u16       ms; how much slower than the fastest server of
                                 its priority group this server may be and still
                                 count as a candidate. Called the margin below.
    connect_lifetime   u16       seconds this reply may start a handshake;
                                 0 means it may not
    flags              u32       bit 0: complete the handshake with
                                 P_CONTROL_WKC_V1

A value longer than that is accepted and the excess ignored, which is how a
field can be added later.

The spec gives this struct as `uint16 length = 20` but its prose says the
minimum size is 18. The listed fields sum to 20, which is what this implements.
Reported on openvpn-rfc PR #30.

Unwrapped, a probe is 27 bytes on the wire and a reply is 35.


Server side
-----------

A UDP server answers probes, and keeps nothing per probe.

The session id of the reply is the same SYN-cookie the server puts in a reset
packet: a keyed hash (SipHash) over the client session id, the client address
and port, and a coarse timestamp, under a key only the server holds. The server
can therefore check a later packet against a reply it sent without having
stored anything.

`--server-probe-reply` sets the advertised values:

    server-probe-reply off
    server-probe-reply max-latency-diff [weight [priority]]

Defaults are weight 50, priority 100 and a 10 ms margin. With `off` an incoming
probe is dropped by opcode, before any unwrapping work is done.

A probe is answered only if its timestamp is within `--hand-window` of the
server clock. Probes count against `--connect-freq-initial`, the same budget as
reset packets.

`connect_lifetime` is not configurable; it follows from `--hand-window` as
`2 * ((hand-window + 1) / 2)`, so 60 seconds at the default. That is the window
in which the cookie is guaranteed to still validate.


tls-crypt-v2
------------

A tls-crypt-v2 server has no per-client key until the client gives it one, and
this server keeps no state between the probe and the handshake. So the client
appends its wrapped client key to the probe itself, which makes it
`P_CONTROL_OOB_WKC_V1` instead of `P_CONTROL_OOB_V1`. The server unwraps it,
recovers the client key, and wraps the reply with that key as a plain
`P_CONTROL_OOB_V1`.

The reply sets bit 0 of its flags to say "if you start a handshake from this,
send the wrapped key again", and the client then sends `P_CONTROL_WKC_V1`
rather than `P_CONTROL_V1`.

A tls-crypt-v2 client that gets a reply without that bit does not take the
shortcut, because the server would not be able to decrypt its first packet.


Client side
-----------

`--server-probe [max-latency-diff]` turns it on. The client needs at least two
remotes; with one there is nothing to order.

Probing runs synchronously in `init_instance()`, before the first remote is
picked, and only once per process — a reconnect does not probe again. It
resolves every remote itself and then blocks in `select()` until every probe is
answered or the window elapses. A signal breaks out of it. The connection path
later resolves the chosen remote again.

The client opens one UDP socket per address family, bound the way the
connection socket would be: `--local`, `--lport`, `--bind-dev`, `--mark`. One
socket set serves every probe, so every probed remote must bind the same way
and use the same control-channel key as the first one. If any of them differs,
nothing is probed and the configured order stands.

It sends one probe per resolved address, waits 500 ms, resends to whoever has
not answered, and waits another 500 ms. An address that answers in the first
half-window is probed once; one that stays quiet is probed twice. An address
that two remotes resolve to is probed once, and the single reply is credited to
both of them with the same round-trip time.

Ordering follows DNS SRV (RFC 2782), and operates on remotes rather than on the
addresses replies arrive from:

  - remotes that answered come before those that did not;
  - within that, lower priority value first;
  - within one priority, remotes whose round-trip time is within the margin of
    the fastest are picked by weighted random, and the rest follow in
    round-trip-time order;
  - remotes that did not answer keep their configured order, after all the ones
    that did.

Each server advertises its own margin, so one server's choice does not
constrain the others. A client that passes `--server-probe <ms>` overrides all
of them.

Round-trip time is measured from the first send to the moment the client reads
the reply, so it includes time the reply spent in the receive queue. It is good
enough to compare servers with, but it is not a network measurement.

If the top-ranked remote advertised a non-zero `connect_lifetime`, the client
keeps the probe socket of that remote's address family and hands it to the
connection instead of opening a new one; the socket of the other family is
closed. The connection therefore keeps the probe's source address and port,
which is what the cookie is bound to.

Starting a handshake from a reply needs one trick. The client pretends it
received a server reset with message id 0 and acknowledges that phantom id, so
its first packet carries an ACK — and `reliable_ack_write()` only emits the
server session id when an ACK is present. That session id is the cookie, which
the server re-derives and checks. Packet ids on both sides then start at 1, as
they would after a real reset exchange.

Such a handshake gets a short deadline, `min(--hand-window, 5s)`, instead of the
full window. The server answered a moment ago, so silence means it did not
accept our packet as a continuation of that reply, not that the server is down.
That happens when a load balancer sent the probe and the handshake to different
instances, when NAT moved our source port, or when the server rotated its
session-id key. On timeout the client restarts the attempt and moves on to the
next address or remote.

The shortcut is also given up before it is used if the advertised lifetime
elapsed during a slow start-up, such as a private key passphrase or token
prompt, or if the remote finally selected is not the one that won the probe.


Where the code lives
--------------------

    control_msg.c/.h   TLV framing, shared with other TLV control messages
    oob.c/.h           OOB message and TLV types, encode and decode, ranking
    ssl_pkt.c/.h       opcodes 12 and 13, tls_wrap_oob_standalone(), verdicts
    mudp.c             server: answer a probe without creating a session
    oob_client.c       client: probe, collect replies, reorder the remotes
    ssl.c              session_skip_to_pre_start_client(), the short deadline
    socket.c, init.c   adopting the probe socket as the connection socket

The 18 commits are in that order, and each one builds and passes tests on its
own, so the series can be reviewed or bisected incrementally. They are on
Gerrit under topic
[oob-server-probe](https://gerrit.openvpn.net/q/topic:oob-server-probe):

|  # | Change | Subject |
|----|--------|---------|
|  1 | [1741](https://gerrit.openvpn.net/c/openvpn/+/1741) | control message TLV encoding |
|  2 | [1742](https://gerrit.openvpn.net/c/openvpn/+/1742) | SERVER_PROBE parsing, probe-reply decision |
|  3 | [1744](https://gerrit.openvpn.net/c/openvpn/+/1744) | answer SERVER_PROBE on the server |
|  4 | [1745](https://gerrit.openvpn.net/c/openvpn/+/1745) | client PROBE_REPLY parser |
|  5 | [1746](https://gerrit.openvpn.net/c/openvpn/+/1746) | probe-result ranking |
|  6 | [1915](https://gerrit.openvpn.net/c/openvpn/+/1915) | let an optional UDP socket give up on a failed bind |
|  7 | [1747](https://gerrit.openvpn.net/c/openvpn/+/1747) | `--server-probe`, the probe loop |
|  8 | [1748](https://gerrit.openvpn.net/c/openvpn/+/1748) | RTT measurement |
|  9 | [1749](https://gerrit.openvpn.net/c/openvpn/+/1749) | extract `init_tls_wrap_ctx()` |
| 10 | [1750](https://gerrit.openvpn.net/c/openvpn/+/1750) | wrap the probe with tls-auth/tls-crypt |
| 11 | [1751](https://gerrit.openvpn.net/c/openvpn/+/1751) | probe every resolved address |
| 12 | [1752](https://gerrit.openvpn.net/c/openvpn/+/1752) | `--server-probe-reply` |
| 13 | [1758](https://gerrit.openvpn.net/c/openvpn/+/1758) | unwrap tls-crypt-v2 probes |
| 14 | [1759](https://gerrit.openvpn.net/c/openvpn/+/1759) | send tls-crypt-v2 probes |
| 15 | [1768](https://gerrit.openvpn.net/c/openvpn/+/1768) | advertise `connect_lifetime` |
| 16 | [1769](https://gerrit.openvpn.net/c/openvpn/+/1769) | adopt the probe socket |
| 17 | [1770](https://gerrit.openvpn.net/c/openvpn/+/1770) | start the handshake from the reply |
| 18 | [1771](https://gerrit.openvpn.net/c/openvpn/+/1771) | fall back quickly when it is ignored |

Changes 1741 to 1752 alter no behaviour for a client that does not set
`--server-probe`. The behaviour change worth the hardest look is 1769 to 1771,
which touch shared socket setup and the TLS session state machine.

`tests/unit_tests/openvpn/test_oob.c` covers the TLV framing, the parsers and
the ranking rules, and `test_pkt.c` covers the wrapped round trip in all three
wrap modes. The socket handover, the probe loop and the shortcut itself were
tested by hand.


Limits
------

Probing delays the first connection attempt by up to one second, plus the time
to resolve the remotes.

It needs at least two remotes, so the most common client config, a single
`--remote`, gets nothing from it.

Probing TCP remotes is not implemented yet, so in a mixed list they end up
after every UDP remote that answered. For someone using a `udp, udp, tcp`
fallback list that is a visible change.

Probing replaces any order `--remote-random` produced.

If no server answers at all, the configured order stands. A server whose clock
is more than `--hand-window` away from the client will not answer, and a client
whose clock is wrong gets no replies at all.

The shortcut is not used on Windows while DCO is active, because the socket
cannot be handed to the kernel driver.

On Windows builds without a native `gettimeofday()` the clock has about 15.6 ms
resolution, which is coarser than the 10 ms default margin, so the candidate
band is decided by tick alignment rather than by latency.

Each probe costs the server one `--connect-freq-initial` token. A completed
handshake returns its token; a probe never does. A probing client therefore
spends more of that budget than one that does not probe, and it spends it on
every server it probes, not only on the one it connects to.

The Android path hands the probe socket to `VpnService.protect()` the way the
connection socket is handled. It has been reviewed but not run on a device.


Security notes
--------------

Probes and replies carry the same `--tls-auth` or `--tls-crypt` wrapping as any
other control packet. With neither configured they are unauthenticated, exactly
as reset packets are today.

The timestamp window does not stop replay; it only bounds how long a captured
probe stays useful, and there is no packet-id check on this path.

A reply is 35 bytes against a 27-byte probe, about 1.3x. With tls-crypt-v2 the
probe is much larger than the reply. Replies go only to the source address, and
the rate limiter applies.

The client accepts a reply only if it echoes the client session id and comes
from an address the client probed.


Open questions
--------------

Points I would like decided.

1. Should a server answer probes by default, or only when
   `--server-probe-reply` is given? It answers by default now, with an `off`
   switch.

2. Should a probe with a stale timestamp be dropped or answered? Dropping
   denies service to clients with a wrong clock and saves nothing, because the
   rate-limiter token is already spent by then. If it is answered, should the
   reply still advertise a `connect_lifetime`?

3. Should probes have their own rate-limit budget instead of sharing
   `--connect-freq-initial` with reset packets?

4. Should a single-remote client probe anyway, to get the cookie and the round
   trip, even though there is nothing to reorder?

5. Should the per-server `max_latency_diff` be capped? A server can advertise
   65535 and always be a candidate.

6. Do the messages need TLVs at all? This is a spec question rather than an
   implementation one, but three things point the same way:

   - every message carries exactly one mandatory TLV today, so the layer costs
     four bytes per message and a scanner, and buys nothing yet;
   - appending a field to a value already works without it, since a value
     longer than expected is accepted and the excess ignored;
   - the scanner does not deliver what TLVs imply. It rejects any mandatory TLV
     that is not the one being looked for, including one it understands, so a
     message with two mandatory TLVs cannot be read at all. If a later message
     needs two, the scanner has to be rewritten anyway.
