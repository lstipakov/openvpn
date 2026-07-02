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

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "oob.h"
#include "test_common.h"

/* Write a probe parameter TLV and read it back; fields must survive the
 * round trip and the whole buffer must be consumed. */
static void
test_probe_parameter_roundtrip(void **state)
{
    struct gc_arena gc = gc_new();
    struct buffer buf = alloc_buf_gc(128, &gc);

    const struct oob_probe_parameter in = {
        .timestamp = 0x0123456789abcdefULL,
        .flags = 0,
    };
    assert_true(oob_probe_parameter_write(&buf, &in));
    /* header (4) + value (12) */
    assert_int_equal(BLEN(&buf), 4 + OOB_PROBE_PARAMETER_LEN);

    uint16_t type;
    bool optional;
    uint16_t value_len;
    assert_true(oob_tlv_read_header(&buf, &type, &optional, &value_len));
    assert_int_equal(type, OOB_TLV_PROBE_PARAMETER);
    assert_false(optional);
    assert_int_equal(value_len, OOB_PROBE_PARAMETER_LEN);

    struct oob_probe_parameter out = { 0 };
    assert_true(oob_probe_parameter_read(&buf, &out, value_len));
    assert_true(in.timestamp == out.timestamp);
    assert_int_equal(in.flags, out.flags);
    assert_int_equal(BLEN(&buf), 0);

    gc_free(&gc);
}

/* Write a probe reply TLV and read it back. */
static void
test_probe_reply_roundtrip(void **state)
{
    struct gc_arena gc = gc_new();
    struct buffer buf = alloc_buf_gc(128, &gc);

    struct oob_probe_reply in = {
        .priority = 10,
        .weight = 100,
        .connect_lifetime = 30,
        .flags = 1,
        .max_latency_diff = 25,
    };
    memcpy(in.peer_session_id.id, "ABCDEFGH", SID_SIZE);

    assert_true(oob_probe_reply_write(&buf, &in));
    assert_int_equal(BLEN(&buf), 4 + OOB_PROBE_REPLY_LEN);

    uint16_t type;
    bool optional;
    uint16_t value_len;
    assert_true(oob_tlv_read_header(&buf, &type, &optional, &value_len));
    assert_int_equal(type, OOB_TLV_PROBE_REPLY);
    assert_int_equal(value_len, OOB_PROBE_REPLY_LEN);

    struct oob_probe_reply out = { 0 };
    assert_true(oob_probe_reply_read(&buf, &out, value_len));
    assert_memory_equal(in.peer_session_id.id, out.peer_session_id.id, SID_SIZE);
    assert_int_equal(in.priority, out.priority);
    assert_int_equal(in.weight, out.weight);
    assert_int_equal(in.connect_lifetime, out.connect_lifetime);
    assert_int_equal(in.flags, out.flags);
    assert_int_equal(in.max_latency_diff, out.max_latency_diff);
    assert_int_equal(BLEN(&buf), 0);

    gc_free(&gc);
}

/* A TLV with a longer-than-known value must still parse: the known fields are
 * read and the trailing bytes are skipped (forward compatibility). */
static void
test_probe_parameter_forward_compat(void **state)
{
    struct gc_arena gc = gc_new();
    struct buffer buf = alloc_buf_gc(128, &gc);

    const uint16_t extended_len = OOB_PROBE_PARAMETER_LEN + 4;
    assert_true(oob_tlv_write_header(&buf, OOB_TLV_PROBE_PARAMETER, false, extended_len));
    assert_true(buf_write_u32(&buf, 0));          /* timestamp high */
    assert_true(buf_write_u32(&buf, 0xdeadbeef)); /* timestamp low */
    assert_true(buf_write_u32(&buf, 0));          /* flags */
    assert_true(buf_write_u32(&buf, 0x11223344)); /* unknown trailing field */

    uint16_t type;
    bool optional;
    uint16_t value_len;
    assert_true(oob_tlv_read_header(&buf, &type, &optional, &value_len));
    assert_int_equal(value_len, extended_len);

    struct oob_probe_parameter out = { 0 };
    assert_true(oob_probe_parameter_read(&buf, &out, value_len));
    assert_true(out.timestamp == 0xdeadbeefULL);
    assert_int_equal(out.flags, 0);
    /* the unknown trailing field must have been consumed */
    assert_int_equal(BLEN(&buf), 0);

    gc_free(&gc);
}

/* A declared value length shorter than the mandatory minimum must be rejected. */
static void
test_probe_parameter_too_short(void **state)
{
    struct gc_arena gc = gc_new();
    struct buffer buf = alloc_buf_gc(128, &gc);

    struct oob_probe_parameter out = { 0 };
    assert_false(oob_probe_parameter_read(&buf, &out, OOB_PROBE_PARAMETER_LEN - 1));

    gc_free(&gc);
}

/* Reading a header from a buffer that is too small must fail rather than read
 * past the end. */
static void
test_tlv_header_truncated(void **state)
{
    struct gc_arena gc = gc_new();
    struct buffer buf = alloc_buf_gc(128, &gc);

    uint16_t type;
    bool optional;
    uint16_t value_len;

    /* empty buffer */
    assert_false(oob_tlv_read_header(&buf, &type, &optional, &value_len));

    /* only the type field present, no length */
    assert_true(buf_write_u16(&buf, OOB_TLV_PROBE_PARAMETER));
    assert_false(oob_tlv_read_header(&buf, &type, &optional, &value_len));

    gc_free(&gc);
}

/* A SERVER_PROBE carrying just a probe_parameter is found by the scan. */
static void
test_server_probe_read_finds_parameter(void **state)
{
    struct gc_arena gc = gc_new();
    struct buffer buf = alloc_buf_gc(128, &gc);

    const struct oob_probe_parameter in = {
        .timestamp = 0x1122334455667788ULL,
        .flags = 0,
    };
    assert_true(oob_server_probe_write(&buf, &in));

    struct oob_probe_parameter out = { 0 };
    assert_true(oob_server_probe_read(&buf, &out));
    assert_true(in.timestamp == out.timestamp);
    assert_int_equal(in.flags, out.flags);

    gc_free(&gc);
}

/* TLVs other than probe_parameter are skipped, so the scan finds the
 * probe_parameter even when preceded by an unknown TLV. */
static void
test_server_probe_read_skips_unknown(void **state)
{
    struct gc_arena gc = gc_new();
    struct buffer buf = alloc_buf_gc(128, &gc);

    /* SERVER_PROBE message header, then an unknown TLV (type 0x7ff) ... */
    assert_true(oob_msg_write_header(&buf, OOB_MSG_SERVER_PROBE));
    assert_true(oob_tlv_write_header(&buf, 0x7ff, false, 4));
    assert_true(buf_write_u32(&buf, 0xcafef00d));
    /* ... followed by the real probe_parameter */
    const struct oob_probe_parameter in = { .timestamp = 42, .flags = 0 };
    assert_true(oob_probe_parameter_write(&buf, &in));

    struct oob_probe_parameter out = { 0 };
    assert_true(oob_server_probe_read(&buf, &out));
    assert_true(out.timestamp == 42);

    gc_free(&gc);
}

/* A payload with no probe_parameter must be rejected. */
static void
test_server_probe_read_missing(void **state)
{
    struct gc_arena gc = gc_new();
    struct buffer buf = alloc_buf_gc(128, &gc);

    assert_true(oob_msg_write_header(&buf, OOB_MSG_SERVER_PROBE));
    assert_true(oob_tlv_write_header(&buf, 0x7ff, false, 4));
    assert_true(buf_write_u32(&buf, 0));

    struct oob_probe_parameter out = { 0 };
    assert_false(oob_server_probe_read(&buf, &out));

    gc_free(&gc);
}

/* A TLV whose declared length runs past the buffer must be rejected, not
 * read out of bounds. */
static void
test_server_probe_read_truncated(void **state)
{
    struct gc_arena gc = gc_new();
    struct buffer buf = alloc_buf_gc(128, &gc);

    /* TLV header claims a 16-byte value but no value bytes follow */
    assert_true(oob_msg_write_header(&buf, OOB_MSG_SERVER_PROBE));
    assert_true(oob_tlv_write_header(&buf, 0x7ff, false, 16));

    struct oob_probe_parameter out = { 0 };
    assert_false(oob_server_probe_read(&buf, &out));

    gc_free(&gc);
}

/* A SERVER_PROBE reader rejects a payload carrying a different message type
 * (here a PROBE_REPLY's), even if it contains a valid probe_parameter TLV. */
static void
test_server_probe_read_wrong_msg_type(void **state)
{
    struct gc_arena gc = gc_new();
    struct buffer buf = alloc_buf_gc(128, &gc);

    assert_true(oob_msg_write_header(&buf, OOB_MSG_PROBE_REPLY));
    const struct oob_probe_parameter in = { .timestamp = 42, .flags = 0 };
    assert_true(oob_probe_parameter_write(&buf, &in));

    struct oob_probe_parameter out = { 0 };
    assert_false(oob_server_probe_read(&buf, &out));

    gc_free(&gc);
}

/* Timestamp window check accepts values within the window (either direction)
 * and rejects values outside it. */
static void
test_timestamp_in_window(void **state)
{
    const uint64_t now = 1000000;
    const uint64_t window = 30;

    assert_true(oob_timestamp_in_window(now, now, window));
    assert_true(oob_timestamp_in_window(now - window, now, window));      /* boundary, past */
    assert_true(oob_timestamp_in_window(now + window, now, window));      /* boundary, future */
    assert_false(oob_timestamp_in_window(now - window - 1, now, window)); /* too old */
    assert_false(oob_timestamp_in_window(now + window + 1, now, window)); /* too far ahead */
}

/* A valid, in-window SERVER_PROBE yields a reply that echoes the peer's
 * session id and carries the configured priority and weight. */
static void
test_build_probe_reply_valid(void **state)
{
    struct gc_arena gc = gc_new();
    struct buffer buf = alloc_buf_gc(128, &gc);

    const uint64_t now = 1000000;
    const struct oob_probe_parameter probe = { .timestamp = now, .flags = 0 };
    assert_true(oob_server_probe_write(&buf, &probe));

    struct session_id peer;
    memcpy(peer.id, "PEER1234", SID_SIZE);

    struct oob_probe_reply reply;
    assert_true(oob_build_probe_reply(&buf, now, 30, &peer, 5, 50, 25, &reply));
    assert_memory_equal(reply.peer_session_id.id, peer.id, SID_SIZE);
    assert_int_equal(reply.priority, 5);
    assert_int_equal(reply.weight, 50);
    assert_int_equal(reply.connect_lifetime, 0);
    assert_int_equal(reply.flags, 0);
    assert_int_equal(reply.max_latency_diff, 25);

    gc_free(&gc);
}

/* A probe whose timestamp is outside the window is dropped (no reply). */
static void
test_build_probe_reply_stale(void **state)
{
    struct gc_arena gc = gc_new();
    struct buffer buf = alloc_buf_gc(128, &gc);

    const uint64_t now = 1000000;
    const struct oob_probe_parameter probe = { .timestamp = now - 1000, .flags = 0 };
    assert_true(oob_server_probe_write(&buf, &probe));

    struct session_id peer = { 0 };
    struct oob_probe_reply reply;
    assert_false(oob_build_probe_reply(&buf, now, 30, &peer, 0, 0, 0, &reply));

    gc_free(&gc);
}

/* A payload without a probe_parameter is dropped (no reply). */
static void
test_build_probe_reply_no_parameter(void **state)
{
    struct gc_arena gc = gc_new();
    struct buffer buf = alloc_buf_gc(128, &gc);

    assert_true(oob_msg_write_header(&buf, OOB_MSG_SERVER_PROBE));
    assert_true(oob_tlv_write_header(&buf, 0x7ff, false, 4));
    assert_true(buf_write_u32(&buf, 0));

    struct session_id peer = { 0 };
    struct oob_probe_reply reply;
    assert_false(oob_build_probe_reply(&buf, 1000000, 30, &peer, 0, 0, 0, &reply));

    gc_free(&gc);
}

/* A PROBE_REPLY carrying a probe_reply is found by the client scan, with all
 * fields surviving. */
static void
test_client_reply_read_finds_reply(void **state)
{
    struct gc_arena gc = gc_new();
    struct buffer buf = alloc_buf_gc(128, &gc);

    struct oob_probe_reply in = {
        .priority = 5,
        .weight = 50,
        .connect_lifetime = 120,
        .flags = 1,
    };
    memcpy(in.peer_session_id.id, "SRVREPLY", SID_SIZE);
    assert_true(oob_client_reply_write(&buf, &in));

    struct oob_probe_reply out = { 0 };
    assert_true(oob_client_reply_read(&buf, &out));
    assert_memory_equal(out.peer_session_id.id, in.peer_session_id.id, SID_SIZE);
    assert_int_equal(out.priority, in.priority);
    assert_int_equal(out.weight, in.weight);
    assert_int_equal(out.connect_lifetime, in.connect_lifetime);
    assert_int_equal(out.flags, in.flags);

    gc_free(&gc);
}

/* TLVs other than probe_reply are skipped. */
static void
test_client_reply_read_skips_unknown(void **state)
{
    struct gc_arena gc = gc_new();
    struct buffer buf = alloc_buf_gc(128, &gc);

    assert_true(oob_msg_write_header(&buf, OOB_MSG_PROBE_REPLY));
    assert_true(oob_tlv_write_header(&buf, 0x7ff, false, 4));
    assert_true(buf_write_u32(&buf, 0xabad1dea));
    struct oob_probe_reply in = { .priority = 7 };
    assert_true(oob_probe_reply_write(&buf, &in));

    struct oob_probe_reply out = { 0 };
    assert_true(oob_client_reply_read(&buf, &out));
    assert_int_equal(out.priority, 7);

    gc_free(&gc);
}

/* A payload with no probe_reply is rejected. */
static void
test_client_reply_read_missing(void **state)
{
    struct gc_arena gc = gc_new();
    struct buffer buf = alloc_buf_gc(128, &gc);

    assert_true(oob_msg_write_header(&buf, OOB_MSG_PROBE_REPLY));
    assert_true(oob_tlv_write_header(&buf, 0x7ff, false, 4));
    assert_true(buf_write_u32(&buf, 0));

    struct oob_probe_reply out = { 0 };
    assert_false(oob_client_reply_read(&buf, &out));

    gc_free(&gc);
}

/* Likewise, a PROBE_REPLY reader rejects a payload with the wrong message
 * type even when a valid probe_reply TLV follows. */
static void
test_client_reply_read_wrong_msg_type(void **state)
{
    struct gc_arena gc = gc_new();
    struct buffer buf = alloc_buf_gc(128, &gc);

    assert_true(oob_msg_write_header(&buf, OOB_MSG_SERVER_PROBE));
    struct oob_probe_reply in = { .priority = 7 };
    assert_true(oob_probe_reply_write(&buf, &in));

    struct oob_probe_reply out = { 0 };
    assert_false(oob_client_reply_read(&buf, &out));

    gc_free(&gc);
}

/* Deterministic RNG stubs for the weighted-selection ordering. rank_rng_zero
 * makes the weighted draw always pick the first remaining candidate, preserving
 * order; rank_rng_fixed returns a value we set to land in a chosen weight slice. */
static int64_t
rank_rng_zero(void)
{
    return 0;
}

static int64_t rank_rng_value;
static int64_t
rank_rng_fixed(void)
{
    return rank_rng_value;
}

/* Responders rank ahead of non-responders regardless of index order. */
static void
test_rank_responder_before_nonresponder(void **state)
{
    struct gc_arena gc = gc_new();
    struct oob_probe_result r[] = {
        { .index = 0, .responded = false },
        { .index = 1, .responded = true, .priority = 100, .weight = 50 },
    };
    oob_rank_probe_results(r, 2, 10, rank_rng_zero, &gc);
    assert_int_equal(r[0].index, 1);
    assert_int_equal(r[1].index, 0);
    gc_free(&gc);
}

/* Among responders, the lowest priority value wins (an absolute ordering). */
static void
test_rank_by_priority(void **state)
{
    struct gc_arena gc = gc_new();
    struct oob_probe_result r[] = {
        { .index = 0, .responded = true, .priority = 20, .weight = 50 },
        { .index = 1, .responded = true, .priority = 5, .weight = 50 },
        { .index = 2, .responded = true, .priority = 10, .weight = 50 },
    };
    oob_rank_probe_results(r, 3, 10, rank_rng_zero, &gc);
    assert_int_equal(r[0].index, 1); /* priority 5 */
    assert_int_equal(r[1].index, 2); /* priority 10 */
    assert_int_equal(r[2].index, 0); /* priority 20 */
    gc_free(&gc);
}

/* Within a priority, only servers within the latency margin of the fastest are
 * candidates; a slower (out-of-band) server ranks behind a faster one no matter
 * how large its weight. */
static void
test_rank_candidate_band(void **state)
{
    struct gc_arena gc = gc_new();
    struct oob_probe_result r[] = {
        { .index = 0, .responded = true, .priority = 10, .weight = 1000, .rtt_ms = 100 },
        { .index = 1, .responded = true, .priority = 10, .weight = 1, .rtt_ms = 20 },
    };
    /* margin 10ms: 20ms is fastest; 100ms is 80ms slower -> out of band */
    oob_rank_probe_results(r, 2, 10, rank_rng_zero, &gc);
    assert_int_equal(r[0].index, 1); /* fast, in-band, despite tiny weight */
    assert_int_equal(r[1].index, 0); /* slow, out-of-band, despite huge weight */
    gc_free(&gc);
}

/* A server widens its own band via the advertised max_latency_diff, joining the
 * candidate set even when it is well behind the fastest; it then participates in
 * the weighted selection. */
static void
test_rank_advertised_margin(void **state)
{
    struct gc_arena gc = gc_new();
    struct oob_probe_result r[] = {
        { .index = 0, .responded = true, .priority = 10, .weight = 1, .rtt_ms = 20 },
        { .index = 1,
          .responded = true,
          .priority = 10,
          .weight = 1000,
          .rtt_ms = 100,
          .max_latency_diff = 200 },
    };
    /* Client did not set a margin (-1), so each server's advertised value
     * applies: the 100ms server advertises 200 -> it is a candidate (the
     * default 10 would have excluded it); with weight 1000 (slice [1,1001)) a
     * draw of 500 selects it first. */
    rank_rng_value = 500;
    oob_rank_probe_results(r, 2, -1, rank_rng_fixed, &gc);
    assert_int_equal(r[0].index, 1);
    gc_free(&gc);
}

/* Among candidates, weight drives RFC-2782 proportional selection: a draw is
 * mapped to the server whose cumulative weight slice it falls in. */
static void
test_rank_weighted_selection(void **state)
{
    struct gc_arena gc = gc_new();
    /* equal priority and RTT -> both in band; weights 30 and 70, sum 100:
     * index 0 owns [0,30), index 1 owns [30,100). */
    const struct oob_probe_result base[] = {
        { .index = 0, .responded = true, .priority = 10, .weight = 30, .rtt_ms = 20 },
        { .index = 1, .responded = true, .priority = 10, .weight = 70, .rtt_ms = 20 },
    };
    struct oob_probe_result r[2];

    memcpy(r, base, sizeof(base));
    rank_rng_value = 10; /* falls in index 0's slice */
    oob_rank_probe_results(r, 2, 50, rank_rng_fixed, &gc);
    assert_int_equal(r[0].index, 0);

    memcpy(r, base, sizeof(base));
    rank_rng_value = 50; /* falls in index 1's slice */
    oob_rank_probe_results(r, 2, 50, rank_rng_fixed, &gc);
    assert_int_equal(r[0].index, 1);

    gc_free(&gc);
}

/* Non-responders are placed last, keeping their original relative order. */
static void
test_rank_nonresponders_last(void **state)
{
    struct gc_arena gc = gc_new();
    struct oob_probe_result r[] = {
        { .index = 0, .responded = false },
        { .index = 1, .responded = true, .priority = 10, .weight = 50, .rtt_ms = 20 },
        { .index = 2, .responded = false },
        { .index = 3, .responded = true, .priority = 10, .weight = 50, .rtt_ms = 20 },
    };
    oob_rank_probe_results(r, 4, 10, rank_rng_zero, &gc);
    assert_int_equal(r[0].index, 1); /* responder (rng_zero keeps order) */
    assert_int_equal(r[1].index, 3); /* responder */
    assert_int_equal(r[2].index, 0); /* non-responder, original order kept */
    assert_int_equal(r[3].index, 2);
    gc_free(&gc);
}

int
main(void)
{
    openvpn_unit_test_setup();
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_probe_parameter_roundtrip),
        cmocka_unit_test(test_probe_reply_roundtrip),
        cmocka_unit_test(test_probe_parameter_forward_compat),
        cmocka_unit_test(test_probe_parameter_too_short),
        cmocka_unit_test(test_tlv_header_truncated),
        cmocka_unit_test(test_server_probe_read_finds_parameter),
        cmocka_unit_test(test_server_probe_read_skips_unknown),
        cmocka_unit_test(test_server_probe_read_missing),
        cmocka_unit_test(test_server_probe_read_truncated),
        cmocka_unit_test(test_server_probe_read_wrong_msg_type),
        cmocka_unit_test(test_timestamp_in_window),
        cmocka_unit_test(test_build_probe_reply_valid),
        cmocka_unit_test(test_build_probe_reply_stale),
        cmocka_unit_test(test_build_probe_reply_no_parameter),
        cmocka_unit_test(test_client_reply_read_finds_reply),
        cmocka_unit_test(test_client_reply_read_skips_unknown),
        cmocka_unit_test(test_client_reply_read_missing),
        cmocka_unit_test(test_client_reply_read_wrong_msg_type),
        cmocka_unit_test(test_rank_responder_before_nonresponder),
        cmocka_unit_test(test_rank_by_priority),
        cmocka_unit_test(test_rank_candidate_band),
        cmocka_unit_test(test_rank_advertised_margin),
        cmocka_unit_test(test_rank_weighted_selection),
        cmocka_unit_test(test_rank_nonresponders_last),
    };

    return cmocka_run_group_tests_name("oob tests", tests, NULL, NULL);
}
