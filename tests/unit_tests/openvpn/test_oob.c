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

#include "control_msg.h"
#include "oob.h"
#include "test_common.h"

/* Write a probe request TLV and read it back; fields must survive the round
 * trip and the whole buffer must be consumed. */
static void
test_probe_request_roundtrip(void **state)
{
    struct gc_arena gc = gc_new();
    struct buffer buf = alloc_buf_gc(128, &gc);

    const struct oob_probe_request in = {
        .request_id = 0xdeadbeef,
        .timestamp = 0x0123456789abcdefULL,
        .flags = 0,
    };
    assert_true(oob_probe_request_write(&buf, &in));
    /* header (4) + value (16) */
    assert_int_equal(BLEN(&buf), 4 + OOB_PROBE_REQUEST_LEN);

    /* the header codec, read from a copy so the scan below still sees it */
    struct buffer peek = buf;
    struct ctrl_msg_tlv_header hdr;
    assert_true(ctrl_msg_tlv_read_header(&peek, &hdr));
    assert_int_equal(hdr.type, TLV_TYPE_PROBE_REQUEST);
    assert_false(hdr.optional);
    assert_int_equal(hdr.value_len, OOB_PROBE_REQUEST_LEN);

    struct buffer value;
    assert_true(ctrl_msg_find_tlv(&buf, TLV_TYPE_PROBE_REQUEST, &value));
    assert_int_equal(BLEN(&value), OOB_PROBE_REQUEST_LEN);

    struct oob_probe_request out = { 0 };
    assert_true(oob_probe_request_read(&value, &out));
    assert_int_equal(in.request_id, out.request_id);
    assert_true(in.timestamp == out.timestamp);
    assert_int_equal(in.flags, out.flags);
    /* the scan consumed header and value alike */
    assert_int_equal(BLEN(&buf), 0);

    gc_free(&gc);
}

/* The probe request wire format is locked to the spec's field order
 * (request_id, timestamp, flags), big-endian. */
static void
test_probe_request_wire_format(void **state)
{
    struct gc_arena gc = gc_new();
    struct buffer buf = alloc_buf_gc(128, &gc);

    const struct oob_probe_request in = {
        .request_id = 0x11223344,
        .timestamp = 0x0102030405060708ULL,
        .flags = 0,
    };
    assert_true(oob_probe_request_write(&buf, &in));

    const uint8_t expected[] = {
        0x00,
        0x02, /* TLV type 2 (not optional) */
        0x00,
        0x10, /* TLV value length = 16 */
        0x11,
        0x22,
        0x33,
        0x44, /* request_id */
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06,
        0x07,
        0x08, /* timestamp */
        0x00,
        0x00,
        0x00,
        0x00, /* flags */
    };
    assert_int_equal(BLEN(&buf), sizeof(expected));
    assert_memory_equal(BPTR(&buf), expected, sizeof(expected));

    gc_free(&gc);
}

/* Write a probe reply TLV and read it back. */
static void
test_probe_reply_roundtrip(void **state)
{
    struct gc_arena gc = gc_new();
    struct buffer buf = alloc_buf_gc(128, &gc);

    struct oob_probe_reply in = {
        .request_id = 0x11223344,
        .priority = 10,
        .weight = 100,
        .connect_lifetime = 30,
        .flags = 1,
        .max_latency_diff = 25,
    };

    assert_true(oob_probe_reply_write(&buf, &in));
    assert_int_equal(BLEN(&buf), 4 + OOB_PROBE_REPLY_LEN);

    struct buffer peek = buf;
    struct ctrl_msg_tlv_header hdr;
    assert_true(ctrl_msg_tlv_read_header(&peek, &hdr));
    assert_int_equal(hdr.type, TLV_TYPE_PROBE_REPLY);
    assert_int_equal(hdr.value_len, OOB_PROBE_REPLY_LEN);

    struct buffer value;
    assert_true(ctrl_msg_find_tlv(&buf, TLV_TYPE_PROBE_REPLY, &value));

    struct oob_probe_reply out = { 0 };
    assert_true(oob_probe_reply_read(&value, &out));
    assert_int_equal(in.request_id, out.request_id);
    assert_int_equal(in.priority, out.priority);
    assert_int_equal(in.weight, out.weight);
    assert_int_equal(in.connect_lifetime, out.connect_lifetime);
    assert_int_equal(in.flags, out.flags);
    assert_int_equal(in.max_latency_diff, out.max_latency_diff);
    assert_int_equal(BLEN(&buf), 0);

    gc_free(&gc);
}

/* The probe reply wire format is locked to the spec's field order (request_id,
 * priority, weight, max_latency_diff, connect_lifetime, flags), big-endian. */
static void
test_probe_reply_wire_format(void **state)
{
    struct gc_arena gc = gc_new();
    struct buffer buf = alloc_buf_gc(128, &gc);

    struct oob_probe_reply in = {
        .request_id = 0x11223344,
        .priority = 10,
        .weight = 100,
        .connect_lifetime = 30,
        .flags = 1,
        .max_latency_diff = 25,
    };

    assert_true(oob_probe_reply_write(&buf, &in));

    const uint8_t expected[] = {
        0x00,
        0x03, /* TLV type 3 (not optional) */
        0x00,
        0x0e, /* TLV value length = 14 */
        0x11,
        0x22,
        0x33,
        0x44, /* request_id */
        0x00,
        0x0a, /* priority = 10 */
        0x00,
        0x64, /* weight = 100 */
        0x00,
        0x19, /* max_latency_diff = 25 */
        0x00,
        0x1e, /* connect_lifetime = 30 */
        0x00,
        0x01, /* flags = 1 */
    };
    assert_int_equal(BLEN(&buf), sizeof(expected));
    assert_memory_equal(BPTR(&buf), expected, sizeof(expected));

    gc_free(&gc);
}

/* A TLV with a longer-than-known value must still parse: the known fields are
 * read and the trailing bytes are skipped (forward compatibility). */
static void
test_probe_request_forward_compat(void **state)
{
    struct gc_arena gc = gc_new();
    struct buffer buf = alloc_buf_gc(128, &gc);

    const uint16_t extended_len = OOB_PROBE_REQUEST_LEN + 4;
    assert_true(ctrl_msg_tlv_write_header(&buf, TLV_TYPE_PROBE_REQUEST, false, extended_len));
    assert_true(buf_write_u32(&buf, 7));          /* request_id */
    assert_true(buf_write_u32(&buf, 0));          /* timestamp high */
    assert_true(buf_write_u32(&buf, 0xdeadbeef)); /* timestamp low */
    assert_true(buf_write_u32(&buf, 0));          /* flags */
    assert_true(buf_write_u32(&buf, 0x11223344)); /* unknown trailing field */

    struct buffer value;
    assert_true(ctrl_msg_find_tlv(&buf, TLV_TYPE_PROBE_REQUEST, &value));
    assert_int_equal(BLEN(&value), extended_len);

    struct oob_probe_request out = { 0 };
    assert_true(oob_probe_request_read(&value, &out));
    assert_int_equal(out.request_id, 7);
    assert_true(out.timestamp == 0xdeadbeefULL);
    assert_int_equal(out.flags, 0);
    /* the unknown trailing field must have been consumed from the payload */
    assert_int_equal(BLEN(&buf), 0);

    gc_free(&gc);
}

/* A value shorter than the mandatory fields must be rejected, even when it
 * holds enough bytes for some of the individual fields to read successfully. */
static void
test_probe_request_too_short(void **state)
{
    struct gc_arena gc = gc_new();
    struct buffer buf = alloc_buf_gc(128, &gc);

    /* 4 of the 16 mandatory value bytes: enough for the request_id alone */
    assert_true(buf_write_u32(&buf, 0xdeadbeef));

    struct oob_probe_request out = { 0 };
    assert_false(oob_probe_request_read(&buf, &out));

    gc_free(&gc);
}

/* A TLV header claiming more value bytes than the payload holds must be
 * rejected by the scan rather than reported as found -- for the TLV being
 * looked for as much as for one that would merely be skipped. */
static void
test_find_tlv_value_truncated(void **state)
{
    struct gc_arena gc = gc_new();
    struct buffer value;

    /* the wanted TLV declares 12 value bytes, only 4 are present */
    struct buffer buf = alloc_buf_gc(128, &gc);
    assert_true(ctrl_msg_tlv_write_header(&buf, TLV_TYPE_PROBE_REQUEST, false,
                                          OOB_PROBE_REQUEST_LEN));
    assert_true(buf_write_u32(&buf, 0xdeadbeef));
    assert_false(ctrl_msg_find_tlv(&buf, TLV_TYPE_PROBE_REQUEST, &value));

    /* same defect on a TLV that would be skipped: the scan must not walk past
     * the end of the payload looking for the next header */
    struct buffer buf2 = alloc_buf_gc(128, &gc);
    assert_true(ctrl_msg_tlv_write_header(&buf2, 0x7ff, false, 64));
    assert_true(buf_write_u32(&buf2, 0));
    assert_false(ctrl_msg_find_tlv(&buf2, TLV_TYPE_PROBE_REQUEST, &value));

    gc_free(&gc);
}

/* Bytes left over after the last TLV that are too few for a header make the
 * message malformed, even when the wanted TLV was already found. */
static void
test_find_tlv_trailing_bytes(void **state)
{
    struct gc_arena gc = gc_new();
    struct buffer value;

    /* 1 to 3 bytes: less than a 4-byte TLV header */
    for (int trailing = 1; trailing <= 3; trailing++)
    {
        struct buffer buf = alloc_buf_gc(128, &gc);
        const struct oob_probe_request in = { .timestamp = 1, .flags = 0 };
        assert_true(oob_probe_request_write(&buf, &in));
        for (int i = 0; i < trailing; i++)
        {
            assert_true(buf_write_u8(&buf, 0));
        }
        assert_false(ctrl_msg_find_tlv(&buf, TLV_TYPE_PROBE_REQUEST, &value));
    }

    gc_free(&gc);
}

/* An unknown TLV marked optional after the wanted one is skipped, and the
 * wanted value is still the one returned. */
static void
test_find_tlv_skips_optional_after_wanted(void **state)
{
    struct gc_arena gc = gc_new();
    struct buffer buf = alloc_buf_gc(128, &gc);
    struct buffer value;

    const struct oob_probe_request in = { .timestamp = 7, .flags = 0 };
    assert_true(oob_probe_request_write(&buf, &in));
    assert_true(ctrl_msg_tlv_write_header(&buf, 0x7ff, true, 4));
    assert_true(buf_write_u32(&buf, 0));

    assert_true(ctrl_msg_find_tlv(&buf, TLV_TYPE_PROBE_REQUEST, &value));
    assert_int_equal(BLEN(&value), OOB_PROBE_REQUEST_LEN);
    struct oob_probe_request out = { 0 };
    assert_true(oob_probe_request_read(&value, &out));
    assert_true(out.timestamp == 7);

    gc_free(&gc);
}

/* The wanted TLV may occur only once: a second one rejects the message. Repeats
 * of an unknown TLV marked optional are skipped like any other. */
static void
test_find_tlv_rejects_duplicate(void **state)
{
    struct gc_arena gc = gc_new();
    struct buffer value;
    const struct oob_probe_request in = { .request_id = 1 };

    struct buffer buf = alloc_buf_gc(128, &gc);
    assert_true(oob_probe_request_write(&buf, &in));
    assert_true(oob_probe_request_write(&buf, &in));
    assert_false(ctrl_msg_find_tlv(&buf, TLV_TYPE_PROBE_REQUEST, &value));

    buf = alloc_buf_gc(128, &gc);
    for (int i = 0; i < 2; i++)
    {
        assert_true(ctrl_msg_tlv_write_header(&buf, 0x7ff, true, 4));
        assert_true(buf_write_u32(&buf, 0));
    }
    assert_true(oob_probe_request_write(&buf, &in));
    assert_true(ctrl_msg_find_tlv(&buf, TLV_TYPE_PROBE_REQUEST, &value));

    gc_free(&gc);
}

/* An empty payload holds no TLV. */
static void
test_find_tlv_empty_payload(void **state)
{
    struct gc_arena gc = gc_new();
    struct buffer buf = alloc_buf_gc(16, &gc);
    struct buffer value;

    assert_false(ctrl_msg_find_tlv(&buf, TLV_TYPE_PROBE_REQUEST, &value));

    gc_free(&gc);
}

/* A payload of just a probe request is found by the scan, along with its
 * request_id. */
static void
test_probe_request_find(void **state)
{
    struct gc_arena gc = gc_new();
    struct buffer buf = alloc_buf_gc(128, &gc);

    const struct oob_probe_request in = {
        .request_id = 42,
        .timestamp = 0x1122334455667788ULL,
        .flags = 0,
    };
    assert_true(oob_probe_request_write(&buf, &in));

    struct oob_probe_request out = { 0 };
    assert_true(oob_probe_request_find(&buf, &out));
    assert_int_equal(out.request_id, 42);
    assert_true(in.timestamp == out.timestamp);
    assert_int_equal(in.flags, out.flags);

    gc_free(&gc);
}

/* TLVs other than probe request are skipped, so the scan finds the
 * probe request even when preceded by an unknown TLV. */
static void
test_probe_request_find_skips_unknown(void **state)
{
    struct gc_arena gc = gc_new();
    struct buffer buf = alloc_buf_gc(128, &gc);

    /* An unknown but optional TLV (type 0x7ff) ... */
    assert_true(ctrl_msg_tlv_write_header(&buf, 0x7ff, true, 4));
    assert_true(buf_write_u32(&buf, 0xcafef00d));
    /* ... followed by the real probe request */
    const struct oob_probe_request in = { .timestamp = 42, .flags = 0 };
    assert_true(oob_probe_request_write(&buf, &in));

    struct oob_probe_request out = { 0 };
    assert_true(oob_probe_request_find(&buf, &out));
    assert_true(out.timestamp == 42);

    gc_free(&gc);
}

/* An unknown TLV that is NOT marked optional carries something the sender
 * requires us to act on: the whole message is rejected, whether that TLV comes
 * before or after the one we were looking for. */
static void
test_probe_request_find_rejects_unknown_mandatory(void **state)
{
    struct gc_arena gc = gc_new();
    const struct oob_probe_request in = { .timestamp = 42, .flags = 0 };

    struct buffer before = alloc_buf_gc(128, &gc);
    assert_true(ctrl_msg_tlv_write_header(&before, 0x7ff, false, 4));
    assert_true(buf_write_u32(&before, 0xcafef00d));
    assert_true(oob_probe_request_write(&before, &in));

    struct buffer after = alloc_buf_gc(128, &gc);
    assert_true(oob_probe_request_write(&after, &in));
    assert_true(ctrl_msg_tlv_write_header(&after, 0x7ff, false, 4));
    assert_true(buf_write_u32(&after, 0xcafef00d));

    struct oob_probe_request out = { 0 };
    assert_false(oob_probe_request_find(&before, &out));
    assert_false(oob_probe_request_find(&after, &out));

    gc_free(&gc);
}

/* A payload with no probe request must be rejected. */
static void
test_probe_request_find_missing(void **state)
{
    struct gc_arena gc = gc_new();
    struct buffer buf = alloc_buf_gc(128, &gc);

    assert_true(ctrl_msg_tlv_write_header(&buf, 0x7ff, true, 4));
    assert_true(buf_write_u32(&buf, 0));

    struct oob_probe_request out = { 0 };
    assert_false(oob_probe_request_find(&buf, &out));

    gc_free(&gc);
}

/* A TLV whose declared length runs past the buffer must be rejected, not
 * read out of bounds. */
static void
test_probe_request_find_truncated(void **state)
{
    struct gc_arena gc = gc_new();
    struct buffer buf = alloc_buf_gc(128, &gc);

    /* TLV header claims a 16-byte value but no value bytes follow */
    assert_true(ctrl_msg_tlv_write_header(&buf, 0x7ff, false, 16));

    struct oob_probe_request out = { 0 };
    assert_false(oob_probe_request_find(&buf, &out));

    gc_free(&gc);
}

/* A payload carrying a probe reply instead holds no probe request. */
static void
test_probe_request_find_reply_tlv(void **state)
{
    struct gc_arena gc = gc_new();
    struct buffer buf = alloc_buf_gc(128, &gc);

    const struct oob_probe_reply in = { .request_id = 42 };
    assert_true(oob_probe_reply_write(&buf, &in));

    struct oob_probe_request out = { 0 };
    assert_false(oob_probe_request_find(&buf, &out));

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

/* A well-formed probe with an in-window timestamp is answered. */
static void
test_probe_request_check_valid(void **state)
{
    struct gc_arena gc = gc_new();
    struct buffer buf = alloc_buf_gc(128, &gc);

    const uint64_t now = 1000000;
    const struct oob_probe_request probe = { .request_id = 1, .timestamp = now, .flags = 0 };
    assert_true(oob_probe_request_write(&buf, &probe));

    struct oob_probe_request req = { 0 };
    assert_int_equal(oob_probe_request_check(&buf, now, 30, &req), OOB_PROBE_OK);
    assert_int_equal(req.request_id, 1);

    gc_free(&gc);
}

/* A well-formed probe whose timestamp is outside the window is stale; the
 * caller decides whether it still gets an answer. */
static void
test_probe_request_check_stale(void **state)
{
    struct gc_arena gc = gc_new();
    struct buffer buf = alloc_buf_gc(128, &gc);

    const uint64_t now = 1000000;
    const struct oob_probe_request probe = { .request_id = 7, .timestamp = now - 1000, .flags = 0 };
    assert_true(oob_probe_request_write(&buf, &probe));

    struct oob_probe_request req = { 0 };
    assert_int_equal(oob_probe_request_check(&buf, now, 30, &req), OOB_PROBE_STALE);
    assert_int_equal(req.request_id, 7); /* a stale probe may still be answered */

    gc_free(&gc);
}

/* A payload without a probe request is invalid (no reply). */
static void
test_probe_request_check_no_request(void **state)
{
    struct gc_arena gc = gc_new();
    struct buffer buf = alloc_buf_gc(128, &gc);

    assert_true(ctrl_msg_tlv_write_header(&buf, 0x7ff, true, 4));
    assert_true(buf_write_u32(&buf, 0));

    struct oob_probe_request req;
    assert_int_equal(oob_probe_request_check(&buf, 1000000, 30, &req), OOB_PROBE_INVALID);

    gc_free(&gc);
}

/* A payload of just a probe reply is found by the client scan, with all
 * fields surviving. */
static void
test_probe_reply_find(void **state)
{
    struct gc_arena gc = gc_new();
    struct buffer buf = alloc_buf_gc(128, &gc);

    struct oob_probe_reply in = {
        .request_id = 7,
        .priority = 5,
        .weight = 50,
        .max_latency_diff = 25,
        .connect_lifetime = 120,
        .flags = 1,
    };
    assert_true(oob_probe_reply_write(&buf, &in));

    struct oob_probe_reply out = { 0 };
    assert_true(oob_probe_reply_find(&buf, &out));
    assert_int_equal(out.request_id, in.request_id);
    assert_int_equal(out.priority, in.priority);
    assert_int_equal(out.weight, in.weight);
    assert_int_equal(out.max_latency_diff, in.max_latency_diff);
    assert_int_equal(out.connect_lifetime, in.connect_lifetime);
    assert_int_equal(out.flags, in.flags);

    gc_free(&gc);
}

/* TLVs other than the probe reply are skipped. */
static void
test_probe_reply_find_skips_unknown(void **state)
{
    struct gc_arena gc = gc_new();
    struct buffer buf = alloc_buf_gc(128, &gc);

    assert_true(ctrl_msg_tlv_write_header(&buf, 0x7ff, true, 4));
    assert_true(buf_write_u32(&buf, 0xabad1dea));
    struct oob_probe_reply in = { .priority = 7 };
    assert_true(oob_probe_reply_write(&buf, &in));

    struct oob_probe_reply out = { 0 };
    assert_true(oob_probe_reply_find(&buf, &out));
    assert_int_equal(out.priority, 7);

    gc_free(&gc);
}

/* As on the probe side, a mandatory TLV we do not understand -- here trailing
 * the probe reply -- invalidates the reply. */
static void
test_probe_reply_find_rejects_unknown_mandatory(void **state)
{
    struct gc_arena gc = gc_new();
    struct buffer buf = alloc_buf_gc(128, &gc);

    struct oob_probe_reply in = { .priority = 7 };
    assert_true(oob_probe_reply_write(&buf, &in));
    assert_true(ctrl_msg_tlv_write_header(&buf, 0x7ff, false, 4));
    assert_true(buf_write_u32(&buf, 0xabad1dea));

    struct oob_probe_reply out = { 0 };
    assert_false(oob_probe_reply_find(&buf, &out));

    gc_free(&gc);
}

/* A payload with no probe reply is rejected. */
static void
test_probe_reply_find_missing(void **state)
{
    struct gc_arena gc = gc_new();
    struct buffer buf = alloc_buf_gc(128, &gc);

    assert_true(ctrl_msg_tlv_write_header(&buf, 0x7ff, true, 4));
    assert_true(buf_write_u32(&buf, 0));

    struct oob_probe_reply out = { 0 };
    assert_false(oob_probe_reply_find(&buf, &out));

    gc_free(&gc);
}

/* Likewise, a payload carrying a probe request instead holds no probe reply. */
static void
test_probe_reply_find_request_tlv(void **state)
{
    struct gc_arena gc = gc_new();
    struct buffer buf = alloc_buf_gc(128, &gc);

    const struct oob_probe_request in = { .request_id = 7 };
    assert_true(oob_probe_request_write(&buf, &in));

    struct oob_probe_reply out = { 0 };
    assert_false(oob_probe_reply_find(&buf, &out));

    gc_free(&gc);
}

/* The OOB tests run as a second group of pkt_testdriver; see test_pkt.c. */
int
run_oob_tests(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_probe_request_roundtrip),
        cmocka_unit_test(test_probe_request_wire_format),
        cmocka_unit_test(test_probe_reply_roundtrip),
        cmocka_unit_test(test_probe_reply_wire_format),
        cmocka_unit_test(test_probe_request_forward_compat),
        cmocka_unit_test(test_probe_request_too_short),
        cmocka_unit_test(test_find_tlv_value_truncated),
        cmocka_unit_test(test_find_tlv_trailing_bytes),
        cmocka_unit_test(test_find_tlv_skips_optional_after_wanted),
        cmocka_unit_test(test_find_tlv_rejects_duplicate),
        cmocka_unit_test(test_find_tlv_empty_payload),
        cmocka_unit_test(test_probe_request_find),
        cmocka_unit_test(test_probe_request_find_skips_unknown),
        cmocka_unit_test(test_probe_request_find_rejects_unknown_mandatory),
        cmocka_unit_test(test_probe_request_find_missing),
        cmocka_unit_test(test_probe_request_find_truncated),
        cmocka_unit_test(test_probe_request_find_reply_tlv),
        cmocka_unit_test(test_timestamp_in_window),
        cmocka_unit_test(test_probe_request_check_valid),
        cmocka_unit_test(test_probe_request_check_stale),
        cmocka_unit_test(test_probe_request_check_no_request),
        cmocka_unit_test(test_probe_reply_find),
        cmocka_unit_test(test_probe_reply_find_skips_unknown),
        cmocka_unit_test(test_probe_reply_find_rejects_unknown_mandatory),
        cmocka_unit_test(test_probe_reply_find_missing),
        cmocka_unit_test(test_probe_reply_find_request_tlv),
    };

    return cmocka_run_group_tests_name("oob tests", tests, NULL, NULL);
}
