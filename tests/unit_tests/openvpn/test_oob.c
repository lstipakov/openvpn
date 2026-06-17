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

/* A message header survives the round trip; it is 10 bytes on the wire. */
static void
test_msg_header_roundtrip(void **state)
{
    struct gc_arena gc = gc_new();
    struct buffer buf = alloc_buf_gc(64, &gc);

    const struct ctrl_msg_header in = {
        .type = OOB_MSG_PROBE_REPLY,
        .message_id = 0x11223344,
        .response_id = 0x55667788,
    };
    assert_true(ctrl_msg_write_header(&buf, &in));
    assert_int_equal(BLEN(&buf), 10);
    const uint8_t wire[] = { 0x01, 0x01, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
    assert_memory_equal(BPTR(&buf), wire, sizeof(wire));

    struct ctrl_msg_header out = { 0 };
    assert_true(ctrl_msg_read_header(&buf, OOB_MSG_PROBE_REPLY, &out));
    assert_int_equal(out.type, in.type);
    assert_int_equal(out.message_id, in.message_id);
    assert_int_equal(out.response_id, in.response_id);
    assert_int_equal(BLEN(&buf), 0);

    gc_free(&gc);
}

/* 0 is not a valid message_id, and a header cut short is rejected. */
static void
test_msg_header_invalid(void **state)
{
    struct gc_arena gc = gc_new();
    struct ctrl_msg_header out;

    struct buffer zero = alloc_buf_gc(64, &gc);
    const struct ctrl_msg_header no_id = { .type = OOB_MSG_SERVER_PROBE };
    assert_true(ctrl_msg_write_header(&zero, &no_id));
    assert_false(ctrl_msg_read_header(&zero, OOB_MSG_SERVER_PROBE, &out));

    struct buffer short_hdr = alloc_buf_gc(64, &gc);
    assert_true(buf_write_u16(&short_hdr, OOB_MSG_SERVER_PROBE));
    assert_true(buf_write_u32(&short_hdr, 1));
    assert_true(buf_write_u16(&short_hdr, 0)); /* two bytes of response_id */
    assert_false(ctrl_msg_read_header(&short_hdr, OOB_MSG_SERVER_PROBE, &out));

    gc_free(&gc);
}

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

    /* the header codec, read from a copy so the scan below still sees it */
    struct buffer peek = buf;
    struct ctrl_msg_tlv_header hdr;
    assert_true(ctrl_msg_tlv_read_header(&peek, &hdr));
    assert_int_equal(hdr.type, OOB_TLV_PROBE_PARAMETER);
    assert_false(hdr.optional);
    assert_int_equal(hdr.value_len, OOB_PROBE_PARAMETER_LEN);

    struct buffer value;
    assert_true(ctrl_msg_find_tlv(&buf, OOB_TLV_PROBE_PARAMETER, &value));
    assert_int_equal(BLEN(&value), OOB_PROBE_PARAMETER_LEN);

    struct oob_probe_parameter out = { 0 };
    assert_true(oob_probe_parameter_read(&value, &out));
    assert_true(in.timestamp == out.timestamp);
    assert_int_equal(in.flags, out.flags);
    /* the scan consumed header and value alike */
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

    struct buffer peek = buf;
    struct ctrl_msg_tlv_header hdr;
    assert_true(ctrl_msg_tlv_read_header(&peek, &hdr));
    assert_int_equal(hdr.type, OOB_TLV_PROBE_REPLY);
    assert_int_equal(hdr.value_len, OOB_PROBE_REPLY_LEN);

    struct buffer value;
    assert_true(ctrl_msg_find_tlv(&buf, OOB_TLV_PROBE_REPLY, &value));

    struct oob_probe_reply out = { 0 };
    assert_true(oob_probe_reply_read(&value, &out));
    assert_memory_equal(in.peer_session_id.id, out.peer_session_id.id, SID_SIZE);
    assert_int_equal(in.priority, out.priority);
    assert_int_equal(in.weight, out.weight);
    assert_int_equal(in.connect_lifetime, out.connect_lifetime);
    assert_int_equal(in.flags, out.flags);
    assert_int_equal(in.max_latency_diff, out.max_latency_diff);
    assert_int_equal(BLEN(&buf), 0);

    gc_free(&gc);
}

/* The probe reply wire format is locked to the spec's field order
 * (priority, weight, max_latency_diff, connect_lifetime, flags), big-endian. */
static void
test_probe_reply_wire_format(void **state)
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

    const uint8_t expected[] = {
        0x02,
        0x01, /* TLV type 0x201 (not optional) */
        0x00,
        0x14, /* TLV value length = 20 */
        'A',
        'B',
        'C',
        'D',
        'E',
        'F',
        'G',
        'H',  /* peer_session_id */
        0x00,
        0x0a, /* priority = 10 */
        0x00,
        0x64, /* weight = 100 */
        0x00,
        0x19, /* max_latency_diff = 25 */
        0x00,
        0x1e, /* connect_lifetime = 30 */
        0x00,
        0x00,
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
test_probe_parameter_forward_compat(void **state)
{
    struct gc_arena gc = gc_new();
    struct buffer buf = alloc_buf_gc(128, &gc);

    const uint16_t extended_len = OOB_PROBE_PARAMETER_LEN + 4;
    assert_true(ctrl_msg_tlv_write_header(&buf, OOB_TLV_PROBE_PARAMETER, false, extended_len));
    assert_true(buf_write_u32(&buf, 0));          /* timestamp high */
    assert_true(buf_write_u32(&buf, 0xdeadbeef)); /* timestamp low */
    assert_true(buf_write_u32(&buf, 0));          /* flags */
    assert_true(buf_write_u32(&buf, 0x11223344)); /* unknown trailing field */

    struct buffer value;
    assert_true(ctrl_msg_find_tlv(&buf, OOB_TLV_PROBE_PARAMETER, &value));
    assert_int_equal(BLEN(&value), extended_len);

    struct oob_probe_parameter out = { 0 };
    assert_true(oob_probe_parameter_read(&value, &out));
    assert_true(out.timestamp == 0xdeadbeefULL);
    assert_int_equal(out.flags, 0);
    /* the unknown trailing field must have been consumed from the payload */
    assert_int_equal(BLEN(&buf), 0);

    gc_free(&gc);
}

/* A value shorter than the mandatory fields must be rejected, even when it
 * holds enough bytes for some of the individual fields to read successfully. */
static void
test_probe_parameter_too_short(void **state)
{
    struct gc_arena gc = gc_new();
    struct buffer buf = alloc_buf_gc(128, &gc);

    /* 4 of the 12 mandatory value bytes: too short for the timestamp, but
     * enough for a u32 read to succeed on its own */
    assert_true(buf_write_u32(&buf, 0xdeadbeef));

    struct oob_probe_parameter out = { 0 };
    assert_false(oob_probe_parameter_read(&buf, &out));

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
    assert_true(ctrl_msg_tlv_write_header(&buf, OOB_TLV_PROBE_PARAMETER, false,
                                          OOB_PROBE_PARAMETER_LEN));
    assert_true(buf_write_u32(&buf, 0xdeadbeef));
    assert_false(ctrl_msg_find_tlv(&buf, OOB_TLV_PROBE_PARAMETER, &value));

    /* same defect on a TLV that would be skipped: the scan must not walk past
     * the end of the payload looking for the next header */
    struct buffer buf2 = alloc_buf_gc(128, &gc);
    assert_true(ctrl_msg_tlv_write_header(&buf2, 0x7ff, false, 64));
    assert_true(buf_write_u32(&buf2, 0));
    assert_false(ctrl_msg_find_tlv(&buf2, OOB_TLV_PROBE_PARAMETER, &value));

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
        const struct oob_probe_parameter in = { .timestamp = 1, .flags = 0 };
        assert_true(oob_probe_parameter_write(&buf, &in));
        for (int i = 0; i < trailing; i++)
        {
            assert_true(buf_write_u8(&buf, 0));
        }
        assert_false(ctrl_msg_find_tlv(&buf, OOB_TLV_PROBE_PARAMETER, &value));
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

    const struct oob_probe_parameter in = { .timestamp = 7, .flags = 0 };
    assert_true(oob_probe_parameter_write(&buf, &in));
    assert_true(ctrl_msg_tlv_write_header(&buf, 0x7ff, true, 4));
    assert_true(buf_write_u32(&buf, 0));

    assert_true(ctrl_msg_find_tlv(&buf, OOB_TLV_PROBE_PARAMETER, &value));
    assert_int_equal(BLEN(&value), OOB_PROBE_PARAMETER_LEN);
    struct oob_probe_parameter out = { 0 };
    assert_true(oob_probe_parameter_read(&value, &out));
    assert_true(out.timestamp == 7);

    gc_free(&gc);
}

/* An empty payload holds no TLV. */
static void
test_find_tlv_empty_payload(void **state)
{
    struct gc_arena gc = gc_new();
    struct buffer buf = alloc_buf_gc(16, &gc);
    struct buffer value;

    assert_false(ctrl_msg_find_tlv(&buf, OOB_TLV_PROBE_PARAMETER, &value));

    gc_free(&gc);
}

/* Reading a TLV header must fail when the buffer holds less data than a
 * complete 4-byte header (empty, or only the type field), rather than read
 * past the available data. */
static void
test_tlv_header_truncated(void **state)
{
    struct gc_arena gc = gc_new();
    struct buffer buf = alloc_buf_gc(128, &gc);

    struct ctrl_msg_tlv_header hdr;

    /* empty buffer */
    assert_false(ctrl_msg_tlv_read_header(&buf, &hdr));

    /* only the type field present, no length */
    assert_true(buf_write_u16(&buf, OOB_TLV_PROBE_PARAMETER));
    assert_false(ctrl_msg_tlv_read_header(&buf, &hdr));

    gc_free(&gc);
}

/* The OOB tests run as a second group of pkt_testdriver; see test_pkt.c. */
int
run_oob_tests(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_msg_header_roundtrip),
        cmocka_unit_test(test_msg_header_invalid),
        cmocka_unit_test(test_probe_parameter_roundtrip),
        cmocka_unit_test(test_probe_reply_roundtrip),
        cmocka_unit_test(test_probe_reply_wire_format),
        cmocka_unit_test(test_probe_parameter_forward_compat),
        cmocka_unit_test(test_probe_parameter_too_short),
        cmocka_unit_test(test_find_tlv_value_truncated),
        cmocka_unit_test(test_find_tlv_trailing_bytes),
        cmocka_unit_test(test_find_tlv_skips_optional_after_wanted),
        cmocka_unit_test(test_find_tlv_empty_payload),
        cmocka_unit_test(test_tlv_header_truncated),
    };

    return cmocka_run_group_tests_name("oob tests", tests, NULL, NULL);
}
