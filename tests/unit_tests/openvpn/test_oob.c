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
    };

    return cmocka_run_group_tests_name("oob tests", tests, NULL, NULL);
}
