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
#include "ssl_pkt.h"
#include "test_common.h"

/* The early negotiation flags TLV of a reset packet asking a tls-crypt-v2
 * client to resend its WKc, as older versions wrote it by hand. */
static void
test_tlv_write_u16_wire_format(void **state)
{
    struct gc_arena gc = gc_new();
    struct buffer buf = alloc_buf_gc(16, &gc);

    assert_true(ctrl_msg_tlv_write_u16(&buf, TLV_TYPE_EARLY_NEG_FLAGS, false,
                                       EARLY_NEG_FLAG_RESEND_WKC));
    const uint8_t expected[] = { 0x00, 0x01, 0x00, 0x02, 0x00, 0x01 };
    assert_int_equal(BLEN(&buf), sizeof(expected));
    assert_memory_equal(BPTR(&buf), expected, sizeof(expected));

    /* the optional flag is the most significant bit of the type field */
    buf_clear(&buf);
    assert_true(ctrl_msg_tlv_write_u16(&buf, TLV_TYPE_EARLY_NEG_FLAGS, true, 0));
    assert_int_equal(BPTR(&buf)[0], 0x80);
    assert_int_equal(BPTR(&buf)[1], 0x01);

    gc_free(&gc);
}

/* A TLV header survives the round trip, the optional flag kept apart from
 * the 15-bit type. */
static void
test_tlv_header_roundtrip(void **state)
{
    struct gc_arena gc = gc_new();
    struct buffer buf = alloc_buf_gc(16, &gc);

    assert_true(ctrl_msg_tlv_write_header(&buf, 0x1234, true, 5));
    assert_int_equal(BLEN(&buf), 4);

    struct ctrl_msg_tlv_header hdr;
    assert_true(ctrl_msg_tlv_read_header(&buf, &hdr));
    assert_int_equal(hdr.type, 0x1234);
    assert_true(hdr.optional);
    assert_int_equal(hdr.value_len, 5);
    assert_int_equal(BLEN(&buf), 0);

    gc_free(&gc);
}

/* Walking a payload returns each TLV in turn, with a value covering exactly
 * its bytes, and consumes the payload. */
static void
test_tlv_next_walks_payload(void **state)
{
    struct gc_arena gc = gc_new();
    struct buffer buf = alloc_buf_gc(64, &gc);

    assert_true(ctrl_msg_tlv_write_u16(&buf, TLV_TYPE_EARLY_NEG_FLAGS, false, 0xabcd));
    assert_true(ctrl_msg_tlv_write_header(&buf, 0x7ff, true, 4));
    assert_true(buf_write_u32(&buf, 0x11223344));
    assert_true(ctrl_msg_tlv_write_header(&buf, 0x5, false, 0)); /* empty value */

    struct ctrl_msg_tlv_header hdr;
    struct buffer value;

    assert_true(ctrl_msg_tlv_next(&buf, &hdr, &value));
    assert_int_equal(hdr.type, TLV_TYPE_EARLY_NEG_FLAGS);
    assert_false(hdr.optional);
    assert_int_equal(BLEN(&value), 2);
    assert_int_equal(buf_read_u16(&value), 0xabcd);

    assert_true(ctrl_msg_tlv_next(&buf, &hdr, &value));
    assert_int_equal(hdr.type, 0x7ff);
    assert_true(hdr.optional);
    assert_int_equal(BLEN(&value), 4);
    assert_int_equal(buf_read_u32(&value, NULL), 0x11223344);

    assert_true(ctrl_msg_tlv_next(&buf, &hdr, &value));
    assert_int_equal(hdr.type, 0x5);
    assert_int_equal(BLEN(&value), 0);

    assert_int_equal(BLEN(&buf), 0);

    gc_free(&gc);
}

/* A TLV header claiming more value bytes than the payload holds is rejected,
 * rather than read past the end of the payload. */
static void
test_tlv_next_value_truncated(void **state)
{
    struct gc_arena gc = gc_new();
    struct buffer buf = alloc_buf_gc(64, &gc);

    assert_true(ctrl_msg_tlv_write_header(&buf, TLV_TYPE_EARLY_NEG_FLAGS, false, 8));
    assert_true(buf_write_u32(&buf, 0));

    struct ctrl_msg_tlv_header hdr;
    struct buffer value;
    assert_false(ctrl_msg_tlv_next(&buf, &hdr, &value));

    gc_free(&gc);
}

/* Reading a TLV header must fail when the buffer holds less data than a
 * complete 4-byte header, rather than read past the available data. */
static void
test_tlv_header_truncated(void **state)
{
    struct gc_arena gc = gc_new();
    const uint8_t bytes[] = { 0x00, 0x01, 0x00 };

    /* 0 to 3 bytes: none, part of the type field, the type field, and the type
     * field with half of the length */
    for (size_t n = 0; n <= sizeof(bytes); n++)
    {
        struct buffer buf = alloc_buf_gc(16, &gc);
        assert_true(buf_write(&buf, bytes, n));
        struct buffer copy = buf;

        struct ctrl_msg_tlv_header hdr;
        struct buffer value;
        assert_false(ctrl_msg_tlv_read_header(&buf, &hdr));
        assert_false(ctrl_msg_tlv_next(&copy, &hdr, &value));
    }

    gc_free(&gc);
}

/* Writing fails, rather than writes a partial TLV, when buf is too small. */
static void
test_tlv_write_no_room(void **state)
{
    struct gc_arena gc = gc_new();

    struct buffer buf = alloc_buf_gc(3, &gc);
    assert_false(ctrl_msg_tlv_write_header(&buf, TLV_TYPE_EARLY_NEG_FLAGS, false, 2));

    /* room for the header but not the value */
    buf = alloc_buf_gc(5, &gc);
    assert_false(ctrl_msg_tlv_write_u16(&buf, TLV_TYPE_EARLY_NEG_FLAGS, false, 1));

    gc_free(&gc);
}

/* The TLV codec tests run as a group of pkt_testdriver; see test_pkt.c. */
int
run_control_msg_tests(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_tlv_write_u16_wire_format),
        cmocka_unit_test(test_tlv_header_roundtrip),
        cmocka_unit_test(test_tlv_next_walks_payload),
        cmocka_unit_test(test_tlv_next_value_truncated),
        cmocka_unit_test(test_tlv_header_truncated),
        cmocka_unit_test(test_tlv_write_no_room),
    };

    return cmocka_run_group_tests_name("control message TLV tests", tests, NULL, NULL);
}
