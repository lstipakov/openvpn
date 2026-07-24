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

/* connect_lifetime = 0 (a TCP reply: no handshake shortcut offered) survives
 * the write/read round trip like any other value. */
static void
test_probe_reply_zero_lifetime_roundtrip(void **state)
{
    struct gc_arena gc = gc_new();
    struct buffer buf = alloc_buf_gc(128, &gc);

    struct oob_probe_reply in = {
        .priority = 10,
        .weight = 100,
        .connect_lifetime = 0,
        .flags = 0,
    };
    memcpy(in.peer_session_id.id, "ABCDEFGH", SID_SIZE);

    assert_true(oob_probe_reply_write(&buf, &in));

    struct buffer value;
    assert_true(ctrl_msg_find_tlv(&buf, OOB_TLV_PROBE_REPLY, &value));

    struct oob_probe_reply out = { 0 };
    assert_true(oob_probe_reply_read(&value, &out));
    assert_int_equal(out.connect_lifetime, 0);

    gc_free(&gc);
}

/* Feed @p len framed bytes to a frame reader, delivering at most @p chunk
 * bytes per want/advance round. Returns the final status. */
static enum oob_frame_status
frame_reader_feed(struct oob_frame_reader *r, const uint8_t *data, int len, int chunk)
{
    int off = 0;
    enum oob_frame_status status = OOB_FRAME_NEED_MORE;
    while (off < len && status == OOB_FRAME_NEED_MORE)
    {
        uint8_t *dst;
        int want = oob_frame_reader_want(r, &dst);
        assert_true(want > 0);
        int n = want < chunk ? want : chunk;
        if (n > len - off)
        {
            n = len - off;
        }
        memcpy(dst, data + off, n);
        off += n;
        status = oob_frame_reader_advance(r, n);
    }
    return status;
}

/* A whole frame delivered in as few reads as the reader asks for. */
static void
test_frame_reader_whole(void **state)
{
    const uint8_t frame[] = { 0x00, 0x05, 'h', 'e', 'l', 'l', 'o' };
    struct oob_frame_reader r = { 0 };

    assert_int_equal(frame_reader_feed(&r, frame, sizeof(frame), 9999), OOB_FRAME_COMPLETE);
    assert_int_equal(r.pkt_len, 5);
    assert_memory_equal(r.pkt, "hello", 5);
}

/* One byte per read, including splitting the 2-byte length prefix. */
static void
test_frame_reader_byte_at_a_time(void **state)
{
    const uint8_t frame[] = { 0x00, 0x05, 'h', 'e', 'l', 'l', 'o' };
    struct oob_frame_reader r = { 0 };

    assert_int_equal(frame_reader_feed(&r, frame, sizeof(frame), 1), OOB_FRAME_COMPLETE);
    assert_int_equal(r.pkt_len, 5);
    assert_memory_equal(r.pkt, "hello", 5);
}

/* The want()/advance() contract across the header/payload boundary: the
 * reader asks exactly for what is missing at every step. */
static void
test_frame_reader_split_across_header(void **state)
{
    const uint8_t frame[] = { 0x00, 0x03, 'a', 'b', 'c' };
    struct oob_frame_reader r = { 0 };
    uint8_t *dst;

    assert_int_equal(oob_frame_reader_want(&r, &dst), 2);
    memcpy(dst, frame, 1); /* half the header */
    assert_int_equal(oob_frame_reader_advance(&r, 1), OOB_FRAME_NEED_MORE);

    assert_int_equal(oob_frame_reader_want(&r, &dst), 1); /* other half */
    memcpy(dst, frame + 1, 1);
    assert_int_equal(oob_frame_reader_advance(&r, 1), OOB_FRAME_NEED_MORE);

    assert_int_equal(oob_frame_reader_want(&r, &dst), 3); /* whole payload */
    memcpy(dst, frame + 2, 2);                            /* ... but deliver only part of it */
    assert_int_equal(oob_frame_reader_advance(&r, 2), OOB_FRAME_NEED_MORE);

    assert_int_equal(oob_frame_reader_want(&r, &dst), 1); /* the remainder */
    memcpy(dst, frame + 4, 1);
    assert_int_equal(oob_frame_reader_advance(&r, 1), OOB_FRAME_COMPLETE);
    assert_memory_equal(r.pkt, "abc", 3);
}

/* A zero length prefix is invalid (a packet always has at least an opcode). */
static void
test_frame_reader_zero_len(void **state)
{
    const uint8_t frame[] = { 0x00, 0x00 };
    struct oob_frame_reader r = { 0 };

    assert_int_equal(frame_reader_feed(&r, frame, sizeof(frame), 9999), OOB_FRAME_ERROR);
}

/* A length prefix beyond OOB_FRAME_MAX_LEN is invalid (not a probe reply). */
static void
test_frame_reader_oversize_len(void **state)
{
    const uint8_t frame[] = { 0x02, 0x00 }; /* 512 > 256 */
    struct oob_frame_reader r = { 0 };

    assert_int_equal(frame_reader_feed(&r, frame, sizeof(frame), 9999), OOB_FRAME_ERROR);
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
    assert_true(buf_write_u16(&buf, OOB_MSG_SERVER_PROBE));
    assert_true(ctrl_msg_tlv_write_header(&buf, 0x7ff, false, 4));
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

    assert_true(buf_write_u16(&buf, OOB_MSG_SERVER_PROBE));
    assert_true(ctrl_msg_tlv_write_header(&buf, 0x7ff, false, 4));
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
    assert_true(buf_write_u16(&buf, OOB_MSG_SERVER_PROBE));
    assert_true(ctrl_msg_tlv_write_header(&buf, 0x7ff, false, 16));

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

    assert_true(buf_write_u16(&buf, OOB_MSG_PROBE_REPLY));
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

    struct oob_probe_reply reply = {
        .priority = 5,
        .weight = 50,
        .max_latency_diff = 25,
        .connect_lifetime = 120,
        .flags = OOB_PROBE_REPLY_FLAG_RESEND_WKC,
    };
    assert_true(oob_build_probe_reply(&buf, now, 30, &peer, &reply));
    assert_memory_equal(reply.peer_session_id.id, peer.id, SID_SIZE);
    assert_int_equal(reply.priority, 5);
    assert_int_equal(reply.weight, 50);
    assert_int_equal(reply.connect_lifetime, 120);
    assert_int_equal(reply.flags, OOB_PROBE_REPLY_FLAG_RESEND_WKC);
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
    struct oob_probe_reply reply = { 0 };
    assert_false(oob_build_probe_reply(&buf, now, 30, &peer, &reply));

    gc_free(&gc);
}

/* A payload without a probe_parameter is dropped (no reply). */
static void
test_build_probe_reply_no_parameter(void **state)
{
    struct gc_arena gc = gc_new();
    struct buffer buf = alloc_buf_gc(128, &gc);

    assert_true(buf_write_u16(&buf, OOB_MSG_SERVER_PROBE));
    assert_true(ctrl_msg_tlv_write_header(&buf, 0x7ff, false, 4));
    assert_true(buf_write_u32(&buf, 0));

    struct session_id peer = { 0 };
    struct oob_probe_reply reply = { 0 };
    assert_false(oob_build_probe_reply(&buf, 1000000, 30, &peer, &reply));

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

    assert_true(buf_write_u16(&buf, OOB_MSG_PROBE_REPLY));
    assert_true(ctrl_msg_tlv_write_header(&buf, 0x7ff, false, 4));
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

    assert_true(buf_write_u16(&buf, OOB_MSG_PROBE_REPLY));
    assert_true(ctrl_msg_tlv_write_header(&buf, 0x7ff, false, 4));
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

    assert_true(buf_write_u16(&buf, OOB_MSG_SERVER_PROBE));
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
        { .index = 1, .responded = true, .reply = { .priority = 100, .weight = 50 } },
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
        { .index = 0, .responded = true, .reply = { .priority = 20, .weight = 50 } },
        { .index = 1, .responded = true, .reply = { .priority = 5, .weight = 50 } },
        { .index = 2, .responded = true, .reply = { .priority = 10, .weight = 50 } },
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
        { .index = 0, .responded = true, .rtt_ms = 100, .reply = { .priority = 10, .weight = 1000 } },
        { .index = 1, .responded = true, .rtt_ms = 20, .reply = { .priority = 10, .weight = 1 } },
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
        { .index = 0, .responded = true, .rtt_ms = 20, .reply = { .priority = 10, .weight = 1 } },
        { .index = 1,
          .responded = true,
          .rtt_ms = 100,
          .reply = { .priority = 10, .weight = 1000, .max_latency_diff = 200 } },
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
        { .index = 0, .responded = true, .rtt_ms = 20, .reply = { .priority = 10, .weight = 30 } },
        { .index = 1, .responded = true, .rtt_ms = 20, .reply = { .priority = 10, .weight = 70 } },
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
        { .index = 1, .responded = true, .rtt_ms = 20, .reply = { .priority = 10, .weight = 50 } },
        { .index = 2, .responded = false },
        { .index = 3, .responded = true, .rtt_ms = 20, .reply = { .priority = 10, .weight = 50 } },
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
        cmocka_unit_test(test_probe_reply_wire_format),
        cmocka_unit_test(test_probe_reply_zero_lifetime_roundtrip),
        cmocka_unit_test(test_frame_reader_whole),
        cmocka_unit_test(test_frame_reader_byte_at_a_time),
        cmocka_unit_test(test_frame_reader_split_across_header),
        cmocka_unit_test(test_frame_reader_zero_len),
        cmocka_unit_test(test_frame_reader_oversize_len),
        cmocka_unit_test(test_probe_parameter_forward_compat),
        cmocka_unit_test(test_probe_parameter_too_short),
        cmocka_unit_test(test_find_tlv_value_truncated),
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
