//! Fake TLS 1.3 Handshake
//!
//! Validates TLS ClientHello against user secrets (HMAC-SHA256) and
//! builds fake ServerHello responses for domain fronting.

const std = @import("std");
const constants = @import("constants.zig");
const crypto = @import("../crypto/crypto.zig");
const obfuscation = @import("obfuscation.zig");

/// Re-export for convenience
pub const UserSecret = obfuscation.UserSecret;

// ============= TLS Validation Result =============

pub const TlsValidation = struct {
    /// Username that validated
    user: []const u8,
    /// Session ID from ClientHello
    session_id: []const u8,
    /// Client digest for response generation
    digest: [constants.tls_digest_len]u8,
    /// Timestamp extracted from digest
    timestamp: u32,
    /// The 16-byte user secret that matched (needed for ServerHello HMAC)
    secret: [16]u8,
};

// ============= Public Functions =============

/// Validate a TLS ClientHello against user secrets.
/// Returns validation result if a matching user is found.
pub fn validateTlsHandshake(
    allocator: std.mem.Allocator,
    handshake: []const u8,
    secrets: []const UserSecret,
    ignore_time_skew: bool,
) !?TlsValidation {
    const min_len = constants.tls_digest_pos + constants.tls_digest_len + 1;
    if (handshake.len < min_len) return null;

    // Extract digest
    const digest: [constants.tls_digest_len]u8 = handshake[constants.tls_digest_pos..][0..constants.tls_digest_len].*;

    // Extract session ID
    const session_id_len_pos = constants.tls_digest_pos + constants.tls_digest_len;
    if (session_id_len_pos >= handshake.len) return null;
    const session_id_len: usize = handshake[session_id_len_pos];
    if (session_id_len > 32) return null;

    const session_id_start = session_id_len_pos + 1;
    if (handshake.len < session_id_start + session_id_len) return null;

    // Build message with zeroed digest for HMAC
    const msg = try allocator.alloc(u8, handshake.len);
    defer allocator.free(msg);
    @memcpy(msg, handshake);
    @memset(msg[constants.tls_digest_pos..][0..constants.tls_digest_len], 0);

    const now: i64 = if (!ignore_time_skew)
        @intCast(std.time.timestamp())
    else
        0;

    for (secrets) |entry| {
        const computed = crypto.sha256Hmac(&entry.secret, msg);

        // Constant-time comparison of first 28 bytes using stdlib
        if (!std.crypto.timing_safe.eql([28]u8, digest[0..28].*, computed[0..28].*)) continue;

        // Extract timestamp from last 4 bytes (XOR)
        const timestamp = std.mem.readInt(u32, &[4]u8{
            digest[28] ^ computed[28],
            digest[29] ^ computed[29],
            digest[30] ^ computed[30],
            digest[31] ^ computed[31],
        }, .little);

        if (!ignore_time_skew) {
            const time_diff = now - @as(i64, @intCast(timestamp));
            if (time_diff < constants.time_skew_min or time_diff > constants.time_skew_max) {
                continue;
            }
        }

        return .{
            .user = entry.name,
            .session_id = handshake[session_id_start .. session_id_start + session_id_len],
            .digest = digest,
            .timestamp = timestamp,
            .secret = entry.secret,
        };
    }

    return null;
}

/// Build a fake TLS ServerHello response.
///
/// The response consists of three TLS records that the client validates:
/// 1. ServerHello record (type 0x16) — contains the HMAC digest in the `random` field
/// 2. Change Cipher Spec record (type 0x14) — fixed 6 bytes
/// 3. Fake Application Data record (type 0x17) — random body simulating encrypted data
///
/// The client (ConnectionSocket.cpp) validates the response by:
/// - Checking for `\x16\x03\x03` prefix (ServerHello record)
/// - Reading len1 (ServerHello record payload length)
/// - Checking for `\x14\x03\x03\x00\x01\x01\x17\x03\x03` after the ServerHello record
/// - Reading len2 (Application Data payload length)
/// - Waiting for all `len1 + 5 + 11 + len2` bytes
/// - Saving bytes at offset 11..43 (the random field), zeroing them
/// - Computing HMAC-SHA256(secret, client_digest || entire_response_with_zeroed_random)
/// - Comparing the HMAC to the saved random field (straight 32-byte compare, no XOR)
pub fn buildServerHello(
    allocator: std.mem.Allocator,
    secret: []const u8,
    client_digest: *const [constants.tls_digest_len]u8,
    session_id: []const u8,
) ![]u8 {
    // Generate random X25519-like key (just random bytes for fake TLS)
    var x25519_key: [32]u8 = undefined;
    crypto.randomBytes(&x25519_key);

    const session_id_len: u8 = @intCast(session_id.len);

    // Extensions: key_share (x25519) + supported_versions (TLS 1.3)
    const key_share_ext = buildKeyShareExt(&x25519_key);
    const supported_versions_ext = [_]u8{
        0x00, 0x2b, // supported_versions
        0x00, 0x02, // length
        0x03, 0x04, // TLS 1.3
    };
    const extensions_len: u16 = @intCast(key_share_ext.len + supported_versions_ext.len);

    const body_len: u24 = @intCast(2 + // version
        32 + // random
        1 + session_id.len + // session_id
        2 + // cipher suite
        1 + // compression
        2 + key_share_ext.len + supported_versions_ext.len // extensions
    );

    // Pre-calculate total response size
    const record_len: u16 = @intCast(@as(u32, body_len) + 4);
    const server_hello_len = 5 + @as(usize, record_len);
    const ccs_len: usize = 6;

    // Fake Application Data record: simulates encrypted handshake data.
    // The canonical Python proxy uses random.randrange(1024, 4096) bytes.
    // We use a deterministic-ish size within that range.
    const fake_app_data_body_len: u16 = blk: {
        var len_buf: [2]u8 = undefined;
        crypto.randomBytes(&len_buf);
        const raw = std.mem.readInt(u16, &len_buf, .big);
        // Map to range [1024, 4096): 1024 + (raw % 3072)
        break :blk 1024 + (raw % 3072);
    };
    const app_data_record_len: usize = 5 + @as(usize, fake_app_data_body_len);

    const total_len = server_hello_len + ccs_len + app_data_record_len;

    const response = try allocator.alloc(u8, total_len);
    errdefer allocator.free(response);
    var pos: usize = 0;

    // --- ServerHello record ---
    // Record header
    response[pos] = constants.tls_record_handshake;
    pos += 1;
    @memcpy(response[pos..][0..2], &constants.tls_version);
    pos += 2;
    std.mem.writeInt(u16, response[pos..][0..2], record_len, .big);
    pos += 2;

    // Handshake header
    response[pos] = 0x02; // ServerHello type
    pos += 1;
    response[pos] = @intCast((body_len >> 16) & 0xff);
    response[pos + 1] = @intCast((body_len >> 8) & 0xff);
    response[pos + 2] = @intCast(body_len & 0xff);
    pos += 3;

    // Version (TLS 1.2 in header)
    @memcpy(response[pos..][0..2], &constants.tls_version);
    pos += 2;

    // Random (32 bytes placeholder — will be replaced with HMAC digest)
    const random_pos = pos;
    @memset(response[pos..][0..32], 0);
    pos += 32;

    // Session ID
    response[pos] = session_id_len;
    pos += 1;
    @memcpy(response[pos..][0..session_id.len], session_id);
    pos += session_id.len;

    // Cipher suite: TLS_AES_128_GCM_SHA256
    response[pos] = 0x13;
    response[pos + 1] = 0x01;
    pos += 2;

    // Compression: none
    response[pos] = 0x00;
    pos += 1;

    // Extensions
    std.mem.writeInt(u16, response[pos..][0..2], extensions_len, .big);
    pos += 2;
    @memcpy(response[pos..][0..key_share_ext.len], &key_share_ext);
    pos += key_share_ext.len;
    @memcpy(response[pos..][0..supported_versions_ext.len], &supported_versions_ext);
    pos += supported_versions_ext.len;

    // --- Change Cipher Spec record ---
    response[pos] = constants.tls_record_change_cipher;
    response[pos + 1] = constants.tls_version[0];
    response[pos + 2] = constants.tls_version[1];
    response[pos + 3] = 0x00;
    response[pos + 4] = 0x01;
    response[pos + 5] = 0x01;
    pos += 6;

    // --- Fake Application Data record ---
    // The client expects \x17\x03\x03 + 2-byte length + body after the CCS record.
    response[pos] = constants.tls_record_application;
    response[pos + 1] = constants.tls_version[0];
    response[pos + 2] = constants.tls_version[1];
    std.mem.writeInt(u16, response[pos + 3 ..][0..2], fake_app_data_body_len, .big);
    pos += 5;

    // Fill with random bytes to simulate encrypted handshake data
    crypto.randomBytes(response[pos..][0..fake_app_data_body_len]);
    pos += fake_app_data_body_len;

    std.debug.assert(pos == total_len);

    // Compute HMAC over the ENTIRE response (all three records) with random field zeroed.
    // The client validates: HMAC-SHA256(secret, client_digest || full_response_zeroed_random)
    // and compares the result to the 32 bytes at offset 11 (straight compare, no XOR).
    const hmac_input = try allocator.alloc(u8, constants.tls_digest_len + total_len);
    defer allocator.free(hmac_input);
    @memcpy(hmac_input[0..constants.tls_digest_len], client_digest);
    @memcpy(hmac_input[constants.tls_digest_len..], response[0..total_len]);

    const response_digest = crypto.sha256Hmac(secret, hmac_input);

    // Insert digest into ServerHello random field (no timestamp XOR for server response)
    @memcpy(response[random_pos..][0..32], &response_digest);

    return response;
}

fn buildKeyShareExt(public_key: *const [32]u8) [40]u8 {
    var ext: [40]u8 = undefined;
    ext[0] = 0x00;
    ext[1] = 0x33; // key_share
    ext[2] = 0x00;
    ext[3] = 0x24; // length = 36
    ext[4] = 0x00;
    ext[5] = 0x1d; // x25519
    ext[6] = 0x00;
    ext[7] = 0x20; // key length = 32
    @memcpy(ext[8..40], public_key);
    return ext;
}

/// Check if bytes look like a TLS ClientHello.
pub fn isTlsHandshake(first_bytes: []const u8) bool {
    if (first_bytes.len < 3) return false;
    return first_bytes[0] == constants.tls_record_handshake and
        first_bytes[1] == 0x03 and
        (first_bytes[2] == 0x01 or first_bytes[2] == 0x03);
}

/// Extract SNI from a TLS ClientHello.
pub fn extractSni(handshake: []const u8) ?[]const u8 {
    if (handshake.len < 43 or handshake[0] != constants.tls_record_handshake) return null;

    const record_len = std.mem.readInt(u16, handshake[3..5], .big);
    if (handshake.len < @as(usize, 5) + record_len) return null;

    var pos: usize = 5;
    if (pos >= handshake.len or handshake[pos] != 0x01) return null; // not ClientHello

    pos += 4; // type + 3-byte length
    pos += 2 + 32; // version + random

    if (pos + 1 > handshake.len) return null;
    const session_id_len: usize = handshake[pos];
    pos += 1 + session_id_len;

    if (pos + 2 > handshake.len) return null;
    const cipher_suites_len = std.mem.readInt(u16, handshake[pos..][0..2], .big);
    pos += 2 + cipher_suites_len;

    if (pos + 1 > handshake.len) return null;
    const comp_len: usize = handshake[pos];
    pos += 1 + comp_len;

    if (pos + 2 > handshake.len) return null;
    const ext_total_len = std.mem.readInt(u16, handshake[pos..][0..2], .big);
    pos += 2;
    const ext_end = pos + ext_total_len;
    if (ext_end > handshake.len) return null;

    // Walk extensions
    while (pos + 4 <= ext_end) {
        const etype = std.mem.readInt(u16, handshake[pos..][0..2], .big);
        const elen = std.mem.readInt(u16, handshake[pos + 2 ..][0..2], .big);
        pos += 4;
        if (pos + elen > ext_end) break;

        if (etype == 0x0000 and elen >= 5) {
            // server_name extension
            var sn_pos = pos + 2; // skip list_len
            const sn_end = @min(pos + elen, ext_end);
            while (sn_pos + 3 <= sn_end) {
                const name_type = handshake[sn_pos];
                const name_len = std.mem.readInt(u16, handshake[sn_pos + 1 ..][0..2], .big);
                sn_pos += 3;
                if (sn_pos + name_len > sn_end) break;
                if (name_type == 0 and name_len > 0) {
                    return handshake[sn_pos .. sn_pos + name_len];
                }
                sn_pos += name_len;
            }
        }
        pos += elen;
    }

    return null;
}

// ============= Tests =============

test "isTlsHandshake" {
    try std.testing.expect(isTlsHandshake(&[_]u8{ 0x16, 0x03, 0x01 }));
    try std.testing.expect(isTlsHandshake(&[_]u8{ 0x16, 0x03, 0x03 }));
    try std.testing.expect(!isTlsHandshake(&[_]u8{ 0x16, 0x03 }));
    try std.testing.expect(!isTlsHandshake(&[_]u8{ 0x17, 0x03, 0x03 }));
}

test "timing_safe.eql" {
    const a = [_]u8{ 1, 2, 3 };
    const b = [_]u8{ 1, 2, 3 };
    const c = [_]u8{ 1, 2, 4 };
    try std.testing.expect(std.crypto.timing_safe.eql([3]u8, a, b));
    try std.testing.expect(!std.crypto.timing_safe.eql([3]u8, a, c));
}

test "buildServerHello produces valid three-record structure" {
    const allocator = std.testing.allocator;
    var digest = [_]u8{0x42} ** 32;
    const session_id = [_]u8{0x01} ** 32;

    const response = try buildServerHello(
        allocator,
        &digest,
        &digest,
        &session_id,
    );
    defer allocator.free(response);

    // Record 1: ServerHello (\x16\x03\x03)
    try std.testing.expectEqual(@as(u8, constants.tls_record_handshake), response[0]);
    try std.testing.expectEqual(@as(u8, 0x03), response[1]);
    try std.testing.expectEqual(@as(u8, 0x03), response[2]);

    const len1 = std.mem.readInt(u16, response[3..5], .big);
    const ccs_start = 5 + @as(usize, len1);

    // Record 2: Change Cipher Spec (\x14\x03\x03\x00\x01\x01)
    try std.testing.expect(response.len > ccs_start + 6);
    try std.testing.expectEqual(@as(u8, constants.tls_record_change_cipher), response[ccs_start]);
    try std.testing.expectEqual(@as(u8, 0x03), response[ccs_start + 1]);
    try std.testing.expectEqual(@as(u8, 0x03), response[ccs_start + 2]);
    try std.testing.expectEqual(@as(u8, 0x00), response[ccs_start + 3]);
    try std.testing.expectEqual(@as(u8, 0x01), response[ccs_start + 4]);
    try std.testing.expectEqual(@as(u8, 0x01), response[ccs_start + 5]);

    // Record 3: Application Data (\x17\x03\x03)
    const app_start = ccs_start + 6;
    try std.testing.expect(response.len > app_start + 5);
    try std.testing.expectEqual(@as(u8, constants.tls_record_application), response[app_start]);
    try std.testing.expectEqual(@as(u8, 0x03), response[app_start + 1]);
    try std.testing.expectEqual(@as(u8, 0x03), response[app_start + 2]);

    const len2 = std.mem.readInt(u16, response[app_start + 3 ..][0..2], .big);
    // Fake AppData body should be in [1024, 4096)
    try std.testing.expect(len2 >= 1024);
    try std.testing.expect(len2 < 4096);

    // Total response length should match all three records
    try std.testing.expectEqual(5 + @as(usize, len1) + 6 + 5 + @as(usize, len2), response.len);

    // HMAC digest is at offset 11 (tls_digest_pos) in the response
    // Verify it by recomputing: HMAC(secret, client_digest || response_with_zeroed_random)
    var zeroed = try allocator.alloc(u8, response.len);
    defer allocator.free(zeroed);
    @memcpy(zeroed, response);
    @memset(zeroed[constants.tls_digest_pos..][0..constants.tls_digest_len], 0);

    var hmac_input = try allocator.alloc(u8, constants.tls_digest_len + response.len);
    defer allocator.free(hmac_input);
    @memcpy(hmac_input[0..constants.tls_digest_len], &digest);
    @memcpy(hmac_input[constants.tls_digest_len..], zeroed);

    const expected_hmac = crypto.sha256Hmac(&digest, hmac_input);
    try std.testing.expect(std.crypto.timing_safe.eql(
        [32]u8,
        response[constants.tls_digest_pos..][0..32].*,
        expected_hmac,
    ));
}
