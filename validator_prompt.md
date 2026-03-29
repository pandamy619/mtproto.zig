Goal
Build a production MTProto proxy in Zig (Telegram proxy) that works with all clients including iPhone/iOS Telegram. The proxy implements FakeTLS + MTProto Obfuscated2 protocol to relay traffic between Telegram clients and Telegram datacenters.

Instructions
- The server runs as a systemd service on a Linux VPS at 45.77.223.232, deployed via make deploy which cross-compiles from Mac and SCPs the binary
- Cross-compilation: zig build -Doptimize=ReleaseFast -Dtarget=x86_64-linux
- Zig version: 0.15
- User IPs: 81.17.27.66 = Mac, 109.252.90.134 = iPhone (also tried VPN IP 103.242.74.56)
- Deploy requires stopping service first due to ReadOnlyPaths=/opt/mtproto-proxy in systemd unit — Makefile handles this (stop → scp → start)

Discoveries
Architecture & Prior Fixes
1. iOS TCP Connection Pooling: iOS Telegram pre-opens 2-5 idle TCP connections (pool warming). Short timeouts kill these, causing iOS to mark proxy as unstable. Solution: two-stage timeout with poll() (5-min idle) then SO_RCVTIMEO (10s active).
2. GPA Mutex Deadlock: GeneralPurposeAllocator has an internal mutex causing deadlocks under heavy thread contention. Fixed by switching to std.heap.page_allocator.
3. Three critical bugs in buildServerHello were fixed based on canonical Telegram client source (ConnectionSocket.cpp):
   - Bug 1 - HMAC Scope: The HMAC must cover the entire response (ServerHello + CCS + fake AppData records), not just the ServerHello record.
   - Bug 2 - Timestamp XOR was incorrectly ADDED: Server response HMAC has NO timestamp XOR (timestamp XOR is client-side only).
   - Bug 3 - Fake AppData record is REQUIRED: Client expects three records: ServerHello \x16\x03\x03, CCS \x14\x03\x03\x00\x01\x01, Fake AppData \x17\x03\x03.
Canonical Python mtprotoproxy Analysis (THIS SESSION)
4. FAST_MODE in canonical Python proxy: The canonical Python proxy (alexbers/mtprotoproxy) has FAST_MODE=True by default. In FAST_MODE:
   - Client's enc_key+enc_iv (already SHA256-hashed key + raw IV) is embedded reversed into the DC nonce at rnd[8..56)
   - DC decryptor and client encryptor are replaced with no-ops for S2C direction
   - S2C data passes through without decrypt/re-encrypt (DC encrypts with same keystream client expects)
   - C2S direction always does full decrypt+re-encrypt regardless of FAST_MODE
5. Our Zig proxy uses non-FAST_MODE behavior — full decrypt/re-encrypt in both directions with independent DC keys. This is correct and should work. Exhaustive comparison confirmed:
   - Counter states match canonical: client_decryptor=4, client_encryptor=0, tg_encryptor=4, tg_decryptor=0
   - Key derivation matches exactly: decrypt_key = SHA256(dec_prekey || secret), encrypt_key = SHA256(reversed_prekey || secret)
   - DC nonce construction matches: raw keys (no SHA256), encrypt full nonce but only replace bytes from proto_tag_pos onward
   - Direction semantics in relay match: S2C = tg_decryptor → client_encryptor → TLS wrap; C2S = TLS unwrap → client_decryptor → tg_encryptor
Current Critical Bug (THIS SESSION)
6. CPU busy-loop / spin bug: After adding diagnostic hex-dump logging to relayDcToClient and relayClientToDc, the deployed proxy enters a 95-100% CPU busy-loop with many threads (48-280) that never produce log output. Connections are accepted (threads spawned) but relay diagnostics never appear. The process becomes unresponsive to logging.
   Root cause NOT YET identified but likely suspects:
   - The diagnostic logging itself may be triggering the issue (format string with hex slice {x:0>2} on a slice could have issues in ReleaseFast)
   - Possible interaction between non-blocking sockets and the diagnostic code paths
   - The busy-loop existed BEFORE this session's changes too (280 threads accumulated in previous deployment before restart) — the diagnostics just made it more visible
   Evidence: Before restart, the old binary had accumulated 280 threads doing nothing (all idle pool connections from iPhone). After restart with new binary, Mac connected successfully (TLS OK, MTProto OK, 304B pipelined data), entered relay, but then NO further log output appeared while CPU hit 95.7% with 48 threads.

Accomplished
Completed:
- ✅ Two-stage timeout (idle poll() 5min → active SO_RCVTIMEO 10s)
- ✅ Thread stack size reduced to 128KB
- ✅ Replaced GPA with std.heap.page_allocator
- ✅ Max concurrent connection limit (atomic counter, cap 8192)
- ✅ TasksMax=65535 in systemd service file
- ✅ Peer IP in all log messages via formatAddress() helper
- ✅ Diagnostic byte counters and direction-specific error logging in relay
- ✅ Fixed buildServerHello (HMAC over full response, no timestamp XOR, fake AppData re-added)
- ✅ Mac Telegram Desktop works — stable connections, functional proxy
- ✅ Full comparison of crypto chain against canonical Python mtprotoproxy — all correct
- ✅ Added diagnostic hex-dump logging to relayDcToClient (first S2C pre/post crypto), pipelined data info, TLS Alert detection, conn_id passed to relay functions
In Progress / Broken:
- ⏳ CPU busy-loop bug: Latest deployed binary with diagnostics causes 95%+ CPU. Need to investigate and fix. The busy-loop may be in the relay poll() loop — if dc.read() returns WouldBlock repeatedly without the poll() catching it, or if there's a condition where poll() reports ready but no data is available, causing an infinite loop.
- ⏳ iPhone still broken: iPhone connections (both direct 109.252.90.134 and VPN 103.242.74.56) fail with c2s=0 s2c=~100-200 ConnectionReset — iPhone never sends relay data
- ⏳ Mac connections also partially fail: Some Mac connections show same pattern (polls=2 c2s=0 s2c=~154 ConnectionReset) — only some Mac connections survive and work
Next Steps:
1. Fix the CPU busy-loop — most likely in relayBidirectional poll loop. Check if relayClientToDc or relayDcToClient can silently return (not error) when the connection is actually dead, causing poll() to spin. The WouldBlock handling return if (err == error.WouldBlock) {} else err returns void (success) which makes the outer loop continue to poll() — this is by design but could spin if the socket is in a broken state that always reports ready.
2. Once busy-loop is fixed, the hex-dump diagnostics should reveal why S2C data causes iPhone (and some Mac connections) to RST.
3. Investigate the polls=2 c2s=0 s2c=~100-200 pattern — this happens on BOTH Mac and iPhone. Some connections die immediately after first S2C relay. Could be auth key negotiation responses that the client rejects.

Codebase

--- src/main.zig ---
```zig
//! MTProto Proxy — Zig implementation
//!
//! A production-grade Telegram MTProto proxy supporting TLS-fronted
//! obfuscated connections to Telegram datacenters.

const std = @import("std");
const constants = @import("protocol/constants.zig");
const crypto = @import("crypto/crypto.zig");
const obfuscation = @import("protocol/obfuscation.zig");
const tls = @import("protocol/tls.zig");
const config = @import("config.zig");
const proxy = @import("proxy/proxy.zig");

// Override default log level so info/debug messages are visible in release builds.
pub const std_options = std.Options{
    .log_level = .debug,
};

const log = std.log.scoped(.mtproto);

const version = "0.1.0";

// ============= Output Helpers (Zig 0.15 compatible) =============

/// Write a formatted string to stdout via posix write.
fn writeStdout(comptime fmt: []const u8, args: anytype) void {
    var buf: [4096]u8 = undefined;
    const slice = std.fmt.bufPrint(&buf, fmt, args) catch return;
    _ = std.posix.write(std.posix.STDOUT_FILENO, slice) catch return;
}

/// Write a formatted string to stderr.
fn writeStderr(comptime fmt: []const u8, args: anytype) void {
    var buf: [4096]u8 = undefined;
    const slice = std.fmt.bufPrint(&buf, fmt, args) catch return;
    _ = std.posix.write(std.posix.STDERR_FILENO, slice) catch return;
}

/// Write a hex byte to stdout.
fn writeHexByte(byte: u8) void {
    const hex = "0123456789abcdef";
    const out = [2]u8{ hex[byte >> 4], hex[byte & 0x0f] };
    _ = std.posix.write(std.posix.STDOUT_FILENO, &out) catch return;
}

/// Write raw string to stdout.
fn writeRaw(s: []const u8) void {
    _ = std.posix.write(std.posix.STDOUT_FILENO, s) catch return;
}

// ============= Public IP Detection =============

/// Try to detect the server's public IP address via external services.
/// Returns the IP string (caller owns memory) or null on failure.
fn detectPublicIp(allocator: std.mem.Allocator) ?[]const u8 {
    // Try multiple services in order
    const services = [_][]const []const u8{
        &.{ "curl", "-s", "--max-time", "3", "https://ifconfig.me" },
        &.{ "curl", "-s", "--max-time", "3", "https://api.ipify.org" },
        &.{ "curl", "-s", "--max-time", "3", "https://icanhazip.com" },
    };

    for (services) |argv| {
        const result = std.process.Child.run(.{
            .allocator = allocator,
            .argv = argv,
        }) catch continue;

        defer allocator.free(result.stderr);

        const stdout = result.stdout;
        // Trim whitespace/newlines
        const trimmed = std.mem.trim(u8, stdout, &[_]u8{ ' ', '\t', '\n', '\r' });
        if (trimmed.len == 0 or trimmed.len > 45) {
            allocator.free(stdout);
            continue;
        }

        // Basic validation: should look like an IP
        if (std.mem.indexOfScalar(u8, trimmed, '.') != null or
            std.mem.indexOfScalar(u8, trimmed, ':') != null)
        {
            // If trimmed is a sub-slice of stdout, dupe it so we can free stdout
            const ip = allocator.dupe(u8, trimmed) catch {
                allocator.free(stdout);
                continue;
            };
            allocator.free(stdout);
            return ip;
        }
        allocator.free(stdout);
    }
    return null;
}

// ============= Startup Banner =============

/// Print a stylish startup banner with config summary and connection links.
fn printBanner(allocator: std.mem.Allocator, cfg: config.Config) void {
    const R = "\x1b[0m";
    const B = "\x1b[1m";
    const D = "\x1b[2m";
    const cyan = "\x1b[36m";
    const green = "\x1b[32m";
    const yellow = "\x1b[33m";
    const magenta = "\x1b[35m";
    const white = "\x1b[97m";
    const red = "\x1b[31m";

    // Detect public IP
    writeRaw("\n" ++ D ++ "  Detecting public IP..." ++ R);
    const public_ip = detectPublicIp(allocator);
    defer if (public_ip) |ip| allocator.free(ip);
    writeRaw("\r\x1b[K");

    const server_ip = public_ip orelse "<SERVER_IP>";

    // Logo
    writeRaw("\n" ++ B ++ cyan);
    writeRaw("       __  __ _____ ____            _\n");
    writeRaw("      |  \\/  |_   _|  _ \\ _ __ ___ | |_ ___\n");
    writeRaw("      | |\\/| | | | | |_) | '__/ _ \\| __/ _ \\\n");
    writeRaw("      | |  | | | | |  __/| | | (_) | || (_) |\n");
    writeRaw("      |_|  |_| |_| |_|   |_|  \\___/ \\__\\___/\n");
    writeRaw(R);
    writeStdout("      {s}{s}proxy · zig edition · v{s}{s}\n\n", .{ D, white, version, R });

    // ─── SERVER ─────────────────────────────────────
    writeRaw("  " ++ D ++ "───" ++ R ++ " " ++ B ++ cyan ++ "SERVER" ++ R ++ " " ++ D ++ "──────────────────────────────────────" ++ R ++ "\n");
    writeStdout("      Listen       " ++ B ++ green ++ "0.0.0.0:{d}" ++ R ++ "\n", .{cfg.port});
    writeStdout("      Public IP    " ++ B ++ "{s}{s}" ++ R ++ "\n", .{
        if (public_ip != null) green else yellow,
        server_ip,
    });
    writeStdout("      TLS Domain   " ++ B ++ yellow ++ "{s}" ++ R ++ "\n", .{cfg.tls_domain});
    writeRaw("      Masking      " ++ B);
    if (cfg.mask) {
        writeRaw(green ++ "enabled");
    } else {
        writeRaw(yellow ++ "disabled");
    }
    writeRaw(R ++ "\n\n");

    // ─── USERS ──────────────────────────────────────
    writeStdout("  " ++ D ++ "───" ++ R ++ " " ++ B ++ cyan ++ "USERS" ++ R ++ " ({d}) " ++ D ++ "────────────────────────────────────" ++ R ++ "\n", .{cfg.users.count()});
    var it = @constCast(&cfg.users).iterator();
    while (it.next()) |entry| {
        writeStdout("      " ++ green ++ "●" ++ R ++ " " ++ B ++ "{s}" ++ R ++ "  " ++ D, .{entry.key_ptr.*});
        for (entry.value_ptr.*) |byte| {
            writeHexByte(byte);
        }
        writeRaw(R ++ "\n");
    }
    writeRaw("\n");

    // ─── LINKS ──────────────────────────────────────
    writeRaw("  " ++ D ++ "───" ++ R ++ " " ++ B ++ cyan ++ "LINKS" ++ R ++ " " ++ D ++ "──────────────────────────────────────" ++ R ++ "\n");
    if (public_ip == null) {
        writeRaw("      " ++ red ++ "⚠  Could not detect IP. Replace <SERVER_IP> manually." ++ R ++ "\n");
    }

    var it2 = @constCast(&cfg.users).iterator();
    while (it2.next()) |entry| {
        writeStdout("      " ++ B ++ magenta ++ "{s}" ++ R ++ "\n", .{entry.key_ptr.*});

        // tg:// deep link
        writeStdout("      " ++ cyan ++ "tg://" ++ R ++ "proxy?server={s}&port={d}&secret=", .{ server_ip, cfg.port });
        writeRaw(green ++ "ee");
        for (entry.value_ptr.*) |byte| {
            writeHexByte(byte);
        }
        for (cfg.tls_domain) |byte| {
            writeHexByte(byte);
        }
        writeRaw(R ++ "\n");

        // t.me link
        writeStdout("      " ++ D ++ "t.me/proxy?server={s}&port={d}&secret=ee", .{ server_ip, cfg.port });
        for (entry.value_ptr.*) |byte| {
            writeHexByte(byte);
        }
        for (cfg.tls_domain) |byte| {
            writeHexByte(byte);
        }
        writeRaw(R ++ "\n");
    }

    // Footer
    writeRaw("\n  " ++ D ++ "──────────────────────────────────────────────────" ++ R ++ "\n");
    writeRaw("  " ++ B ++ cyan ++ "⏳ Waiting for connections..." ++ R ++ "\n\n");
}

pub fn main() !void {
    // Use page_allocator instead of GeneralPurposeAllocator for production.
    // GPA has an internal mutex that causes deadlocks under heavy thread contention
    // (1000+ simultaneous connections all doing TLS validation allocations).
    const allocator = std.heap.page_allocator;

    // Parse config path from args
    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();
    _ = args.next(); // skip program name
    const config_path = args.next() orelse "config.toml";

    // Parse config
    const cfg = config.Config.loadFromFile(allocator, config_path) catch |err| {
        writeStderr("\x1b[1m\x1b[31m  ✗ Failed to load config '{s}': {}\x1b[0m\n", .{ config_path, err });
        writeStderr("\n  Usage: mtproto-proxy [config.toml]\n\n", .{});
        return;
    };
    defer cfg.deinit(allocator);

    // Print the startup banner (includes IP detection)
    printBanner(allocator, cfg);

    // Create shared state (DI — no globals)
    var state = proxy.ProxyState.init(allocator, cfg);
    defer state.deinit();

    // Run the proxy
    try state.run();
}

test {
    _ = constants;
    _ = crypto;
    _ = obfuscation;
    _ = tls;
    _ = config;
    _ = proxy;
}
```

--- src/config.zig ---
```zig
//! Configuration loading for MTProto proxy.
//!
//! Parses a simplified TOML config with user secrets and server settings.
//! Format is compatible with the Rust telemt config.toml.

const std = @import("std");

pub const Config = struct {
    port: u16 = 443,
    tls_domain: []const u8 = "google.com",
    users: std.StringHashMap([16]u8),
    /// Whether to mask bad clients (forward to tls_domain)
    mask: bool = true,

    pub fn loadFromFile(allocator: std.mem.Allocator, path: []const u8) !Config {
        const file = try std.fs.cwd().openFile(path, .{});
        defer file.close();
        const content = try file.readToEndAlloc(allocator, 1024 * 1024);
        defer allocator.free(content);
        return parse(allocator, content);
    }

    pub fn parse(allocator: std.mem.Allocator, content: []const u8) !Config {
        var cfg = Config{
            .users = std.StringHashMap([16]u8).init(allocator),
        };

        var lines = std.mem.splitScalar(u8, content, '\n');
        var in_users_section = false;
        var in_censorship_section = false;
        var in_server_section = false;

        while (lines.next()) |raw_line| {
            const line = std.mem.trim(u8, raw_line, &[_]u8{ ' ', '\t', '\r' });

            // Skip empty lines and comments
            if (line.len == 0 or line[0] == '#') continue;

            // Section headers
            if (line[0] == '[') {
                in_users_section = std.mem.eql(u8, line, "[access.users]");
                in_censorship_section = std.mem.eql(u8, line, "[censorship]");
                in_server_section = std.mem.eql(u8, line, "[server]");
                continue;
            }

            // Key = value parsing
            if (std.mem.indexOfScalar(u8, line, '=')) |eq_pos| {
                const key = std.mem.trim(u8, line[0..eq_pos], &[_]u8{ ' ', '\t' });
                var value = std.mem.trim(u8, line[eq_pos + 1 ..], &[_]u8{ ' ', '\t' });

                // Strip quotes from value
                if (value.len >= 2 and value[0] == '"' and value[value.len - 1] == '"') {
                    value = value[1 .. value.len - 1];
                }

                if (in_users_section) {
                    // Parse user secret (32 hex chars = 16 bytes)
                    if (value.len != 32) continue;
                    var secret: [16]u8 = undefined;
                    _ = std.fmt.hexToBytes(&secret, value) catch continue;
                    const name = try allocator.dupe(u8, key);
                    try cfg.users.put(name, secret);
                } else if (in_server_section) {
                    if (std.mem.eql(u8, key, "port")) {
                        cfg.port = std.fmt.parseInt(u16, value, 10) catch 443;
                    }
                } else if (in_censorship_section) {
                    if (std.mem.eql(u8, key, "tls_domain")) {
                        cfg.tls_domain = try allocator.dupe(u8, value);
                    } else if (std.mem.eql(u8, key, "mask")) {
                        cfg.mask = std.mem.eql(u8, value, "true");
                    }
                }
            }
        }

        return cfg;
    }

    pub fn deinit(self: *const Config, allocator: std.mem.Allocator) void {
        var users = @constCast(&self.users);
        var it = users.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
        }
        users.deinit();
        // Free tls_domain if it was allocated (not the default)
        if (!std.mem.eql(u8, self.tls_domain, "google.com")) {
            allocator.free(self.tls_domain);
        }
    }

    /// Get user secrets as a flat slice for handshake validation.
    pub fn getUserSecrets(self: *const Config, allocator: std.mem.Allocator) ![]const struct { name: []const u8, secret: [16]u8 } {
        const Entry = struct { name: []const u8, secret: [16]u8 };
        var list = std.ArrayList(Entry).init(allocator);
        var it = @constCast(&self.users).iterator();
        while (it.next()) |entry| {
            try list.append(.{
                .name = entry.key_ptr.*,
                .secret = entry.value_ptr.*,
            });
        }
        return try list.toOwnedSlice();
    }
};

// ============= Tests =============

test "parse config" {
    const content =
        \\[server]
        \\port = 8443
        \\
        \\[censorship]
        \\tls_domain = "example.com"
        \\mask = true
        \\
        \\[access.users]
        \\alice = "00112233445566778899aabbccddeeff"
        \\bob = "ffeeddccbbaa99887766554433221100"
    ;

    var cfg = try Config.parse(std.testing.allocator, content);
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u16, 8443), cfg.port);
    try std.testing.expectEqualStrings("example.com", cfg.tls_domain);
    try std.testing.expect(cfg.mask);
    try std.testing.expectEqual(@as(usize, 2), cfg.users.count());

    const alice_secret = cfg.users.get("alice").?;
    try std.testing.expectEqual(@as(u8, 0x00), alice_secret[0]);
    try std.testing.expectEqual(@as(u8, 0xff), alice_secret[15]);
}
```

--- src/crypto/crypto.zig ---
```zig
//! Cryptographic primitives for MTProto proxy.
//!
//! Wraps Zig's std.crypto for:
//! - AES-256-CTR (obfuscation layer)
//! - AES-256-CBC (middle proxy protocol)
//! - SHA-256, HMAC-SHA256 (TLS handshake validation, key derivation)
//! - MD5, SHA-1 (protocol-mandated for middle proxy KDF — not replaceable)

const std = @import("std");
const Aes256 = std.crypto.core.aes.Aes256;

// ============= AES-256-CTR =============

/// AES-256-CTR stream cipher.
/// CTR mode is symmetric — encrypt and decrypt are the same operation.
pub const AesCtr = struct {
    key: [32]u8,
    /// Cached expanded key schedule (avoids re-computing on every apply())
    enc_ctx: EncCtx,
    /// Current counter value (big-endian u128)
    ctr: u128,
    /// Buffered keystream block
    buffer: [16]u8 = undefined,
    /// How many bytes remain in current keystream block
    buffer_pos: u8 = 16, // start exhausted so first call generates

    /// Expanded AES-256 encryption context type (backend-independent)
    const EncCtx = @TypeOf(Aes256.initEnc([_]u8{0} ** 32));

    pub fn init(key: *const [32]u8, iv: u128) AesCtr {
        return .{
            .key = key.*,
            .enc_ctx = Aes256.initEnc(key.*),
            .ctr = iv,
        };
    }

    pub fn initFromSlices(key: []const u8, iv: []const u8) !AesCtr {
        if (key.len != 32) return error.InvalidKeyLength;
        if (iv.len != 16) return error.InvalidIvLength;
        const k: *const [32]u8 = key[0..32];
        const iv_val = std.mem.readInt(u128, iv[0..16], .big);
        return init(k, iv_val);
    }

    /// Apply keystream to data in-place (encrypt or decrypt).
    pub fn apply(self: *AesCtr, data: []u8) void {
        var i: usize = 0;

        while (i < data.len) {
            if (self.buffer_pos >= 16) {
                // Generate new keystream block
                var ctr_bytes: [16]u8 = undefined;
                std.mem.writeInt(u128, &ctr_bytes, self.ctr, .big);
                self.enc_ctx.encrypt(&self.buffer, &ctr_bytes);
                self.ctr +%= 1;
                self.buffer_pos = 0;
            }

            const available = @as(usize, 16 - self.buffer_pos);
            const remaining = data.len - i;
            const take = @min(available, remaining);

            for (0..take) |j| {
                data[i + j] ^= self.buffer[self.buffer_pos + j];
            }

            self.buffer_pos += @intCast(take);
            i += take;
        }
    }

    /// Encrypt/decrypt into a new buffer.
    pub fn process(self: *AesCtr, allocator: std.mem.Allocator, data: []const u8) ![]u8 {
        const result = try allocator.alloc(u8, data.len);
        @memcpy(result, data);
        self.apply(result);
        return result;
    }

    /// Securely wipe key material.
    pub fn wipe(self: *AesCtr) void {
        std.crypto.secureZero(u8, &self.key);
        std.crypto.secureZero(u8, &self.buffer);
        self.ctr = 0;
        // Wipe expanded key schedule
        std.crypto.secureZero(u8, std.mem.asBytes(&self.enc_ctx));
    }
};

// ============= AES-256-CBC =============

/// AES-256-CBC cipher with proper chaining.
/// Unlike CTR, CBC is NOT symmetric.
pub const AesCbc = struct {
    key: [32]u8,
    iv: [16]u8,

    const block_size = 16;

    pub fn init(key: *const [32]u8, iv: *const [16]u8) AesCbc {
        return .{
            .key = key.*,
            .iv = iv.*,
        };
    }

    fn xorBlocks(a: *const [16]u8, b: *const [16]u8) [16]u8 {
        var result: [16]u8 = undefined;
        for (0..16) |i| {
            result[i] = a[i] ^ b[i];
        }
        return result;
    }

    /// Encrypt data in-place. Data length must be a multiple of 16.
    /// IV is updated after each call to support chaining across multiple calls.
    pub fn encryptInPlace(self: *AesCbc, data: []u8) !void {
        if (data.len % block_size != 0) return error.UnalignedData;
        if (data.len == 0) return;

        const ctx = Aes256.initEnc(self.key);
        var prev: [16]u8 = self.iv;

        var offset: usize = 0;
        while (offset < data.len) : (offset += block_size) {
            const block: *[16]u8 = data[offset..][0..16];
            // XOR plaintext with previous ciphertext
            for (0..16) |j| {
                block[j] ^= prev[j];
            }
            // Encrypt
            var encrypted: [16]u8 = undefined;
            ctx.encrypt(&encrypted, block);
            block.* = encrypted;
            prev = encrypted;
        }

        // Persist IV for chaining across calls
        self.iv = prev;
    }

    /// Decrypt data in-place. Data length must be a multiple of 16.
    /// IV is updated after each call to support chaining across multiple calls.
    pub fn decryptInPlace(self: *AesCbc, data: []u8) !void {
        if (data.len % block_size != 0) return error.UnalignedData;
        if (data.len == 0) return;

        const ctx = Aes256.initDec(self.key);
        var prev: [16]u8 = self.iv;

        var offset: usize = 0;
        while (offset < data.len) : (offset += block_size) {
            const block: *[16]u8 = data[offset..][0..16];
            const saved = block.*;
            // Decrypt
            var decrypted: [16]u8 = undefined;
            ctx.decrypt(&decrypted, block);
            block.* = decrypted;
            // XOR with previous ciphertext
            for (0..16) |j| {
                block[j] ^= prev[j];
            }
            prev = saved;
        }

        // Persist IV for chaining across calls
        self.iv = prev;
    }

    pub fn wipe(self: *AesCbc) void {
        std.crypto.secureZero(u8, &self.key);
        std.crypto.secureZero(u8, &self.iv);
    }
};

// ============= Hash Functions =============

/// SHA-256
pub fn sha256(data: []const u8) [32]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update(data);
    return h.finalResult();
}

/// SHA-256 HMAC
pub fn sha256Hmac(key: []const u8, data: []const u8) [32]u8 {
    const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
    var mac: [32]u8 = undefined;
    HmacSha256.create(&mac, data, key);
    return mac;
}

/// SHA-1 — protocol-required by Telegram Middle Proxy KDF.
pub fn sha1(data: []const u8) [20]u8 {
    var h = std.crypto.hash.Sha1.init(.{});
    h.update(data);
    return h.finalResult();
}

/// MD5 — protocol-required by Telegram Middle Proxy KDF.
pub fn md5(data: []const u8) [16]u8 {
    var h = std.crypto.hash.Md5.init(.{});
    h.update(data);
    return h.finalResult();
}

// ============= Secure Random =============

/// Fill buffer with cryptographically secure random bytes.
pub fn randomBytes(buf: []u8) void {
    std.crypto.random.bytes(buf);
}

/// Generate a random integer in [0, max).
pub fn randomRange(comptime T: type, max: T) T {
    if (max == 0) return 0;
    return std.crypto.random.intRangeLessThan(T, 0, max);
}

// ============= Tests =============

test "AesCtr roundtrip" {
    const key = [_]u8{0} ** 32;
    const iv: u128 = 12345;
    const original = "Hello, MTProto!";

    var enc = AesCtr.init(&key, iv);
    var buf: [original.len]u8 = undefined;
    @memcpy(&buf, original);
    enc.apply(&buf);

    // encrypted should differ
    try std.testing.expect(!std.mem.eql(u8, &buf, original));

    var dec = AesCtr.init(&key, iv);
    dec.apply(&buf);

    try std.testing.expectEqualSlices(u8, original, &buf);
}

test "AesCtr in-place symmetry" {
    const key = [_]u8{0x42} ** 32;
    const iv: u128 = 999;
    const original = "Test data for in-place encryption";

    var data: [original.len]u8 = undefined;
    @memcpy(&data, original);

    var c1 = AesCtr.init(&key, iv);
    c1.apply(&data);
    try std.testing.expect(!std.mem.eql(u8, &data, original));

    var c2 = AesCtr.init(&key, iv);
    c2.apply(&data);
    try std.testing.expectEqualSlices(u8, original, &data);
}

test "AesCbc roundtrip" {
    const key = [_]u8{0x12} ** 32;
    const iv = [_]u8{0x34} ** 16;

    var plaintext: [48]u8 = undefined;
    for (0..48) |i| {
        plaintext[i] = @intCast(i);
    }
    const original = plaintext;

    var cbc = AesCbc.init(&key, &iv);
    try cbc.encryptInPlace(&plaintext);
    try std.testing.expect(!std.mem.eql(u8, &plaintext, &original));

    // Reset IV for decryption (since encryptInPlace updated it)
    cbc.iv = iv;
    try cbc.decryptInPlace(&plaintext);
    try std.testing.expectEqualSlices(u8, &original, &plaintext);
}

test "AesCbc chaining works" {
    const key = [_]u8{0x42} ** 32;
    const iv = [_]u8{0x00} ** 16;
    var plaintext = [_]u8{0xAA} ** 32;

    var cbc = AesCbc.init(&key, &iv);
    try cbc.encryptInPlace(&plaintext);

    // With CBC chaining, identical plaintext blocks should produce different ciphertext blocks
    try std.testing.expect(!std.mem.eql(u8, plaintext[0..16], plaintext[16..32]));
}

test "sha256 basic" {
    const hash = sha256("");
    // SHA-256 of empty string
    const expected = [_]u8{
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
    };
    try std.testing.expectEqualSlices(u8, &expected, &hash);
}

test "sha256Hmac basic" {
    const mac = sha256Hmac("key", "The quick brown fox jumps over the lazy dog");
    // Known HMAC-SHA256 test vector
    const expected = [_]u8{
        0xf7, 0xbc, 0x83, 0xf4, 0x30, 0x53, 0x84, 0x24,
        0xb1, 0x32, 0x98, 0xe6, 0xaa, 0x6f, 0xb1, 0x43,
        0xef, 0x4d, 0x59, 0xa1, 0x49, 0x46, 0x17, 0x59,
        0x97, 0x47, 0x9d, 0xbc, 0x2d, 0x1a, 0x3c, 0xd8,
    };
    try std.testing.expectEqualSlices(u8, &expected, &mac);
}
```

--- src/protocol/constants.zig ---
```zig
//! Protocol constants and datacenter addresses for MTProto proxy.

const std = @import("std");

// ============= Telegram Datacenters =============

pub const tg_datacenter_port: u16 = 443;

pub const tg_datacenters_v4 = [5]std.net.Address{
    std.net.Address.initIp4(.{ 149, 154, 175, 50 }, tg_datacenter_port),
    std.net.Address.initIp4(.{ 149, 154, 167, 51 }, tg_datacenter_port),
    std.net.Address.initIp4(.{ 149, 154, 175, 100 }, tg_datacenter_port),
    std.net.Address.initIp4(.{ 149, 154, 167, 91 }, tg_datacenter_port),
    std.net.Address.initIp4(.{ 149, 154, 171, 5 }, tg_datacenter_port),
};

pub const tg_datacenters_v6 = [5]std.net.Address{
    std.net.Address.initIp6(.{ 0x20, 0x01, 0x0b, 0x28, 0xf2, 0x3d, 0xf0, 0x01, 0, 0, 0, 0, 0, 0, 0, 0x0a }, tg_datacenter_port, 0, 0),
    std.net.Address.initIp6(.{ 0x20, 0x01, 0x06, 0x7c, 0x04, 0xe8, 0xf0, 0x02, 0, 0, 0, 0, 0, 0, 0, 0x0a }, tg_datacenter_port, 0, 0),
    std.net.Address.initIp6(.{ 0x20, 0x01, 0x0b, 0x28, 0xf2, 0x3d, 0xf0, 0x03, 0, 0, 0, 0, 0, 0, 0, 0x0a }, tg_datacenter_port, 0, 0),
    std.net.Address.initIp6(.{ 0x20, 0x01, 0x06, 0x7c, 0x04, 0xe8, 0xf0, 0x04, 0, 0, 0, 0, 0, 0, 0, 0x0a }, tg_datacenter_port, 0, 0),
    std.net.Address.initIp6(.{ 0x20, 0x01, 0x0b, 0x28, 0xf2, 0x3f, 0xf0, 0x05, 0, 0, 0, 0, 0, 0, 0, 0x0a }, tg_datacenter_port, 0, 0),
};

// ============= Protocol Tags =============

pub const ProtoTag = enum(u32) {
    abridged = 0xefefefef,
    intermediate = 0xeeeeeeee,
    secure = 0xdddddddd,

    pub fn fromBytes(bytes: [4]u8) ?ProtoTag {
        const val = std.mem.readInt(u32, &bytes, .little);
        return std.meta.intToEnum(ProtoTag, val) catch null;
    }

    pub fn toBytes(self: ProtoTag) [4]u8 {
        var buf: [4]u8 = undefined;
        std.mem.writeInt(u32, &buf, @intFromEnum(self), .little);
        return buf;
    }
};

// ============= Handshake Layout =============

/// Bytes to skip at the start of handshake
pub const skip_len: usize = 8;
/// Pre-key length (before hashing with secret)
pub const prekey_len: usize = 32;
/// AES key length
pub const key_len: usize = 32;
/// AES IV length
pub const iv_len: usize = 16;
/// Total handshake length
pub const handshake_len: usize = 64;
/// Position of protocol tag in decrypted handshake
pub const proto_tag_pos: usize = 56;
/// Position of datacenter index
pub const dc_idx_pos: usize = 60;

// ============= TLS Constants =============

/// TLS 1.3 version bytes (in record layer, 0x0303 = TLS 1.2 compat)
pub const tls_version = [2]u8{ 0x03, 0x03 };
/// TLS record type: Handshake
pub const tls_record_handshake: u8 = 0x16;
/// TLS record type: Change Cipher Spec
pub const tls_record_change_cipher: u8 = 0x14;
/// TLS record type: Application Data
pub const tls_record_application: u8 = 0x17;
/// TLS record type: Alert
pub const tls_record_alert: u8 = 0x15;

/// Maximum TLS plaintext record payload (RFC 8446 §5.1)
pub const max_tls_plaintext_size: usize = 16_384;
/// Maximum TLS ciphertext record payload (RFC 8446 §5.2: 2^14 + 256)
pub const max_tls_ciphertext_size: usize = 16_384 + 256;
/// Structural minimum for a valid TLS 1.3 ClientHello with SNI
pub const min_tls_client_hello_size: usize = 100;

// ============= Message Limits =============

pub const min_msg_len: usize = 12;
pub const max_msg_len: usize = 1 << 24; // 16 MB

// ============= Buffer Sizes =============

pub const default_buffer_size: usize = 16384;

// ============= TLS Handshake Constants =============

pub const tls_digest_len: usize = 32;
pub const tls_digest_pos: usize = 11;
pub const tls_digest_half_len: usize = 16;

/// Time skew limits for anti-replay (seconds)
pub const time_skew_min: i64 = -2 * 60;
pub const time_skew_max: i64 = 2 * 60;

// ============= Reserved Nonce Patterns =============

pub const reserved_nonce_first_bytes = [_]u8{0xef};

pub const reserved_nonce_beginnings = [_][4]u8{
    .{ 0x48, 0x45, 0x41, 0x44 }, // HEAD
    .{ 0x50, 0x4F, 0x53, 0x54 }, // POST
    .{ 0x47, 0x45, 0x54, 0x20 }, // GET
    .{ 0x4F, 0x50, 0x54, 0x49 }, // OPTI (OPTIONS)
    .{ 0x50, 0x55, 0x54, 0x20 }, // PUT
    .{ 0xee, 0xee, 0xee, 0xee }, // Intermediate
    .{ 0xdd, 0xdd, 0xdd, 0xdd }, // Secure
    .{ 0x16, 0x03, 0x01, 0x02 }, // TLS
};

pub const reserved_nonce_continues = [_][4]u8{
    .{ 0x00, 0x00, 0x00, 0x00 },
};

test "proto tag roundtrip" {
    inline for (.{ ProtoTag.abridged, ProtoTag.intermediate, ProtoTag.secure }) |tag| {
        const bytes = tag.toBytes();
        const parsed = ProtoTag.fromBytes(bytes);
        try std.testing.expectEqual(tag, parsed.?);
    }
}

test "invalid proto tag" {
    try std.testing.expect(ProtoTag.fromBytes(.{ 0, 0, 0, 0 }) == null);
    try std.testing.expect(ProtoTag.fromBytes(.{ 0xff, 0xff, 0xff, 0xff }) == null);
}
```

--- src/protocol/tls.zig ---
```zig
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
```

--- src/protocol/obfuscation.zig ---
```zig
//! MTProto Obfuscation — handshake parsing and key derivation.
//!
//! The obfuscation layer uses AES-256-CTR to encrypt the connection
//! between client and proxy. Key material is derived from the 64-byte
//! handshake and the user's secret.

const std = @import("std");
const constants = @import("constants.zig");
const crypto = @import("../crypto/crypto.zig");

/// Obfuscation parameters extracted from a client handshake.
pub const ObfuscationParams = struct {
    /// Key for decrypting client -> proxy traffic
    decrypt_key: [32]u8,
    /// IV for decrypting client -> proxy traffic
    decrypt_iv: u128,
    /// Key for encrypting proxy -> client traffic
    encrypt_key: [32]u8,
    /// IV for encrypting proxy -> client traffic
    encrypt_iv: u128,
    /// Protocol tag (abridged/intermediate/secure)
    proto_tag: constants.ProtoTag,
    /// Datacenter index (signed: negative = test DC)
    dc_idx: i16,

    /// Try to parse obfuscation params from a 64-byte handshake.
    /// Tries each secret; returns params + matched username on success.
    pub fn fromHandshake(
        handshake: *const [constants.handshake_len]u8,
        secrets: []const UserSecret,
    ) ?struct { params: ObfuscationParams, user: []const u8 } {
        // Extract decrypt prekey (bytes 8..40) and IV (bytes 40..56)
        const dec_prekey_iv = handshake[constants.skip_len .. constants.skip_len + constants.prekey_len + constants.iv_len];
        const dec_prekey = dec_prekey_iv[0..constants.prekey_len];
        const dec_iv_bytes: *const [constants.iv_len]u8 = dec_prekey_iv[constants.prekey_len..][0..constants.iv_len];

        // Encrypt direction: reversed prekey+IV
        var enc_prekey_iv: [constants.prekey_len + constants.iv_len]u8 = undefined;
        for (0..dec_prekey_iv.len) |i| {
            enc_prekey_iv[i] = dec_prekey_iv[dec_prekey_iv.len - 1 - i];
        }
        const enc_prekey = enc_prekey_iv[0..constants.prekey_len];
        const enc_iv_bytes: *const [constants.iv_len]u8 = enc_prekey_iv[constants.prekey_len..][0..constants.iv_len];

        for (secrets) |entry| {
            // Derive decrypt key: SHA256(prekey || secret)
            var dec_key_input: [constants.prekey_len + 16]u8 = undefined;
            @memcpy(dec_key_input[0..constants.prekey_len], dec_prekey);
            @memcpy(dec_key_input[constants.prekey_len..], &entry.secret);
            const decrypt_key = crypto.sha256(&dec_key_input);

            const decrypt_iv = std.mem.readInt(u128, dec_iv_bytes, .big);

            // Decrypt the handshake to check proto tag
            var decryptor = crypto.AesCtr.init(&decrypt_key, decrypt_iv);
            defer decryptor.wipe();
            var decrypted: [constants.handshake_len]u8 = undefined;
            @memcpy(&decrypted, handshake);
            decryptor.apply(&decrypted);

            // Check proto tag at offset 56
            const tag_bytes: [4]u8 = decrypted[constants.proto_tag_pos..][0..4].*;
            const proto_tag = constants.ProtoTag.fromBytes(tag_bytes) orelse continue;

            // Extract DC index at offset 60
            const dc_idx = std.mem.readInt(i16, decrypted[constants.dc_idx_pos..][0..2], .little);

            // Derive encrypt key
            var enc_key_input: [constants.prekey_len + 16]u8 = undefined;
            @memcpy(enc_key_input[0..constants.prekey_len], enc_prekey);
            @memcpy(enc_key_input[constants.prekey_len..], &entry.secret);
            const encrypt_key = crypto.sha256(&enc_key_input);
            const encrypt_iv = std.mem.readInt(u128, enc_iv_bytes, .big);

            return .{
                .params = .{
                    .decrypt_key = decrypt_key,
                    .decrypt_iv = decrypt_iv,
                    .encrypt_key = encrypt_key,
                    .encrypt_iv = encrypt_iv,
                    .proto_tag = proto_tag,
                    .dc_idx = dc_idx,
                },
                .user = entry.name,
            };
        }

        return null;
    }

    /// Create AES-CTR decryptor for client -> proxy direction.
    pub fn createDecryptor(self: *const ObfuscationParams) crypto.AesCtr {
        return crypto.AesCtr.init(&self.decrypt_key, self.decrypt_iv);
    }

    /// Create AES-CTR encryptor for proxy -> client direction.
    pub fn createEncryptor(self: *const ObfuscationParams) crypto.AesCtr {
        return crypto.AesCtr.init(&self.encrypt_key, self.encrypt_iv);
    }

    /// Securely wipe key material.
    pub fn wipe(self: *ObfuscationParams) void {
        @memset(&self.decrypt_key, 0);
        self.decrypt_iv = 0;
        @memset(&self.encrypt_key, 0);
        self.encrypt_iv = 0;
    }
};

/// A user's name and decoded 16-byte secret.
pub const UserSecret = struct {
    name: []const u8,
    secret: [16]u8,
};

/// Check if a 64-byte nonce is valid (doesn't match reserved patterns).
pub fn isValidNonce(nonce: *const [constants.handshake_len]u8) bool {
    // Check first byte
    for (constants.reserved_nonce_first_bytes) |b| {
        if (nonce[0] == b) return false;
    }

    // Check first 4 bytes
    const first_four: [4]u8 = nonce[0..4].*;
    for (constants.reserved_nonce_beginnings) |reserved| {
        if (std.mem.eql(u8, &first_four, &reserved)) return false;
    }

    // Check bytes 4..8
    const continue_four: [4]u8 = nonce[4..8].*;
    for (constants.reserved_nonce_continues) |reserved| {
        if (std.mem.eql(u8, &continue_four, &reserved)) return false;
    }

    return true;
}

/// Generate a valid random 64-byte nonce.
pub fn generateNonce() [constants.handshake_len]u8 {
    while (true) {
        var nonce: [constants.handshake_len]u8 = undefined;
        crypto.randomBytes(&nonce);
        if (isValidNonce(&nonce)) return nonce;
    }
}

/// Prepare nonce for sending to Telegram DC.
/// Sets proto tag at offset 56 and optionally embeds reversed key+IV.
pub fn prepareTgNonce(
    nonce: *[constants.handshake_len]u8,
    proto_tag: constants.ProtoTag,
    enc_key_iv: ?[]const u8,
) void {
    const tag_bytes = proto_tag.toBytes();
    @memcpy(nonce[constants.proto_tag_pos..][0..4], &tag_bytes);

    if (enc_key_iv) |key_iv| {
        // Reverse the key+IV into the nonce
        var reversed: [constants.key_len + constants.iv_len]u8 = undefined;
        for (0..key_iv.len) |i| {
            reversed[i] = key_iv[key_iv.len - 1 - i];
        }
        @memcpy(nonce[constants.skip_len..][0 .. constants.key_len + constants.iv_len], &reversed);
    }
}

// ============= Tests =============

test "isValidNonce" {
    // Valid nonce
    var valid = [_]u8{0x42} ** constants.handshake_len;
    valid[4] = 1;
    valid[5] = 2;
    valid[6] = 3;
    valid[7] = 4;
    try std.testing.expect(isValidNonce(&valid));

    // Invalid: starts with 0xef
    var invalid1 = [_]u8{0x00} ** constants.handshake_len;
    invalid1[0] = 0xef;
    try std.testing.expect(!isValidNonce(&invalid1));

    // Invalid: starts with "HEAD"
    var invalid2 = [_]u8{0x00} ** constants.handshake_len;
    invalid2[0] = 'H';
    invalid2[1] = 'E';
    invalid2[2] = 'A';
    invalid2[3] = 'D';
    try std.testing.expect(!isValidNonce(&invalid2));

    // Invalid: bytes 4..8 are all zeros
    var invalid3 = [_]u8{0x42} ** constants.handshake_len;
    invalid3[4] = 0;
    invalid3[5] = 0;
    invalid3[6] = 0;
    invalid3[7] = 0;
    try std.testing.expect(!isValidNonce(&invalid3));
}

test "generateNonce produces valid nonces" {
    const nonce = generateNonce();
    try std.testing.expect(isValidNonce(&nonce));
    try std.testing.expectEqual(@as(usize, constants.handshake_len), nonce.len);
}
```

--- src/proxy/proxy.zig ---
```zig
//! Proxy core — TCP listener, client handler, DC connection, bidirectional relay.
//!
//! Design: ProxyState is passed by reference (DI) — no global mutable state.

const std = @import("std");
const net = std.net;
const posix = std.posix;
const constants = @import("../protocol/constants.zig");
const crypto = @import("../crypto/crypto.zig");
const obfuscation = @import("../protocol/obfuscation.zig");
const tls = @import("../protocol/tls.zig");
const Config = @import("../config.zig").Config;

const log = std.log.scoped(.proxy);

/// TLS record header size
const tls_header_len = 5;
/// Maximum TLS payload we'll write in one record
const max_tls_payload = constants.max_tls_ciphertext_size;
/// Idle timeout for relay poll() and write backpressure (5 minutes)
const relay_timeout_ms = 5 * 60 * 1000;
/// Idle Phase: wait for first byte from client (5 minutes).
/// Mobile clients (iOS Telegram) aggressively pre-warm TCP connection pools,
/// opening 2-5 idle sockets that sit empty until the app needs to send data.
/// A short timeout here kills these pooled connections, causing iOS to mark
/// the proxy as unstable and enter long reconnect cycles.
const idle_timeout_ms: i32 = 5 * 60 * 1000;
/// Active Phase: once data starts arriving, apply tight SO_RCVTIMEO
/// to protect against Slowloris-style attacks (seconds).
const active_timeout_sec: u32 = 10;

// ============= Dynamic Record Sizing (DRS) =============

/// Mimics real browser TLS behavior: start with small records (like Chrome/Firefox
/// initial record sizing for latency), then ramp up to full 16384-byte records
/// for bulk throughput.
///
/// Real browsers use small initial records (~1369 bytes = MSS - TCP/IP/TLS overhead)
/// to avoid head-of-line blocking on the first few roundtrips, then switch to
/// max-size records once the connection is established.
const DynamicRecordSizer = struct {
    /// Current maximum payload per TLS record
    current_size: usize,
    /// Number of records sent so far
    records_sent: u32,
    /// Total bytes sent (for ramp threshold)
    bytes_sent: u64,

    /// Initial record size: MSS(1460) - IP(20) - TCP(20) - TLS_header(5) - AEAD(16) - options(~30) ≈ 1369
    const initial_size: usize = 1369;
    /// Full TLS plaintext record size
    const full_size: usize = constants.max_tls_plaintext_size; // 16384
    /// Ramp up after this many initial records
    const ramp_record_threshold: u32 = 8;
    /// Or ramp up after this many total bytes
    const ramp_byte_threshold: u64 = 128 * 1024;

    fn init() DynamicRecordSizer {
        return .{
            .current_size = initial_size,
            .records_sent = 0,
            .bytes_sent = 0,
        };
    }

    /// Get the max payload size for the next TLS record.
    fn nextRecordSize(self: *DynamicRecordSizer) usize {
        return self.current_size;
    }

    /// Report that a record was sent. Handles ramp-up logic.
    fn recordSent(self: *DynamicRecordSizer, payload_len: usize) void {
        self.records_sent += 1;
        self.bytes_sent += payload_len;

        if (self.current_size < full_size) {
            if (self.records_sent >= ramp_record_threshold or
                self.bytes_sent >= ramp_byte_threshold)
            {
                self.current_size = full_size;
            }
        }
    }
};

/// Shared proxy state — passed by reference, no globals.
pub const ProxyState = struct {
    allocator: std.mem.Allocator,
    config: Config,
    /// Cached user secrets for handshake validation
    user_secrets: []const obfuscation.UserSecret,
    /// Connection counter for logging
    connection_count: std.atomic.Value(u64),
    /// Active concurrent connections (for overload protection)
    active_connections: std.atomic.Value(u32),

    /// Maximum concurrent connections before rejecting new ones.
    /// Prevents thread exhaustion under load.
    const max_connections: u32 = 8192;

    pub fn init(allocator: std.mem.Allocator, cfg: Config) ProxyState {
        var secrets: std.ArrayList(obfuscation.UserSecret) = .empty;
        var it = @constCast(&cfg.users).iterator();
        while (it.next()) |entry| {
            secrets.append(allocator, .{
                .name = entry.key_ptr.*,
                .secret = entry.value_ptr.*,
            }) catch continue;
        }

        return .{
            .allocator = allocator,
            .config = cfg,
            .user_secrets = secrets.toOwnedSlice(allocator) catch &.{},
            .connection_count = std.atomic.Value(u64).init(0),
            .active_connections = std.atomic.Value(u32).init(0),
        };
    }

    pub fn deinit(self: *ProxyState) void {
        self.allocator.free(self.user_secrets);
    }

    /// Start the proxy server.
    pub fn run(self: *ProxyState) !void {
        const address = net.Address.initIp4(.{ 0, 0, 0, 0 }, self.config.port);
        var server = try address.listen(.{
            .reuse_address = true,
        });
        defer server.deinit();

        log.info("Listening on 0.0.0.0:{d}", .{self.config.port});

        while (true) {
            const conn = server.accept() catch |err| {
                log.err("Accept error: {any}", .{err});
                continue;
            };

            const conn_id = self.connection_count.fetchAdd(1, .monotonic);

            // Overload protection: reject if too many concurrent connections
            const active = self.active_connections.load(.monotonic);
            if (active >= max_connections) {
                log.warn("[{d}] Connection rejected: at capacity ({d}/{d})", .{ conn_id, active, max_connections });
                conn.stream.close();
                continue;
            }

            const thread = std.Thread.spawn(.{
                // Proxy threads just shuffle bytes between sockets + AES-CTR (no deep recursion).
                // 128 KB is plenty. Default 8-16 MB per thread would exhaust memory with thousands
                // of idle iOS pool connections (e.g. 4000 threads * 8 MB = 32 GB virtual memory).
                .stack_size = 128 * 1024,
            }, handleConnection, .{ self, conn.stream, conn.address, conn_id }) catch |err| {
                log.err("[{d}] Spawn error: {any}", .{ conn_id, err });
                conn.stream.close();
                continue;
            };
            thread.detach();
        }
    }
};

/// Handle a single client connection.
fn handleConnection(
    state: *ProxyState,
    client_stream: net.Stream,
    peer_addr: net.Address,
    conn_id: u64,
) void {
    defer client_stream.close();

    // Track active connections for overload protection
    _ = state.active_connections.fetchAdd(1, .monotonic);
    defer _ = state.active_connections.fetchSub(1, .monotonic);

    // Format peer IP for logging
    var addr_buf: [64]u8 = undefined;
    const peer_str = formatAddress(peer_addr, &addr_buf);

    handleConnectionInner(state, client_stream, peer_str, conn_id) catch |err| {
        // Idle pool closure is normal — mobile clients pre-warm connections
        // that may never send data. Don't pollute logs.
        if (err == error.IdleConnectionClosed) {
            log.debug("[{d}] ({s}) Closed idle pooled connection", .{ conn_id, peer_str });
            return;
        }
        // WouldBlock during handshake = Slowloris or extreme lag
        if (err == error.WouldBlock) {
            log.warn("[{d}] ({s}) Handshake timeout (Slowloris/lag)", .{ conn_id, peer_str });
            return;
        }
        log.err("[{d}] ({s}) Connection error: {any}", .{ conn_id, peer_str, err });
    };
}

fn handleConnectionInner(
    state: *ProxyState,
    client_stream: net.Stream,
    peer_str: []const u8,
    conn_id: u64,
) !void {
    // === Two-Stage Timeout (Split Timeout) ===
    //
    // Stage 1 — Idle Phase: wait for the first byte with a long timeout.
    // Mobile clients (iOS Telegram) pre-warm TCP connection pools by opening
    // several idle sockets. Killing them too early causes reconnect storms.
    // A sleeping thread in poll() consumes zero CPU.
    //
    // Stage 2 — Active Phase: once data arrives, apply a tight SO_RCVTIMEO
    // to catch real Slowloris attacks (slow-drip partial sends).

    const fd = client_stream.handle;

    // Stage 1: wait for first byte (idle pool phase)
    var poll_fds = [_]posix.pollfd{
        .{ .fd = fd, .events = posix.POLL.IN, .revents = 0 },
    };
    const ready = posix.poll(&poll_fds, idle_timeout_ms) catch return error.ConnectionReset;
    if (ready == 0) {
        // Client held the socket open but never sent data — normal pool behavior.
        return error.IdleConnectionClosed;
    }
    // Client closed the pooled socket from their side (FIN/RST)
    if (poll_fds[0].revents & (posix.POLL.ERR | posix.POLL.HUP) != 0) {
        return error.IdleConnectionClosed;
    }

    // Stage 2: data is coming — apply tight recv timeout (anti-Slowloris)
    setRecvTimeout(fd, active_timeout_sec);

    // Read first 5 bytes to determine TLS vs direct
    var first_bytes: [5]u8 = undefined;
    const n = try readExact(client_stream, &first_bytes);
    if (n < 5) return;

    if (!tls.isTlsHandshake(&first_bytes)) {
        log.debug("[{d}] ({s}) Non-TLS connection, dropping. First bytes: {x:0>2}", .{ conn_id, peer_str, first_bytes });
        return;
    }

    // TLS path: read full ClientHello
    const record_len = std.mem.readInt(u16, first_bytes[3..5], .big);
    if (record_len < constants.min_tls_client_hello_size or record_len > constants.max_tls_plaintext_size) {
        return;
    }

    var client_hello_buf: [5 + constants.max_tls_plaintext_size]u8 = undefined;
    @memcpy(client_hello_buf[0..5], &first_bytes);
    const body_n = try readExact(client_stream, client_hello_buf[5..][0..record_len]);
    if (body_n < record_len) return;

    const client_hello = client_hello_buf[0 .. 5 + record_len];

    // Validate TLS handshake against secrets
    const validation = try tls.validateTlsHandshake(
        state.allocator,
        client_hello,
        state.user_secrets,
        false,
    );

    if (validation == null) {
        log.debug("[{d}] ({s}) TLS auth failed", .{ conn_id, peer_str });
        return;
    }

    const v = validation.?;
    log.info("[{d}] ({s}) TLS auth OK: user={s}", .{ conn_id, peer_str, v.user });

    // Send ServerHello response
    const server_hello = try tls.buildServerHello(
        state.allocator,
        &v.secret,
        &v.digest,
        v.session_id,
    );
    defer state.allocator.free(server_hello);

    _ = try client_stream.write(server_hello);

    // Read 64-byte MTProto handshake (wrapped in TLS Application Data)
    // The client may send a Change Cipher Spec (CCS) record first — skip it.
    var tls_header: [5]u8 = undefined;
    while (true) {
        if (try readExact(client_stream, &tls_header) < 5) return;

        if (tls_header[0] == constants.tls_record_application) break;

        if (tls_header[0] == constants.tls_record_change_cipher) {
            // Read and discard the CCS body
            const ccs_len = std.mem.readInt(u16, tls_header[3..5], .big);
            if (ccs_len > 256) return;
            var ccs_buf: [256]u8 = undefined;
            if (try readExact(client_stream, ccs_buf[0..ccs_len]) < ccs_len) return;
            continue;
        }

        log.debug("[{d}] ({s}) Unexpected TLS record type after ServerHello: 0x{x:0>2}", .{ conn_id, peer_str, tls_header[0] });
        return;
    }

    const payload_len = std.mem.readInt(u16, tls_header[3..5], .big);
    if (payload_len < constants.handshake_len) return;
    if (payload_len > constants.max_tls_ciphertext_size) return; // Fix #4: bounds check against buffer size

    var payload_buf: [constants.max_tls_ciphertext_size]u8 = undefined;
    if (try readExact(client_stream, payload_buf[0..payload_len]) < payload_len) return;

    const handshake: *const [constants.handshake_len]u8 = payload_buf[0..constants.handshake_len];

    // Parse obfuscation params
    const result = obfuscation.ObfuscationParams.fromHandshake(handshake, state.user_secrets) orelse {
        log.debug("[{d}] ({s}) MTProto handshake failed for user {s}", .{ conn_id, peer_str, v.user });
        return;
    };

    var params = result.params;
    defer params.wipe();

    log.info("[{d}] ({s}) MTProto OK: user={s} dc={d} proto={any}", .{
        conn_id,
        peer_str,
        result.user,
        params.dc_idx,
        params.proto_tag,
    });

    // Diagnostic: log client cipher details
    log.info("[{d}] ({s}) Client dec_iv=0x{x:0>32} enc_iv=0x{x:0>32}", .{
        conn_id,                      peer_str,
        @as(u128, params.decrypt_iv), @as(u128, params.encrypt_iv),
    });

    // Resolve DC address — use @abs() to avoid overflow when dc_idx == minInt(i16)
    const dc_idx: usize = if (params.dc_idx > 0)
        @as(usize, @intCast(params.dc_idx)) - 1
    else if (params.dc_idx < 0)
        @as(usize, @abs(params.dc_idx)) - 1
    else
        return;

    if (dc_idx >= constants.tg_datacenters_v4.len) return;

    const dc_addr = constants.tg_datacenters_v4[dc_idx];
    log.info("[{d}] ({s}) Connecting to DC {d}", .{ conn_id, peer_str, params.dc_idx });

    const dc_stream = net.tcpConnectToAddress(dc_addr) catch |err| {
        log.err("[{d}] ({s}) DC connect failed: {any}", .{ conn_id, peer_str, err });
        return;
    };
    defer dc_stream.close();

    // Generate and send obfuscated handshake to Telegram DC
    var tg_nonce = obfuscation.generateNonce();
    // Set proto tag and DC index in the nonce
    const tag_bytes = params.proto_tag.toBytes();
    @memcpy(tg_nonce[constants.proto_tag_pos..][0..4], &tag_bytes);
    std.mem.writeInt(i16, tg_nonce[constants.dc_idx_pos..][0..2], params.dc_idx, .little);

    // Derive TG crypto keys from nonce (raw key bytes, NOT SHA256)
    const tg_enc_key_iv = tg_nonce[constants.skip_len..][0 .. constants.key_len + constants.iv_len];
    var tg_enc_key: [constants.key_len]u8 = tg_enc_key_iv[0..constants.key_len].*;
    var tg_enc_iv_bytes: [constants.iv_len]u8 = tg_enc_key_iv[constants.key_len..][0..constants.iv_len].*;
    const tg_enc_iv = std.mem.readInt(u128, &tg_enc_iv_bytes, .big);

    // Decrypt direction: reversed key+IV
    var tg_dec_key_iv: [constants.key_len + constants.iv_len]u8 = undefined;
    for (0..tg_enc_key_iv.len) |i| {
        tg_dec_key_iv[i] = tg_enc_key_iv[tg_enc_key_iv.len - 1 - i];
    }
    var tg_dec_key: [constants.key_len]u8 = tg_dec_key_iv[0..constants.key_len].*;
    const tg_dec_iv = std.mem.readInt(u128, tg_dec_key_iv[constants.key_len..][0..constants.iv_len], .big);

    // Encrypt the nonce: encrypt full nonce to advance counter, but only
    // replace bytes from proto_tag_pos onwards with ciphertext
    var tg_encryptor = crypto.AesCtr.init(&tg_enc_key, tg_enc_iv);
    defer tg_encryptor.wipe();
    var encrypted_nonce: [constants.handshake_len]u8 = undefined;
    @memcpy(&encrypted_nonce, &tg_nonce);
    tg_encryptor.apply(&encrypted_nonce);
    // Build final nonce: unencrypted prefix + encrypted suffix
    var nonce_to_send: [constants.handshake_len]u8 = undefined;
    @memcpy(nonce_to_send[0..constants.proto_tag_pos], tg_nonce[0..constants.proto_tag_pos]);
    @memcpy(nonce_to_send[constants.proto_tag_pos..], encrypted_nonce[constants.proto_tag_pos..]);

    _ = try dc_stream.write(&nonce_to_send);
    // tg_encryptor counter is now at position 4 (past 64 bytes), correct for subsequent data

    var tg_decryptor = crypto.AesCtr.init(&tg_dec_key, tg_dec_iv);
    defer tg_decryptor.wipe();

    // Wipe key material from stack
    @memset(&tg_enc_key, 0);
    @memset(&tg_enc_iv_bytes, 0);
    @memset(&tg_dec_key, 0);
    @memset(&tg_dec_key_iv, 0);

    log.info("[{d}] ({s}) Relaying traffic", .{ conn_id, peer_str });

    // Set both sockets to non-blocking to prevent deadlocks with poll().
    // The relay handlers already handle WouldBlock errors correctly.
    setNonBlocking(client_stream.handle);
    setNonBlocking(dc_stream.handle);

    // Create client-side crypto
    // client_decryptor: decrypt client→proxy traffic (C2S)
    // client_encryptor: encrypt proxy→client traffic (S2C)
    var client_decryptor = params.createDecryptor();
    var client_encryptor = params.createEncryptor();
    defer client_decryptor.wipe();
    defer client_encryptor.wipe();

    // CRITICAL: The client encrypted its 64-byte handshake with AES-CTR, advancing
    // its counter by 4 blocks (64 / 16 = 4). fromHandshake() used a temp decryptor
    // to verify the handshake then discarded it. Our fresh decryptor starts at
    // counter 0 — we must advance it by 4 to match the client's CTR state.
    client_decryptor.ctr +%= 4;

    // Fix #3: Handle pipelined data — Telegram clients send their first RPC request
    // immediately after the 64-byte handshake in the same TLS record. If we don't
    // forward these bytes, the client's first message is silently lost.
    if (payload_len > constants.handshake_len) {
        const pipelined = payload_buf[constants.handshake_len..payload_len];
        log.info("[{d}] ({s}) Pipelined {d}B after handshake", .{ conn_id, peer_str, pipelined.len });
        // Decrypt with client cipher, re-encrypt with DC cipher
        client_decryptor.apply(pipelined);
        tg_encryptor.apply(pipelined);
        try writeAll(dc_stream, pipelined);
    } else {
        log.info("[{d}] ({s}) No pipelined data after handshake", .{ conn_id, peer_str });
    }

    relayBidirectional(
        client_stream,
        dc_stream,
        &client_decryptor,
        &client_encryptor,
        &tg_encryptor,
        &tg_decryptor,
        conn_id,
    ) catch |err| {
        log.debug("[{d}] ({s}) Relay ended: {any}", .{ conn_id, peer_str, err });
    };
}

/// Bidirectional relay between client (TLS + AES-CTR) and Telegram DC (AES-CTR).
///
/// Data flow:
///   C2S: TLS record → unwrap → AES-CTR decrypt (client) → AES-CTR encrypt (DC) → DC
///   S2C: DC → AES-CTR decrypt (DC) → AES-CTR encrypt (client) → TLS record wrap → client
fn relayBidirectional(
    client: net.Stream,
    dc: net.Stream,
    client_decryptor: *crypto.AesCtr,
    client_encryptor: *crypto.AesCtr,
    tg_encryptor: *crypto.AesCtr,
    tg_decryptor: *crypto.AesCtr,
    conn_id: u64,
) !void {
    var fds = [2]posix.pollfd{
        .{ .fd = client.handle, .events = posix.POLL.IN, .revents = 0 },
        .{ .fd = dc.handle, .events = posix.POLL.IN, .revents = 0 },
    };

    // State for reading TLS records from client
    var tls_hdr_buf: [tls_header_len]u8 = undefined;
    var tls_hdr_pos: usize = 0;
    var tls_body_buf: [max_tls_payload]u8 = undefined;
    var tls_body_pos: usize = 0;
    var tls_body_len: usize = 0;

    // Dynamic Record Sizing for S2C TLS records
    var drs = DynamicRecordSizer.init();

    // Buffer for DC → client direction
    var dc_read_buf: [constants.default_buffer_size]u8 = undefined;

    // Byte counters for diagnostics
    var c2s_bytes: u64 = 0;
    var s2c_bytes: u64 = 0;
    var poll_iterations: u64 = 0;
    var no_progress_count: u32 = 0;

    while (true) {
        const ready = try posix.poll(&fds, relay_timeout_ms);
        if (ready == 0) {
            log.debug("[{d}] Relay: idle timeout (no data for 5 min), c2s={d} s2c={d}", .{ conn_id, c2s_bytes, s2c_bytes });
            return error.ConnectionReset;
        }
        poll_iterations += 1;

        // Check for errors/hangup/invalid FD
        const err_mask = posix.POLL.ERR | posix.POLL.HUP | posix.POLL.NVAL;
        if (fds[0].revents & err_mask != 0) {
            log.debug("[{d}] Relay: client side ERR/HUP/NVAL (revents=0x{x}), polls={d} c2s={d} s2c={d}", .{ conn_id, fds[0].revents, poll_iterations, c2s_bytes, s2c_bytes });
            return error.ConnectionReset;
        }
        if (fds[1].revents & err_mask != 0) {
            log.debug("[{d}] Relay: DC side ERR/HUP/NVAL (revents=0x{x}), polls={d} c2s={d} s2c={d}", .{ conn_id, fds[1].revents, poll_iterations, c2s_bytes, s2c_bytes });
            return error.ConnectionReset;
        }

        // Track progress to detect spin loops
        const bytes_before = c2s_bytes + s2c_bytes;

        // Client → DC (C2S): read TLS records, unwrap, decrypt, re-encrypt, forward
        if (fds[0].revents & posix.POLL.IN != 0) {
            relayClientToDc(
                client,
                dc,
                client_decryptor,
                tg_encryptor,
                &tls_hdr_buf,
                &tls_hdr_pos,
                &tls_body_buf,
                &tls_body_pos,
                &tls_body_len,
                &c2s_bytes,
                conn_id,
            ) catch |err| {
                log.debug("[{d}] Relay: C2S error: {any}, polls={d} c2s={d} s2c={d}", .{ conn_id, err, poll_iterations, c2s_bytes, s2c_bytes });
                return err;
            };
        }

        // DC → Client (S2C): read raw, decrypt DC, encrypt client, wrap in TLS
        if (fds[1].revents & posix.POLL.IN != 0) {
            relayDcToClient(
                dc,
                client,
                tg_decryptor,
                client_encryptor,
                &dc_read_buf,
                &drs,
                &s2c_bytes,
            ) catch |err| {
                log.debug("[{d}] Relay: S2C error: {any}, polls={d} c2s={d} s2c={d}", .{ conn_id, err, poll_iterations, c2s_bytes, s2c_bytes });
                return err;
            };
        }

        // Spin detection: if poll() returned ready but no bytes transferred,
        // increment counter. Terminate if stuck in a tight loop.
        if (c2s_bytes + s2c_bytes == bytes_before) {
            no_progress_count += 1;
            if (no_progress_count >= 100) {
                log.warn("[{d}] Relay: spin detected ({d} no-progress polls), terminating. c2s={d} s2c={d}", .{ conn_id, no_progress_count, c2s_bytes, s2c_bytes });
                return error.ConnectionReset;
            }
        } else {
            no_progress_count = 0;
        }
    }
}

/// C2S direction: Read TLS records from client, unwrap, AES-CTR decrypt, re-encrypt for DC, send.
///
/// Uses incremental state so partial reads across poll iterations are handled correctly.
/// Both CCS and Application Data records share the same body buffer to survive WouldBlock.
fn relayClientToDc(
    client: net.Stream,
    dc: net.Stream,
    client_decryptor: *crypto.AesCtr,
    tg_encryptor: *crypto.AesCtr,
    tls_hdr_buf: *[tls_header_len]u8,
    tls_hdr_pos: *usize,
    tls_body_buf: *[max_tls_payload]u8,
    tls_body_pos: *usize,
    tls_body_len: *usize,
    bytes_counter: *u64,
    conn_id: u64,
) !void {
    // Read as much as possible in this call
    while (true) {
        if (tls_hdr_pos.* < tls_header_len) {
            // Still reading TLS header
            const nr = client.read(tls_hdr_buf[tls_hdr_pos.*..]) catch |err| {
                return if (err == error.WouldBlock) {} else err;
            };
            if (nr == 0) return error.ConnectionReset;
            tls_hdr_pos.* += nr;

            if (tls_hdr_pos.* < tls_header_len) return; // need more header bytes

            // Parse TLS record header
            const record_type = tls_hdr_buf[0];

            if (record_type == constants.tls_record_alert) {
                // Alert = peer closing
                log.info("[{d}] C2S: received TLS Alert, c2s={d}", .{ conn_id, bytes_counter.* });
                return error.ConnectionReset;
            }

            if (record_type == constants.tls_record_change_cipher or
                record_type == constants.tls_record_application)
            {
                tls_body_len.* = std.mem.readInt(u16, tls_hdr_buf[3..5], .big);
                if (tls_body_len.* == 0 or tls_body_len.* > max_tls_payload) {
                    return error.ConnectionReset;
                }
                tls_body_pos.* = 0;
            } else {
                // Unexpected record type
                return error.ConnectionReset;
            }
        }

        // Reading TLS record body (shared path for CCS and Application Data)
        const remaining = tls_body_len.* - tls_body_pos.*;
        if (remaining == 0) {
            // Record complete, reset for next
            tls_hdr_pos.* = 0;
            tls_body_pos.* = 0;
            tls_body_len.* = 0;
            continue;
        }

        const nr = client.read(tls_body_buf[tls_body_pos.*..][0..remaining]) catch |err| {
            return if (err == error.WouldBlock) {} else err;
        };
        if (nr == 0) return error.ConnectionReset;
        tls_body_pos.* += nr;

        if (tls_body_pos.* < tls_body_len.*) return; // need more body bytes

        // Full record body received — check record type
        if (tls_hdr_buf[0] == constants.tls_record_change_cipher) {
            // CCS record fully read — discard body and reset for next record
            tls_hdr_pos.* = 0;
            tls_body_pos.* = 0;
            tls_body_len.* = 0;
            continue;
        }

        // Application Data record — decrypt, re-encrypt, forward
        const payload = tls_body_buf[0..tls_body_len.*];

        // AES-CTR decrypt (client obfuscation layer)
        client_decryptor.apply(payload);

        // AES-CTR encrypt for DC
        tg_encryptor.apply(payload);

        // Send to DC
        try writeAll(dc, payload);
        bytes_counter.* += payload.len;

        // Reset for next TLS record
        tls_hdr_pos.* = 0;
        tls_body_pos.* = 0;
        tls_body_len.* = 0;
        return; // processed one record, return to poll
    }
}

/// S2C direction: Read from DC, AES-CTR decrypt DC, AES-CTR encrypt for client, wrap in TLS, send.
/// Uses DRS (Dynamic Record Sizing) to mimic real browser TLS behavior.
fn relayDcToClient(
    dc: net.Stream,
    client: net.Stream,
    tg_decryptor: *crypto.AesCtr,
    client_encryptor: *crypto.AesCtr,
    dc_read_buf: *[constants.default_buffer_size]u8,
    drs: *DynamicRecordSizer,
    bytes_counter: *u64,
) !void {
    const nr = dc.read(dc_read_buf) catch |err| {
        return if (err == error.WouldBlock) {} else err;
    };
    if (nr == 0) return error.ConnectionReset;

    const data = dc_read_buf[0..nr];

    bytes_counter.* += nr;

    // AES-CTR decrypt DC obfuscation
    tg_decryptor.apply(data);

    // AES-CTR encrypt for client obfuscation
    client_encryptor.apply(data);

    // Wrap in TLS Application Data record(s) using DRS-controlled sizes
    var offset: usize = 0;
    while (offset < data.len) {
        const max_chunk = drs.nextRecordSize();
        const chunk_len = @min(data.len - offset, max_chunk);

        // Build TLS record header
        var hdr: [tls_header_len]u8 = undefined;
        hdr[0] = constants.tls_record_application;
        hdr[1] = constants.tls_version[0];
        hdr[2] = constants.tls_version[1];
        std.mem.writeInt(u16, hdr[3..5], @intCast(chunk_len), .big);

        try writeAll(client, &hdr);
        try writeAll(client, data[offset..][0..chunk_len]);

        drs.recordSent(chunk_len);
        offset += chunk_len;
    }
}

/// Write all bytes to a stream, handling partial writes and backpressure.
/// On non-blocking sockets, waits for POLLOUT when the send buffer is full.
fn writeAll(stream: net.Stream, data: []const u8) !void {
    var written: usize = 0;
    while (written < data.len) {
        const nw = stream.write(data[written..]) catch |err| {
            if (err == error.WouldBlock) {
                // Wait for the socket to become writable
                var fds = [1]posix.pollfd{
                    .{ .fd = stream.handle, .events = posix.POLL.OUT, .revents = 0 },
                };
                const ready = try posix.poll(&fds, relay_timeout_ms);
                if (ready == 0) return error.ConnectionReset; // write timeout
                if (fds[0].revents & (posix.POLL.ERR | posix.POLL.HUP) != 0)
                    return error.ConnectionReset;
                continue;
            }
            return err;
        };
        if (nw == 0) return error.ConnectionReset;
        written += nw;
    }
}

/// Read exactly `buf.len` bytes, returning how many were read.
fn readExact(stream: net.Stream, buf: []u8) !usize {
    var total: usize = 0;
    while (total < buf.len) {
        const nr = stream.read(buf[total..]) catch |err| {
            if (total > 0) return total;
            return err;
        };
        if (nr == 0) return total;
        total += nr;
    }
    return total;
}

/// Format a network address as "ip:port" for logging.
fn formatAddress(addr: net.Address, buf: *[64]u8) []const u8 {
    switch (addr.any.family) {
        posix.AF.INET => {
            const bytes: *const [4]u8 = @ptrCast(&addr.in.sa.addr);
            return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}:{d}", .{
                bytes[0],                                  bytes[1], bytes[2], bytes[3],
                std.mem.bigToNative(u16, addr.in.sa.port),
            }) catch "?";
        },
        posix.AF.INET6 => {
            return std.fmt.bufPrint(buf, "[ipv6]:{d}", .{
                std.mem.bigToNative(u16, addr.in6.sa.port),
            }) catch "?";
        },
        else => return "?",
    }
}

/// Set a file descriptor to non-blocking mode.
fn setNonBlocking(fd: posix.fd_t) void {
    var fl_flags = posix.fcntl(fd, posix.F.GETFL, 0) catch return;
    const nonblock: @TypeOf(fl_flags) = @bitCast(@as(u64, @as(u32, @bitCast(posix.O{ .NONBLOCK = true }))));
    fl_flags |= nonblock;
    _ = posix.fcntl(fd, posix.F.SETFL, fl_flags) catch return;
}

/// Set SO_RCVTIMEO on a socket to limit blocking reads (anti-Slowloris).
fn setRecvTimeout(fd: posix.fd_t, timeout_sec: u32) void {
    const tv = posix.timeval{ .sec = @intCast(timeout_sec), .usec = 0 };
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&tv)) catch return;
}

test "ProxyState init/deinit" {
    const allocator = std.testing.allocator;
    var users = std.StringHashMap([16]u8).init(allocator);
    const name = try allocator.dupe(u8, "test");
    try users.put(name, [_]u8{0} ** 16);

    var cfg = Config{
        .users = users,
    };

    var state = ProxyState.init(allocator, cfg);
    defer {
        state.deinit();
        cfg.deinit(allocator);
    }

    try std.testing.expectEqual(@as(usize, 1), state.user_secrets.len);
}

test "DRS starts small and ramps up" {
    var drs = DynamicRecordSizer.init();

    // Initially should use small records
    try std.testing.expectEqual(DynamicRecordSizer.initial_size, drs.nextRecordSize());

    // Send a few records — should stay small
    for (0..DynamicRecordSizer.ramp_record_threshold - 1) |_| {
        drs.recordSent(1369);
    }
    try std.testing.expectEqual(DynamicRecordSizer.initial_size, drs.nextRecordSize());

    // One more should trigger ramp-up
    drs.recordSent(1369);
    try std.testing.expectEqual(DynamicRecordSizer.full_size, drs.nextRecordSize());
}

test "DRS ramps up by byte threshold" {
    var drs = DynamicRecordSizer.init();

    // Send fewer records but enough bytes to trigger ramp
    drs.recordSent(DynamicRecordSizer.ramp_byte_threshold);
    try std.testing.expectEqual(DynamicRecordSizer.full_size, drs.nextRecordSize());
}
```

--- deploy/mtproto-proxy.service ---
```zig
[Unit]
Description=MTProto Proxy (Zig)
Documentation=https://github.com/sleep3r/mtproto.zig
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=mtproto
Group=mtproto
WorkingDirectory=/opt/mtproto-proxy
ExecStart=/opt/mtproto-proxy/mtproto-proxy /opt/mtproto-proxy/config.toml
Restart=always
RestartSec=3

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadOnlyPaths=/opt/mtproto-proxy

# Allow binding to privileged ports (443)
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

# Limits
LimitNOFILE=65535
TasksMax=65535

[Install]
WantedBy=multi-user.target
```

--- Makefile ---
```zig
.PHONY: build run test clean fmt

# Build the proxy binary
build:
	zig build

# Build with release optimizations
release:
	zig build -Doptimize=ReleaseFast

# Run the proxy (pass CONFIG via: make run CONFIG=path/to/config.toml)
CONFIG ?= config.toml
run:
	zig build run -- $(CONFIG)

# Run unit tests
test:
	zig build test

# Remove build artifacts
clean:
	rm -rf .zig-cache zig-out

# Format all Zig source files
fmt:
	zig fmt src/

# Deploy to VPS (cross-compiles for Linux, uploads, and restarts service)
# Stops the service first because the systemd unit sets ReadOnlyPaths=/opt/mtproto-proxy
SERVER ?= 45.77.223.232
deploy: release_linux
	@echo "Deploying to $(SERVER)..."
	ssh root@$(SERVER) 'systemctl stop mtproto-proxy'
	scp zig-out/bin/mtproto-proxy root@$(SERVER):/opt/mtproto-proxy/
	ssh root@$(SERVER) 'systemctl start mtproto-proxy && systemctl status mtproto-proxy --no-pager'

# Cross-compile for Linux (x86_64)
release_linux:
	zig build -Doptimize=ReleaseFast -Dtarget=x86_64-linux
```

--- build.zig ---
```zig
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    const exe = b.addExecutable(.{
        .name = "mtproto-proxy",
        .root_module = exe_mod,
    });

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the proxy");
    run_step.dependOn(&run_cmd.step);

    // Tests
    const test_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    const unit_tests = b.addTest(.{
        .root_module = test_mod,
    });

    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);
}
```

--- config.toml ---
```zig
[server]
port = 443

[censorship]
tls_domain = "wb.ru"
mask = true

[access.users]
alexander = "0b513f6e83524354984a8835939fa9af"
```
