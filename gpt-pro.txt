You’re very close. I think you have **one instrumentation problem** and **three real I/O bugs**.

## My read

### Highest-probability immediate CPU cause
Your new **hot-path hex logging** is very likely the thing pushing CPU to 95%+.

Why:
- formatting `[]u8` as hex in `ReleaseFast` on every relay packet is expensive;
- under systemd/journald, logs can be **rate-limited or dropped**, so you pay formatting cost but don’t necessarily see output;
- that matches “CPU high, many threads, no relay diagnostics visible”.

So I would treat the logging as the **amplifier**.

### Real correctness bugs I would fix right now
1. **You ignore partial writes** for:
   - `client_stream.write(server_hello)`
   - `dc_stream.write(&nonce_to_send)`

   That is a real bug even if it only triggers occasionally.

2. **`POLLHUP` is handled too early** in `relayBidirectional()`.
   On Linux, `poll()` commonly returns `POLLIN | POLLHUP` when the peer has sent final bytes and then closed.
   Your code exits **before draining readable bytes**.

3. **Your “spin detector” only counts forwarded bytes**, not partial parser progress.
   So a connection that is slowly assembling a TLS record can look like “no progress”.

4. Minor but important: your `c2s=0` logs are misleading because **pipelined bytes are not counted** in `c2s_bytes`.

---

## What I would change first

### 1) Stop doing packet hex dumps in the hot path
Do not use `std.log` with big `{x}` slice formatting per packet.

If you still need tracing, do **bounded previews only**, and only for **one connection / one IP / first packet per direction**.

<details>
<summary>Safe preview helper</summary>

```zig
const trace_packets = false;

fn logPreview(comptime label: []const u8, conn_id: u64, data: []const u8) void {
    if (!trace_packets) return;

    const n = @min(data.len, 32);
    var out: [95]u8 = undefined; // 32 bytes => 64 hex + 31 spaces
    var pos: usize = 0;
    const hex = "0123456789abcdef";

    for (data[0..n], 0..) |b, i| {
        if (i != 0) {
            out[pos] = ' ';
            pos += 1;
        }
        out[pos] = hex[b >> 4];
        out[pos + 1] = hex[b & 0x0f];
        pos += 2;
    }

    log.debug("[{d}] {s}: len={d} first={s}", .{
        conn_id,
        label,
        data.len,
        out[0..pos],
    });
}
```

</details>

Also: for production, I would not keep global release logging at `.debug`. Keep it at `.info`, and make packet tracing an explicit toggle.

---

### 2) Use `writeAll()` for `ServerHello` and DC nonce
This is a must-fix.

```zig
try writeAll(client_stream, server_hello);
...
try writeAll(dc_stream, &nonce_to_send);
```

Replace these two lines:

```zig
_ = try client_stream.write(server_hello);
...
_ = try dc_stream.write(&nonce_to_send);
```

---

### 3) Make relay progress-aware and drain `POLLIN` before treating `POLLHUP` as fatal
This is the main relay fix.

Add:

```zig
const RelayProgress = enum {
    none,
    partial,
    forwarded,
};
```

Then replace your relay functions with these versions.

<details>
<summary><code>relayBidirectional</code>, <code>relayClientToDc</code>, <code>relayDcToClient</code>, <code>writeAll</code></summary>

```zig
const RelayProgress = enum {
    none,
    partial,
    forwarded,
};

fn relayBidirectional(
    client: net.Stream,
    dc: net.Stream,
    client_decryptor: *crypto.AesCtr,
    client_encryptor: *crypto.AesCtr,
    tg_encryptor: *crypto.AesCtr,
    tg_decryptor: *crypto.AesCtr,
    initial_c2s_bytes: u64,
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

    var drs = DynamicRecordSizer.init();
    var dc_read_buf: [constants.default_buffer_size]u8 = undefined;

    var c2s_bytes: u64 = initial_c2s_bytes;
    var s2c_bytes: u64 = 0;
    var poll_iterations: u64 = 0;
    var no_progress_polls: u32 = 0;

    while (true) {
        fds[0].revents = 0;
        fds[1].revents = 0;

        const ready = try posix.poll(&fds, relay_timeout_ms);
        if (ready == 0) {
            log.debug("[{d}] Relay: idle timeout, c2s={d} s2c={d}", .{
                conn_id, c2s_bytes, s2c_bytes,
            });
            return error.ConnectionReset;
        }

        poll_iterations += 1;
        var progressed = false;

        const client_revents = fds[0].revents;
        const dc_revents = fds[1].revents;

        // IMPORTANT: drain readable data first. POLLIN|POLLHUP is common on Linux.
        if ((client_revents & posix.POLL.IN) != 0) {
            const step = relayClientToDc(
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
                log.debug("[{d}] Relay: C2S error: {any}, polls={d} c2s={d} s2c={d}", .{
                    conn_id, err, poll_iterations, c2s_bytes, s2c_bytes,
                });
                return err;
            };
            if (step != .none) progressed = true;
        }

        if ((dc_revents & posix.POLL.IN) != 0) {
            const step = relayDcToClient(
                dc,
                client,
                tg_decryptor,
                client_encryptor,
                &dc_read_buf,
                &drs,
                &s2c_bytes,
            ) catch |err| {
                log.debug("[{d}] Relay: S2C error: {any}, polls={d} c2s={d} s2c={d}", .{
                    conn_id, err, poll_iterations, c2s_bytes, s2c_bytes,
                });
                return err;
            };
            if (step != .none) progressed = true;
        }

        // Hard errors after draining readable data
        if ((client_revents & (posix.POLL.ERR | posix.POLL.NVAL)) != 0) {
            log.debug("[{d}] Relay: client ERR/NVAL (revents=0x{x}), polls={d} c2s={d} s2c={d}", .{
                conn_id, client_revents, poll_iterations, c2s_bytes, s2c_bytes,
            });
            return error.ConnectionReset;
        }
        if ((dc_revents & (posix.POLL.ERR | posix.POLL.NVAL)) != 0) {
            log.debug("[{d}] Relay: DC ERR/NVAL (revents=0x{x}), polls={d} c2s={d} s2c={d}", .{
                conn_id, dc_revents, poll_iterations, c2s_bytes, s2c_bytes,
            });
            return error.ConnectionReset;
        }

        // If HUP arrived without readable data, close immediately.
        // If it arrived with POLLIN, we already drained what we could above.
        if (((client_revents & posix.POLL.HUP) != 0) and ((client_revents & posix.POLL.IN) == 0)) {
            log.debug("[{d}] Relay: client HUP, polls={d} c2s={d} s2c={d}", .{
                conn_id, poll_iterations, c2s_bytes, s2c_bytes,
            });
            return error.ConnectionReset;
        }
        if (((dc_revents & posix.POLL.HUP) != 0) and ((dc_revents & posix.POLL.IN) == 0)) {
            log.debug("[{d}] Relay: DC HUP, polls={d} c2s={d} s2c={d}", .{
                conn_id, poll_iterations, c2s_bytes, s2c_bytes,
            });
            return error.ConnectionReset;
        }

        if (!progressed) {
            no_progress_polls += 1;
            if (no_progress_polls >= 32) {
                log.warn("[{d}] Relay: no-progress poll loop, client_revents=0x{x} dc_revents=0x{x} hdr={d} body_pos={d} body_len={d} c2s={d} s2c={d}", .{
                    conn_id,
                    client_revents,
                    dc_revents,
                    tls_hdr_pos,
                    tls_body_pos,
                    tls_body_len,
                    c2s_bytes,
                    s2c_bytes,
                });
                return error.ConnectionReset;
            }
        } else {
            no_progress_polls = 0;
        }
    }
}

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
) !RelayProgress {
    _ = conn_id;

    var consumed_any = false;

    while (true) {
        if (tls_hdr_pos.* < tls_header_len) {
            const nr = client.read(tls_hdr_buf[tls_hdr_pos.*..]) catch |err| {
                if (err == error.WouldBlock) {
                    return if (consumed_any) .partial else .none;
                }
                return err;
            };
            if (nr == 0) return error.ConnectionReset;

            consumed_any = true;
            tls_hdr_pos.* += nr;

            if (tls_hdr_pos.* < tls_header_len) return .partial;

            const record_type = tls_hdr_buf[0];

            if (record_type == constants.tls_record_alert) {
                return error.ConnectionReset;
            }

            switch (record_type) {
                constants.tls_record_change_cipher, constants.tls_record_application => {
                    tls_body_len.* = std.mem.readInt(u16, tls_hdr_buf[3..5], .big);
                    if (tls_body_len.* == 0 or tls_body_len.* > max_tls_payload) {
                        return error.ConnectionReset;
                    }
                    tls_body_pos.* = 0;
                },
                else => return error.ConnectionReset,
            }
        }

        const remaining = tls_body_len.* - tls_body_pos.*;
        if (remaining == 0) {
            tls_hdr_pos.* = 0;
            tls_body_pos.* = 0;
            tls_body_len.* = 0;
            if (consumed_any) return .partial;
            continue;
        }

        const nr = client.read(tls_body_buf[tls_body_pos.*..][0..remaining]) catch |err| {
            if (err == error.WouldBlock) {
                return if (consumed_any) .partial else .none;
            }
            return err;
        };
        if (nr == 0) return error.ConnectionReset;

        consumed_any = true;
        tls_body_pos.* += nr;

        if (tls_body_pos.* < tls_body_len.*) return .partial;

        if (tls_hdr_buf[0] == constants.tls_record_change_cipher) {
            tls_hdr_pos.* = 0;
            tls_body_pos.* = 0;
            tls_body_len.* = 0;
            continue;
        }

        const payload = tls_body_buf[0..tls_body_len.*];

        client_decryptor.apply(payload);
        tg_encryptor.apply(payload);
        try writeAll(dc, payload);

        bytes_counter.* += payload.len;

        tls_hdr_pos.* = 0;
        tls_body_pos.* = 0;
        tls_body_len.* = 0;
        return .forwarded;
    }
}

fn relayDcToClient(
    dc: net.Stream,
    client: net.Stream,
    tg_decryptor: *crypto.AesCtr,
    client_encryptor: *crypto.AesCtr,
    dc_read_buf: *[constants.default_buffer_size]u8,
    drs: *DynamicRecordSizer,
    bytes_counter: *u64,
) !RelayProgress {
    const nr = dc.read(dc_read_buf) catch |err| {
        if (err == error.WouldBlock) return .none;
        return err;
    };
    if (nr == 0) return error.ConnectionReset;

    const data = dc_read_buf[0..nr];

    tg_decryptor.apply(data);
    client_encryptor.apply(data);

    var offset: usize = 0;
    while (offset < data.len) {
        const max_chunk = drs.nextRecordSize();
        const chunk_len = @min(data.len - offset, max_chunk);

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

    bytes_counter.* += nr;
    return .forwarded;
}

fn writeAll(stream: net.Stream, data: []const u8) !void {
    var written: usize = 0;
    var wouldblock_spins: u8 = 0;

    while (written < data.len) {
        const nw = stream.write(data[written..]) catch |err| {
            if (err == error.WouldBlock) {
                wouldblock_spins += 1;
                if (wouldblock_spins >= 32) return error.ConnectionReset;

                var fds = [1]posix.pollfd{
                    .{ .fd = stream.handle, .events = posix.POLL.OUT, .revents = 0 },
                };

                const ready = try posix.poll(&fds, relay_timeout_ms);
                if (ready == 0) return error.ConnectionReset;

                if ((fds[0].revents & (posix.POLL.ERR | posix.POLL.HUP | posix.POLL.NVAL)) != 0) {
                    return error.ConnectionReset;
                }

                if ((fds[0].revents & posix.POLL.OUT) == 0) continue;
                continue;
            }
            return err;
        };

        if (nw == 0) return error.ConnectionReset;

        wouldblock_spins = 0;
        written += nw;
    }
}
```

</details>

---

### 4) Count pipelined bytes as C2S for diagnostics
Right now the signature `c2s=0 s2c≈154` is misleading because pre-relay pipelined bytes are invisible.

Change:

```zig
var initial_c2s_bytes: u64 = 0;

if (payload_len > constants.handshake_len) {
    const pipelined = payload_buf[constants.handshake_len..payload_len];
    log.info("[{d}] ({s}) Pipelined {d}B after handshake", .{
        conn_id, peer_str, pipelined.len,
    });

    client_decryptor.apply(pipelined);
    tg_encryptor.apply(pipelined);
    try writeAll(dc_stream, pipelined);

    initial_c2s_bytes = pipelined.len;
} else {
    log.info("[{d}] ({s}) No pipelined data after handshake", .{ conn_id, peer_str });
}

try relayBidirectional(
    client_stream,
    dc_stream,
    &client_decryptor,
    &client_encryptor,
    &tg_encryptor,
    &tg_decryptor,
    initial_c2s_bytes,
    conn_id,
);
```

That will stop you from chasing fake `c2s=0` failures that were actually `pipelined>0`.

---

## Why this likely helps the iPhone issue too

I’m not fully certain this is the whole iPhone fix, but these are the right first changes because they directly affect the pattern you’re seeing:

- **partial ServerHello/DC nonce writes** can create intermittent failures;
- **premature `POLLHUP` handling** can truncate the exact first short S2C reply;
- **misleading `c2s=0` metrics** can hide that the client already sent the first request in the handshake record.

Also, some of the “Mac failures” may be **speculative/raced connections**, not real protocol failures. Telegram clients do open loser connections and reset them.

---

## If CPU is still high after removing packet logs

Do this on the VPS before changing more protocol logic:

```bash
pid=$(pidof mtproto-proxy)
ps -L -o pid,tid,pcpu,stat,wchan:32,comm -p "$pid" | sort -k3 -nr | head -30
```

Then attach to one hot thread:

```bash
strace -ttT -fp <TID> -e poll,read,write,recvfrom,sendto,fcntl
```

What to look for:

- Repeating `poll(...) = 1` + `read(...) = -1 EAGAIN`
  - real poll/read spin
- Repeating `write(...) = -1 EAGAIN` + `poll(...POLLOUT...) = 1`
  - write-side spin
- No syscalls but high CPU
  - formatter/logging or pure userspace loop

If available, also:

```bash
perf top -H -p "$pid"
```

If top frames are in `std.fmt` / logging paths, that confirms the tracer is the CPU hog.

---

## One more pragmatic step: test a debug-safe Linux build once
For one controlled iPhone test, I would deploy:

```bash
zig build -Doptimize=ReleaseSafe -Dtarget=x86_64-linux
```

Just once, with packet logging **off**.

Why:
- if you have UB from a stack issue / formatting edge / accidental overwrite, `ReleaseSafe` is much more likely to surface it;
- your current combination of `ReleaseFast` + multi-thread + hot logging is the worst possible debug environment.

If you want to be extra conservative for that test, temporarily bump thread stack to `256 * 1024`.

---

## If iPhone still fails after the relay fixes

Then my next protocol A/B would be:

### Implement canonical **FAST_MODE** as a toggle
Reason:
- your current failures are S2C-centric;
- canonical Python defaults to FAST_MODE;
- FAST_MODE removes one whole S2C decrypt/re-encrypt chain;
- it also reduces CPU.

I would not rip out your current full re-encrypt path; I would add:

- `fast_mode = true` default
- keep current path as fallback

That gives you the fastest answer to: “is the remaining iPhone failure specifically in my S2C full re-encrypt path?”

---

## My recommended deployment order

1. **Remove packet hex dumps** from hot relay path.
2. **Fix `writeAll` usage** for `server_hello` and DC nonce.
3. **Replace relay loop** with the progress-aware version above.
4. **Count pipelined bytes** in C2S totals.
5. Deploy.
6. Re-test:
   - Mac from `81.17.27.66`
   - iPhone from `109.252.90.134`
   - VPN `103.242.74.56`
7. Only if iPhone still fails, add **FAST_MODE toggle**.

---

If you want, I can turn this into a **single ready-to-paste patch for `src/proxy/proxy.zig`** with minimal diff formatting.