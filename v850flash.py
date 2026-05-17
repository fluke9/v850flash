#!/usr/bin/env python3
"""V850E2 single-wire UART boot-protocol tool.

Reverse-engineered single-wire UART boot protocol for V850E2 microcontrollers.
Exposes id / dump / erase / program / diffprogram / watchprogram subcommands
on top of the protocol primitives (Frame encode/decode, checksum, command IDs).

Frame format
------------
Command frame  (host -> device): 01  LEN(2,BE)  CMD  DATA...   SUM  03
Response frame (device -> host): 11  LEN(2,BE)  DATA...        SUM  03 | 17
ACK frame      (host -> device): 11  00 01  06   F9  03   (same shape as
                                                          a device status,
                                                          disambiguated by
                                                          conversation state)

LEN counts everything between LEN and SUM exclusive (i.e. CMD+DATA for command
frames, DATA for response frames).
SUM = (-sum(LEN bytes + payload)) & 0xFF
Footer 03 = end of transfer, 17 = more data blocks follow.

Single-wire note: the FTDI tap sees both directions on the same line, so the
host also sees an echo of its own transmissions. Captures contain the union of
both sides serialized in time order.
"""
from __future__ import annotations

import argparse
import binascii
import os
import sys
import time
from dataclasses import dataclass
from typing import Optional

try:
    import serial  # pyserial; only needed for live read/info subcommands
except ImportError:
    serial = None  # type: ignore

# ---------------------------------------------------------------------------
# Protocol constants

SOH = 0x01   # start-of-header, host command
SOD = 0x11   # start-of-data,   device response (and host streaming-ACK)
ETX = 0x03   # end of frame, last block
ETB = 0x17   # end of block, more data follows

ACK = 0x06   # "normal acknowledgement" payload byte

# Command IDs. All opcodes confirmed by live tests on hardware; the ones we
# actively use are RESET, MEMORY_READ, OSC_FREQ_SET, BAUD_RATE_SET,
# SILICON_SIGNATURE, BLOCK_ERASE, PROGRAMMING. The rest are listed for
# completeness — most have been observed to ACK as command IDs but the
# parameters/flows haven't all been exercised.
COMMANDS = {
    0x00: "RESET",
    0x13: "VERIFY",
    0x20: "CHIP_ERASE",
    0x22: "BLOCK_ERASE",
    0x32: "BLOCK_BLANK_CHECK",
    0x40: "PROGRAMMING",
    0x50: "MEMORY_READ",
    0x70: "STATUS",
    0x90: "OSCILLATING_FREQUENCY_SET",
    0x9A: "BAUD_RATE_SET",
    0xA0: "SECURITY_SET",
    0xB0: "CHECKSUM",
    0xC0: "SILICON_SIGNATURE",
    0xC5: "VERSION_GET",
    ACK:  "ACK",                   # 0x06 — only valid as payload of an 11-frame
}

# Chip registry, keyed by the device-name string the signature query returns.
# The signature payload format differs subtly across V850E2 variants (the size
# fields in particular are encoded inconsistently or partially), so we rely on
# the name field only and look the rest up here.
#
# Each entry is a dict with:
#   pflash    : (start, end) inclusive byte addresses; chip returns 1 byte per
#               addr
#   dflash    : (start, end) inclusive *address* range; chip returns 2 bytes
#               per addr (16-bit-word addressing), so actual byte size =
#               2 * span. Omit the key entirely if the chip has no dflash.
#   block_size: BLOCK_ERASE granularity in bytes (flash hardware constraint;
#               erase start/end must be aligned to this).
#   osc_mhz   : oscillator frequency in MHz; encoded into the 4-byte
#               OSC_FREQ_SET parameter via osc_bytes_from_mhz()
#   bauds     : {baud_rate_bps: d01_byte} mapping for BAUD_RATE_SET (cmd 0x9A).
#               9600 entry (d01=0x00) is implicit; no need to list. The maximum
#               baud here becomes the default for `--fast` dumps on this chip.
CHIPS: dict[str, dict] = {
    "D70F3525": {
        "pflash":     (0x00000000, 0x001FFFFF),    # 2 MiB
        # dflash addresses are 16-bit-word indices: 0x8000 addresses ⇒ 64 KiB.
        "dflash":     (0x02000000, 0x02007FFF),
        "block_size": 0x1000,                       # 4 KiB
        "osc_mhz":    4,
        "bauds":      {115200: 0x01, 500000: 0x02, 1000000: 0x03},
    },
    "D70F3539A": {
        # V850E2/Dx4-3D 2 MB code flash.
        # No data flash on this part (signature reports dflash_end = 0).
        "pflash":     (0x00000000, 0x001FFFFF),
        "block_size": 0x1000,                       # 4 KiB; verified on hardware
        "osc_mhz":    24,
        "bauds":      {115200: 0x01, 500000: 0x02, 1000000: 0x03},
    },
}

# Status codes returned in 11-frame payloads 
STATUS_CODES = {
    0x04: "Command number error",
    0x05: "Parameter error",
    0x06: "ACK",
    0x07: "Checksum error",
    0x0F: "Verify error",
    0x10: "Protect error",
    0x15: "NACK",
    0x1A: "MRG10 error (erase)",
    0x1B: "MRG11 error (internal verify / blank-check)",
    0x1C: "Write error",
    0xFF: "BUSY",
}

def checksum(payload: bytes) -> int:
    """Two's-complement 8-bit sum used by the protocol."""
    return (-sum(payload)) & 0xFF


def osc_bytes_from_mhz(mhz: float) -> bytes:
    """Encode a frequency (in MHz) as the 4-byte OSC_FREQ_SET parameter.
    The chip's formula is:
        freq_kHz = (D01*0.1 + D02*0.01 + D03*0.001) * 10^D04
    so we pick D04 such that the mantissa lands in [0.1, 1.0) and read
    off the first three decimal digits."""
    khz = round(mhz * 1000)
    if khz <= 0:
        raise ValueError(f"osc must be > 0, got {mhz} MHz")
    d04 = 0
    while khz >= 10 ** d04:
        d04 += 1
    # khz / 10^d04 in [0.1, 1.0); m = first 3 decimal digits
    m = (khz * 1000) // (10 ** d04)
    d01, d02, d03 = (m // 100) % 10, (m // 10) % 10, m % 10
    return bytes([d01, d02, d03, d04])


# ---------------------------------------------------------------------------
# Frame model

@dataclass
class Frame:
    header: int          # 0x01 (host cmd) or 0x11 (device data / host ACK)
    length: int          # value of the 2-byte LEN field (count of payload bytes)
    payload: bytes       # CMD+DATA for 01-frames, DATA for 11-frames
    sum_byte: int        # SUM byte as captured
    footer: int          # 0x03 or 0x17
    offset: int = 0      # offset in the source byte stream
    raw: bytes = b""     # complete on-the-wire bytes

    @property
    def sum_ok(self) -> bool:
        body = bytes([(self.length >> 8) & 0xFF, self.length & 0xFF]) + self.payload
        return checksum(body) == self.sum_byte

    @property
    def length_ok(self) -> bool:
        return self.length == len(self.payload)

    @property
    def footer_ok(self) -> bool:
        return self.footer in (ETX, ETB)

    @property
    def valid(self) -> bool:
        return self.sum_ok and self.length_ok and self.footer_ok

    def encode(self) -> bytes:
        body = bytes([(self.length >> 8) & 0xFF, self.length & 0xFF]) + self.payload
        return bytes([self.header]) + body + bytes([checksum(body), self.footer])

    # ----- builders ----------------------------------------------------------

    @classmethod
    def command(cls, cmd_id: int, data: bytes = b"") -> "Frame":
        payload = bytes([cmd_id]) + data
        return cls(SOH, len(payload), payload,
                   checksum(bytes([0, len(payload)]) + payload), ETX)

    @classmethod
    def ack(cls) -> "Frame":
        return cls(SOD, 1, bytes([ACK]),
                   checksum(bytes([0, 1, ACK])), ETX)

    @classmethod
    def data(cls, payload: bytes, last: bool) -> "Frame":
        """Build a data frame (SOD header) used while streaming Programming
        payload to the chip. `last=True` ends the stream with ETX; otherwise
        ETB indicates more frames follow."""
        ln = len(payload)
        body = bytes([(ln >> 8) & 0xFF, ln & 0xFF]) + payload
        return cls(SOD, ln, payload, checksum(body), ETX if last else ETB)




# ---------------------------------------------------------------------------
# Live device interface

class Programmer:
    """Talks to a V850E2 sitting in single-wire UART boot mode.

    Expects the FTDI to be wired per the README (TX through inverter +
    tri-state buffer onto the shared TX/RX line). Because the line is shared,
    every byte we transmit is echoed back on RX — we read and discard that
    echo before looking for the device's response.
    """

    def __init__(self, port: str, baud: int = 9600, timeout: float = 2.0,
                 debug: bool = False):
        if serial is None:
            raise RuntimeError("pyserial not installed (pip install pyserial)")
        # Build unopened so we can pre-set DTR/RTS and avoid the open-glitch
        # pulling RESET unpredictably.
        self.ser = serial.Serial()
        self.ser.port = port
        self.ser.baudrate = baud
        self.ser.bytesize = serial.EIGHTBITS
        self.ser.parity = serial.PARITY_NONE
        self.ser.stopbits = serial.STOPBITS_ONE
        self.ser.timeout = timeout
        self.ser.dsrdtr = False
        self.ser.rtscts = False
        # Wiring: RTS -> RESET (1k series).  FLMD0 is jumper-tied to VCC
        # permanently (we don't switch to user mode from software).
        self.ser.rts = False  # RTS# HIGH -> RESET HIGH (chip runs)
        self.ser.dtr = False  # parked
        self.ser.open()
        self.debug = debug

    def close(self) -> None:
        self.ser.close()

    # ----- low-level --------------------------------------------------------

    def _drain_echo(self, n: int) -> None:
        echo = self.ser.read(n)
        if len(echo) != n:
            raise IOError(f"echo timeout: expected {n} bytes, got {len(echo)}")

    def _read_exact(self, n: int) -> bytes:
        buf = self.ser.read(n)
        if len(buf) != n:
            raise IOError(f"read timeout: expected {n} bytes, got {len(buf)}")
        return buf

    def _send_frame(self, f: Frame) -> None:
        raw = f.encode()
        if self.debug:
            print(f"TX -> {raw.hex(' ')}")
        self.ser.write(raw)
        self._drain_echo(len(raw))

    def _recv_frame(self) -> Frame:
        h = self._read_exact(1)[0]
        if h not in (SOH, SOD):
            raise IOError(f"bad header 0x{h:02X}")
        ln = self._read_exact(2)
        length = (ln[0] << 8) | ln[1]
        payload = self._read_exact(length)
        s = self._read_exact(1)[0]
        f = self._read_exact(1)[0]
        frame = Frame(h, length, payload, s, f, raw=bytes([h]) + ln + payload + bytes([s, f]))
        if self.debug:
            print(f"RX <- {frame.raw.hex(' ')}")
        if not frame.sum_ok:
            raise IOError(f"bad checksum on response (got 0x{s:02X})")
        if not frame.footer_ok:
            raise IOError(f"bad footer 0x{f:02X}")
        return frame

    # ----- handshake --------------------------------------------------------

    def enter_bootmode(self) -> None:
        """Pulse RESET via RTS. FLMD0 is assumed to be hard-wired to VCC."""
        self.ser.rts = True         # RTS# LOW -> RESET LOW
        time.sleep(0.1)
        self.ser.reset_input_buffer()
        self.ser.rts = False        # RTS# HIGH -> RESET HIGH (chip enters BootROM)
        time.sleep(0.1)             # let the BootROM finish startup

    def pulse(self) -> None:
        """Wake/autobaud sync: two 0x00 bytes spaced ~20 ms apart."""
        self.ser.reset_input_buffer()
        self.ser.reset_output_buffer()
        time.sleep(0.2)
        self.ser.write(b"\x00")
        time.sleep(0.02)
        self.ser.write(b"\x00")
        time.sleep(0.02)
        self.ser.reset_input_buffer()

    def _expect_ack(self) -> bytes:
        """Read a status/ACK frame. Some commands (e.g. OSC_FREQ_SET) return a
        longer payload whose first byte is still 0x06 ACK followed by extra
        info — accept those too and return the trailing bytes."""
        f = self._recv_frame()
        if f.header != SOD or len(f.payload) < 1 or f.payload[0] != ACK:
            if f.payload:
                code = f.payload[0]
                name = STATUS_CODES.get(code, f"unknown status")
                detail = f"chip returned {name} (0x{code:02X})"
            else:
                detail = "chip returned an empty status frame"
            raise IOError(f"expected ACK, but {detail} "
                          f"[raw {f.raw.hex(' ')}]")
        return f.payload[1:]

    # ----- commands ---------------------------------------------------------

    def reset(self) -> None:
        self._send_frame(Frame.command(0x00))
        self._expect_ack()

    def go_fast(self, target_baud: int | None = None,
                osc_params: bytes | None = None,
                d01: int | None = None) -> int:
        """Step the chip up from 9600 to a faster baud rate via the captured
        handshake: SILICON_SIGNATURE -> OSC_FREQ_SET -> BAUD_RATE_SET, then
        switch our serial baud and verify with a RESET cmd.

        With `target_baud=None` (default), picks the maximum baud listed in
        CHIPS[name]['bauds']. Otherwise looks up the specific entry. OSC and
        d01 can be overridden for experimentation.

        Returns the baud rate actually selected.
        """
        # The chip refuses BAUD_RATE_SET unless we've done the signature query
        # first — empirically required. We also use the signature to look up
        # the chip's known params in the CHIPS registry.
        sig = self.silicon_signature()
        name = decode_signature(sig).get("name", "")
        entry = CHIPS.get(name)
        if entry is None and (osc_params is None or d01 is None):
            raise RuntimeError(
                f"unknown chip '{name}'; add it to CHIPS or pass osc/d01 explicitly")
        if osc_params is None:
            osc_params = osc_bytes_from_mhz(entry["osc_mhz"])
        if d01 is None:
            bauds = entry["bauds"]
            if target_baud is None:
                target_baud = max(bauds)            # fastest known on this chip
            if target_baud not in bauds:
                raise RuntimeError(
                    f"baud {target_baud} not in CHIPS['{name}']['bauds'] "
                    f"(known: {sorted(bauds)})")
            d01 = bauds[target_baud]
        time.sleep(0.05)
        self._send_frame(Frame.command(0x90, osc_params))
        self._expect_ack()
        time.sleep(0.05)
        self._send_frame(Frame.command(0x9A, bytes([d01])))
        self._expect_ack()                          # ACK at OLD baud
        time.sleep(0.1)                             # chip needs a moment to switch
        self.ser.baudrate = target_baud
        self.ser.reset_input_buffer()
        # verify the chip is now at the new baud
        self._send_frame(Frame.command(0x00))
        self._expect_ack()
        return target_baud

    def silicon_signature(self, opcode: int = 0xC0) -> bytes:
        """Query the silicon signature. The flow is the same shape as MEMORY_READ:
        command -> status ACK -> host streaming-ACK -> data frame."""
        self._send_frame(Frame.command(opcode))
        self._expect_ack()
        self._send_frame(Frame.ack())
        f = self._recv_frame()
        if f.header != SOD:
            raise IOError(f"unexpected response header 0x{f.header:02X}")
        return f.payload

    def block_erase(self, start: int, end: int) -> bytes:
        """Erase a flash region. `start` is the byte address of the first byte
        of the region (must be block-aligned); `end` is the byte address of
        the LAST byte of the region (inclusive). 4-byte big-endian addresses,
        same convention as MEMORY_READ on V850E2."""
        # Brief inter-command settle: the chip drops commands sent too soon
        # after a previous ACK (e.g. PROGRAMMING right after BLOCK_ERASE
        # times out at 50 ms but works reliably at ≥100 ms).
        time.sleep(0.05)
        payload = start.to_bytes(4, "big") + end.to_bytes(4, "big")
        self._send_frame(Frame.command(0x22, payload))
        # Erase takes ~70 ms/block in practice; scale the read timeout with
        # the range size plus 2 s safety. Caps at 120 s.
        approx_blocks = max(1, (end - start + 1) // 0x1000)
        wait = min(120.0, 0.1 * approx_blocks + 2.0)
        prev = self.ser.timeout
        try:
            self.ser.timeout = max(prev or 0, wait)
            return self._expect_ack()
        finally:
            self.ser.timeout = prev

    def programming(self, start: int, end: int, data: bytes, *,
                    bytes_per_addr: int = 1,
                    chunk_size: int = 256, progress=None) -> None:
        """Write `data` into flash from `start` to `end` (inclusive byte addresses).
        Flow:
          - send PROGRAMMING cmd with start/end (4-byte BE)
          - expect ACK
          - loop: send data frame (≤256 B), expect 2-byte status
                  (ST1 reception + ST2 write, both must be 0x06)
          - after the last data frame, send a zero-payload terminator data
            frame (LEN=0, ETX) — the chip's "end of stream" signal; without
            it the chip's UART receiver stays in "expecting more data" mode
            and ignores subsequent commands until a hardware reset

        `bytes_per_addr` must match the region: 1 for pflash, 2 for dflash
        (each dflash address holds two real bytes)."""
        addrs = end - start + 1
        expected = addrs * bytes_per_addr
        if len(data) != expected:
            raise ValueError(
                f"data is {len(data)} B, {addrs} addresses × "
                f"{bytes_per_addr} B/addr = {expected} B expected")
        time.sleep(0.5)    # inter-command settle — see block_erase
        payload = start.to_bytes(4, "big") + end.to_bytes(4, "big")
        self._send_frame(Frame.command(0x40, payload))
        self._expect_ack()

        off = 0
        while off < len(data):
            chunk = data[off:off + chunk_size]
            off += len(chunk)
            is_last = (off >= len(data))
            self._send_frame(Frame.data(chunk, last=is_last))
            # Per-frame status: chip returns 2-byte payload (ST1=reception,
            # ST2=write). We treat anything other than ACK+ACK as a failure.
            f = self._recv_frame()
            p = f.payload
            if len(p) < 2 or p[0] != ACK or p[1] != ACK:
                name1 = STATUS_CODES.get(p[0] if p else 0, "?")
                name2 = STATUS_CODES.get(p[1] if len(p) > 1 else 0, "?")
                raise IOError(
                    f"write failed at offset {off - len(chunk)}: "
                    f"ST1={name1} ST2={name2} (frame {f.raw.hex(' ')})")
            if progress is not None:
                progress(off, len(data))

        # After the last data frame the chip needs a single ZERO-PAYLOAD data
        # frame as a session terminator — without it the chip's UART receiver
        # stays in "expecting more data" mode and ignores all subsequent
        # commands until a hardware reset. The chip doesn't reply to the
        # terminator itself; just send it and move on.
        self._send_frame(Frame.data(b'', last=True))
        time.sleep(0.1)
        self.ser.reset_input_buffer()

    def read_memory(self, start: int, end: int,
                    progress=None, expected_size: Optional[int] = None) -> bytes:
        """Stream a memory range. progress(bytes_so_far, total) is optional.
        `expected_size` overrides the default total used for progress (the
        address span). dflash appears to use 16-bit-word addressing (each
        address holds 2 bytes), so dflash reads return 2x the address span.
        Callers reading dflash should pass `expected_size = 2 * span`."""
        time.sleep(0.3)   # inter-command settle so reads work right after
                          # erase/program
        self.ser.reset_input_buffer()   # drop any residual chip output
        data = bytearray()
        payload = start.to_bytes(4, "big") + end.to_bytes(4, "big")
        self._send_frame(Frame.command(0x50, payload))
        self._expect_ack()
        total = expected_size if expected_size is not None else (end - start + 1)
        while True:
            self._send_frame(Frame.ack())
            f = self._recv_frame()
            if f.header != SOD or (len(f.payload) == 1 and f.payload[0] == ACK):
                raise IOError(f"unexpected data frame: {f.raw.hex(' ')}")
            data.extend(f.payload)
            if progress is not None:
                progress(len(data), total)
            if f.footer == ETX:
                break
        return bytes(data)


# ---------------------------------------------------------------------------
# CLI: read / info

def _open_device(args: argparse.Namespace) -> Programmer:
    # Always connect at 9600 — chip's BootROM default. Higher rates are
    # selected later via go_fast() / cmd_dump's --baud option.
    p = Programmer(args.port, baud=9600, timeout=args.timeout,
                   debug=args.debug)
    p.enter_bootmode()
    p.pulse()
    p.reset()
    return p


def cmd_read(args: argparse.Namespace) -> int:
    start = int(args.start, 0)
    end = int(args.end, 0)
    if end < start:
        print("end must be >= start", file=sys.stderr)
        return 2
    p = _open_device(args)
    try:
        if args.fast:
            actual = p.go_fast(target_baud=args.baud, osc_params=(osc_bytes_from_mhz(args.osc) if args.osc else None))
            sys.stderr.write(f"switched chip to {actual} baud\n")
        last = [0.0]
        def show(done: int, total: int) -> None:
            now = time.time()
            if now - last[0] > 0.2 or done == total:
                pct = 100 * done / total if total else 0
                sys.stderr.write(f"\rreading 0x{start:08X}..0x{end:08X}: "
                                 f"{done}/{total} ({pct:5.1f}%)")
                sys.stderr.flush()
                last[0] = now
        data = p.read_memory(start, end, progress=show)
        sys.stderr.write("\n")
    finally:
        p.close()
    with open(args.out, "wb") as fp:
        fp.write(data)
    crc = binascii.crc32(data) & 0xFFFFFFFF
    print(f"wrote {len(data)} bytes to {args.out}  crc32={crc:08x}")
    req = end - start + 1
    if len(data) != req:
        ratio = len(data) / req
        print(f"  note: requested {req} bytes, got {len(data)} (ratio {ratio:.2f})")
    return 0


def _resolve_chip(p: "Programmer") -> tuple[str, dict]:
    """Query the signature and look up the chip in CHIPS, returning
    (name, entry). Raises a friendly RuntimeError with a copy-pasteable
    CHIPS template if the chip isn't in the registry."""
    info = decode_signature(p.silicon_signature())
    name = info.get("name", "")
    entry = CHIPS.get(name)
    if entry is None:
        known = ", ".join(sorted(CHIPS)) or "(none)"
        raise RuntimeError(
            f"chip '{name}' is not in the CHIPS registry "
            f"(known: {known}).\n"
            f"  add an entry to CHIPS in v850flash.py:\n"
            f'    "{name}": {{\n'
            f'        "pflash":     (0x00000000, 0x????????),   # signature says end=0x{info.get("pflash_end", 0):08X}\n'
            f'        # "dflash":   (0x02000000, 0x????????),   # if the chip has one (signature says end=0x{info.get("dflash_end", 0):08X})\n'
            f'        "block_size": 0x1000,                     # 4 KiB on every V850E2 we have seen\n'
            f'        "osc_mhz":    4,                          # actual board oscillator frequency in MHz\n'
            f'        "bauds":      {{115200: 0x01, 500000: 0x02, 1000000: 0x03}},\n'
            f"    }},\n"
            f"  most fields are common across V850E2; only osc_mhz really has\n"
            f"  to match your board. dump pflash sizes from the chip first if unsure.")
    return name, entry


def cmd_dump(args: argparse.Namespace) -> int:
    """Dump named region(s): pflash, dflash, or both. Queries the chip's
    silicon signature first to discover the actual ranges so the addresses
    aren't hardcoded."""
    p = _open_device(args)
    try:
        # Identify the chip and look up its canonical memory map.
        name, entry = _resolve_chip(p)
        regions = {}
        if "pflash" in entry: regions["pflash"] = entry["pflash"]
        if "dflash" in entry: regions["dflash"] = entry["dflash"]

        if args.region == "both":
            wanted = [r for r in ("pflash", "dflash") if r in regions]
        elif args.region in regions:
            wanted = [args.region]
        else:
            print(f"device '{name}' has no {args.region} region in the registry",
                  file=sys.stderr)
            return 2

        print(f"device: {name}")
        for r in wanted:
            s, e = regions[r]
            span = e - s + 1
            if r == "dflash":
                # dflash addresses count 16-bit words: each address yields
                # 2 bytes of real data, so size = 2 * (address span).
                print(f"  {r}: addresses 0x{s:08X}..0x{e:08X}  "
                      f"({span} words = {span * 2} bytes)")
            else:
                print(f"  {r}: 0x{s:08X}..0x{e:08X}  ({span} bytes)")

        if args.fast:
            actual = p.go_fast(target_baud=args.baud, osc_params=(osc_bytes_from_mhz(args.osc) if args.osc else None))
            sys.stderr.write(f"switched chip to {actual} baud\n")

        for r in wanted:
            s, e = regions[r]
            outpath = args.out_prefix + f"_{r}.bin"
            span = e - s + 1
            expected = span * 2 if r == "dflash" else span
            last = [0.0]
            def show(done: int, total: int) -> None:
                now = time.time()
                if now - last[0] > 0.2 or done == total:
                    pct = 100 * done / total if total else 0
                    sys.stderr.write(f"\r  reading {r}: {done}/{total} ({pct:5.1f}%)")
                    sys.stderr.flush()
                    last[0] = now
            data = p.read_memory(s, e, progress=show, expected_size=expected)
            sys.stderr.write("\n")
            with open(outpath, "wb") as fp:
                fp.write(data)
            crc = binascii.crc32(data) & 0xFFFFFFFF
            req = e - s + 1
            ratio_note = ""
            if len(data) != req:
                ratio_note = f"  (got {len(data)/req:.2f}x of address span)"
            print(f"  -> {outpath}  {len(data)} bytes  crc32={crc:08x}{ratio_note}")
    finally:
        p.close()
    return 0


def _validate_file(region: str, entry: dict, data: bytes) -> bytes | None:
    """Check that `data` has the right size for the chip region. Returns the
    (possibly truncated) data, or None on error (after printing to stderr)."""
    start, end = entry[region]
    bpa = 2 if region == "dflash" else 1
    expected = (end - start + 1) * bpa
    if len(data) < expected:
        print(f"file is {len(data)} B but {region} needs {expected} B",
              file=sys.stderr)
        return None
    if len(data) > expected:
        print(f"note: file is {len(data)} B, truncating to {expected} B "
              f"({region} region size)", file=sys.stderr)
        data = data[:expected]
    return data


def _diff_blocks(region: str, entry: dict, want: bytes, cur: bytes) -> list[int]:
    """Return indices of blocks where chip's content differs from `want`."""
    start, end = entry[region]
    bpa = 2 if region == "dflash" else 1
    blk_addrs = entry["block_size"]
    blk_bytes = blk_addrs * bpa
    n_blocks = (end - start + 1) // blk_addrs
    return [i for i in range(n_blocks)
            if want[i*blk_bytes:(i+1)*blk_bytes] != cur[i*blk_bytes:(i+1)*blk_bytes]]


def _program_blocks(p: "Programmer", region: str, entry: dict,
                    want: bytes, cur: bytes, blocks: list[int]) -> None:
    """Erase (if needed) and program a list of block indices. `cur` is the
    chip's pre-write content (used to decide if an erase is necessary)."""
    start, end = entry[region]
    bpa = 2 if region == "dflash" else 1
    blk_addrs = entry["block_size"]
    blk_bytes = blk_addrs * bpa
    FF = b"\xff" * blk_bytes
    for n, i in enumerate(blocks):
        addr = start + i * blk_addrs
        want_blk = want[i*blk_bytes:(i+1)*blk_bytes]
        cur_blk = cur[i*blk_bytes:(i+1)*blk_bytes]
        if cur_blk != FF:
            p.block_erase(addr, addr + blk_addrs - 1)
        if want_blk != FF:
            p.programming(addr, addr + blk_addrs - 1, want_blk,
                          bytes_per_addr=bpa, chunk_size=256)
        sys.stderr.write(f"\r  {n+1}/{len(blocks)}  block {i}  "
                         f"0x{addr:08X}")
        sys.stderr.flush()
    if blocks:
        sys.stderr.write("\n")


def _diffprogram_once(p: "Programmer", region: str, entry: dict,
                      want: bytes) -> int:
    """Read chip, compute diff, erase+program differing blocks. Returns
    number of blocks programmed."""
    start, end = entry[region]
    bpa = 2 if region == "dflash" else 1
    n_addrs = end - start + 1
    blk_addrs = entry["block_size"]
    total = n_addrs // blk_addrs
    print(f"  reading {region} for diff...")
    t0 = time.time()
    cur = p.read_memory(start, end)
    print(f"  read {n_addrs * bpa} B in {time.time()-t0:.1f} s")
    todo = _diff_blocks(region, entry, want, cur)
    print(f"  {len(todo)}/{total} blocks differ")
    if todo:
        t0 = time.time()
        _program_blocks(p, region, entry, want, cur, todo)
        print(f"  programmed in {time.time()-t0:.1f} s")
    return len(todo)


def cmd_diffprogram(args: argparse.Namespace) -> int:
    """Read the chip, diff against the file, erase+program only the blocks
    that differ. Same arguments as `program`."""
    with open(args.input, "rb") as fp:
        data = fp.read()
    p = _open_device(args)
    try:
        name, entry = _resolve_chip(p)
        if args.region not in entry:
            print(f"device '{name}' has no {args.region} region", file=sys.stderr)
            return 2
        data = _validate_file(args.region, entry, data)
        if data is None:
            return 2
        if args.fast:
            actual = p.go_fast(target_baud=args.baud, osc_params=(osc_bytes_from_mhz(args.osc) if args.osc else None))
            sys.stderr.write(f"switched chip to {actual} baud\n")
        n = _diffprogram_once(p, args.region, entry, data)
        print(f"  done: {n} block(s) updated")
    finally:
        p.close()
    return 0


def cmd_watchprogram(args: argparse.Namespace) -> int:
    """diffprogram in a loop, with an in-memory model of the chip.

    Reads the chip's region ONCE at startup; from then on every "diff" is
    file-vs-model (instant), not file-vs-chip (~22s). After a successful
    program-pass we update the model with the bytes we wrote, so it stays
    in sync. Then we pulse the chip's RESET pin so it restarts."""
    print(f"watching {args.input} (poll every {args.poll}s)")
    print("press Ctrl-C to stop")

    # --- one-time setup: identify chip, slurp initial state into the model ---
    p = _open_device(args)
    try:
        name, entry = _resolve_chip(p)
        if args.region not in entry:
            print(f"device '{name}' has no {args.region} region", file=sys.stderr)
            return 2
        start, end = entry[args.region]
        if args.fast:
            actual = p.go_fast(target_baud=args.baud, osc_params=(osc_bytes_from_mhz(args.osc) if args.osc else None))
            sys.stderr.write(f"at {actual} baud\n")
        print(f"initial chip read of {args.region}...")
        t0 = time.time()
        model = bytearray(p.read_memory(start, end))
        print(f"  {len(model)} B in {time.time()-t0:.1f} s")
        # pulse RESET so the chip restarts cleanly
        p.ser.rts = True; time.sleep(0.05); p.ser.rts = False
    finally:
        p.close()

    bpa = 2 if args.region == "dflash" else 1
    blk_addrs = entry["block_size"]
    blk_bytes = blk_addrs * bpa
    n_total = (end - start + 1) // blk_addrs

    last_mtime: float | None = None
    try:
        while True:
            try:
                cur_mtime = os.path.getmtime(args.input)
            except FileNotFoundError:
                time.sleep(args.poll)
                continue
            if cur_mtime == last_mtime:
                time.sleep(args.poll)
                continue
            last_mtime = cur_mtime
            print(f"\n[{time.strftime('%H:%M:%S')}] file changed")

            # Each iteration runs in a try-block so a transient error
            # (FTDI hiccup, chip wedged, file mid-write, etc.) is reported
            # and we keep watching instead of dying.
            try:
                with open(args.input, "rb") as fp:
                    data = fp.read()
                data = _validate_file(args.region, entry, data)
                if data is None:
                    continue
                todo = [i for i in range(n_total)
                        if data[i*blk_bytes:(i+1)*blk_bytes]
                        != bytes(model[i*blk_bytes:(i+1)*blk_bytes])]
                print(f"  {len(todo)}/{n_total} blocks differ from model")
                if not todo:
                    continue
                p = _open_device(args)
                try:
                    if args.fast:
                        p.go_fast(target_baud=args.baud,
                                  osc_params=(osc_bytes_from_mhz(args.osc)
                                              if args.osc else None))
                    t0 = time.time()
                    _program_blocks(p, args.region, entry, data,
                                    bytes(model), todo)
                    # update model to reflect what we just wrote
                    for i in todo:
                        model[i*blk_bytes:(i+1)*blk_bytes] = \
                            data[i*blk_bytes:(i+1)*blk_bytes]
                    # pulse RESET so the chip restarts
                    p.ser.rts = True
                    time.sleep(0.05)
                    p.ser.rts = False
                    print(f"  {len(todo)} block(s) in {time.time()-t0:.1f} s; "
                          f"RESET pulsed")
                finally:
                    p.close()
            except Exception as e:
                msg, hint = _friendly_error(e)
                print(f"  error this cycle: {msg}", file=sys.stderr)
                if hint:
                    print(f"  hint: {hint}", file=sys.stderr)
                print("  (still watching; touch the file again to retry)",
                      file=sys.stderr)
    except KeyboardInterrupt:
        print("\nstopped.")
    return 0


def cmd_program(args: argparse.Namespace) -> int:
    """Write a file into a flash region (pflash or dflash). The chip's
    address range for the chosen region comes from the CHIPS table; the
    file must be exactly the right size (or larger — truncated to the
    region size)."""
    with open(args.input, "rb") as fp:
        data = fp.read()
    p = _open_device(args)
    try:
        name, entry = _resolve_chip(p)
        if args.region not in entry:
            print(f"device '{name}' has no {args.region} region", file=sys.stderr)
            return 2
        start, end = entry[args.region]
        # dflash holds 2 bytes per address; pflash 1
        bytes_per_addr = 2 if args.region == "dflash" else 1
        expected = (end - start + 1) * bytes_per_addr
        if len(data) < expected:
            print(f"file is {len(data)} B but {args.region} needs {expected} B",
                  file=sys.stderr)
            return 2
        if len(data) > expected:
            print(f"note: file is {len(data)} B, truncating to {expected} B "
                  f"({args.region} region size)", file=sys.stderr)
            data = data[:expected]

        if args.fast:
            actual = p.go_fast(target_baud=args.baud, osc_params=(osc_bytes_from_mhz(args.osc) if args.osc else None))
            sys.stderr.write(f"switched chip to {actual} baud\n")

        print(f"programming {args.region} 0x{start:08X}..0x{end:08X} from "
              f"{args.input} ({len(data)} B in {args.chunk}-B chunks)")
        last = [0.0]
        def show(done: int, total: int) -> None:
            now = time.time()
            if now - last[0] > 0.2 or done == total:
                pct = 100 * done / total if total else 0
                sys.stderr.write(f"\r  {done}/{total}  ({pct:5.1f}%)")
                sys.stderr.flush()
                last[0] = now
        t0 = time.time()
        p.programming(start, end, data, bytes_per_addr=bytes_per_addr,
                      chunk_size=args.chunk, progress=show)
        sys.stderr.write("\n")
        print(f"  done in {time.time() - t0:.1f} s")
    finally:
        p.close()
    return 0


def cmd_erase(args: argparse.Namespace) -> int:
    """Erase one or both flash regions, one block at a time with progress.
    Optional --from / --to (inclusive byte addresses) erase only a sub-range
    of the chosen region; both must be block-aligned (start aligned, end at
    one-less-than-block-aligned)."""
    p = _open_device(args)
    try:
        name, entry = _resolve_chip(p)
        if "block_size" not in entry:
            print(f"CHIPS['{name}'] is missing 'block_size'", file=sys.stderr)
            return 2
        BLK = entry["block_size"]

        regions = {}
        if "pflash" in entry: regions["pflash"] = entry["pflash"]
        if "dflash" in entry: regions["dflash"] = entry["dflash"]
        if args.region == "both":
            wanted = [r for r in ("pflash", "dflash") if r in regions]
        elif args.region in regions:
            wanted = [args.region]
        else:
            print(f"device '{name}' has no {args.region} region", file=sys.stderr)
            return 2

        # Honor partial sub-range only when a single region is specified.
        sub_specified = (args.from_ is not None or args.to is not None
                         or args.from_block is not None or args.to_block is not None)
        if sub_specified and len(wanted) != 1:
            print("--from/--to/--from-block/--to-block only valid with a single region",
                  file=sys.stderr)
            return 2
        if (args.from_ is not None and args.from_block is not None) or \
           (args.to is not None and args.to_block is not None):
            print("specify either byte-address (--from/--to) or block-index "
                  "(--from-block/--to-block), not both", file=sys.stderr)
            return 2

        if args.fast:
            actual = p.go_fast(target_baud=args.baud, osc_params=(osc_bytes_from_mhz(args.osc) if args.osc else None))
            sys.stderr.write(f"switched chip to {actual} baud\n")

        for r in wanted:
            r_start, r_end = regions[r]
            if args.from_block is not None:
                sub_start = r_start + args.from_block * BLK
            elif args.from_:
                sub_start = int(args.from_, 0)
            else:
                sub_start = r_start
            if args.to_block is not None:
                sub_end = r_start + (args.to_block + 1) * BLK - 1
            elif args.to:
                sub_end = int(args.to, 0)
            else:
                sub_end = r_end
            if sub_start < r_start or sub_end > r_end:
                print(f"--from/--to out of {r} range "
                      f"0x{r_start:08X}..0x{r_end:08X}", file=sys.stderr)
                return 2
            if sub_start % BLK or (sub_end + 1) % BLK:
                print(f"sub-range must align to block_size 0x{BLK:X}",
                      file=sys.stderr)
                return 2
            nblocks = (sub_end - sub_start + 1) // BLK
            print(f"erasing {r}: {nblocks} block(s) "
                  f"0x{sub_start:08X}..0x{sub_end:08X}")
            t0 = time.time()
            if args.force_per_block:
                for i in range(nblocks):
                    blk_lo = sub_start + i * BLK
                    blk_hi = blk_lo + BLK - 1
                    p.block_erase(blk_lo, blk_hi)
                    done = i + 1
                    pct = 100 * done / nblocks
                    sys.stderr.write(
                        f"\r  {done}/{nblocks} blocks  "
                        f"0x{blk_lo:08X}..0x{blk_hi:08X}  ({pct:5.1f}%)")
                    sys.stderr.flush()
                sys.stderr.write("\n")
            else:
                # one BLOCK_ERASE for the whole contiguous range — the chip
                # handles the parallel erase internally and ACKs once when done
                p.block_erase(sub_start, sub_end)
            print(f"  done in {time.time() - t0:.1f} s")
    finally:
        p.close()
    return 0


def decode_signature(sig: bytes) -> dict:
    """Parse the SILICON_SIGNATURE (cmd 0xC0) response payload.

    Layout (24 bytes total), reverse-engineered from live captures:
      0      TYP    device-family type byte (0x10 = V850E2)
      1      DEV    device version / variant
      2      NMC    count field (1 in samples we've seen)
      3..12  NAM    device name, 10 ASCII bytes, space-padded
     13..16  EAD1   end of code flash, LE32 (implicit start 0)
     17..20  EAD2   end of data flash, LE32 (= 0 if no dflash on this part)
     21..23  FVER   boot-ROM firmware version, 3 nibbles, formatted "X.XX"

    Tested against D70F3525 (v4.00) and D70F3539A (v1.00).
    """
    out: dict = {"raw": sig}
    if len(sig) >= 13:
        out["type"] = sig[0]
        out["version"] = sig[1]
        out["count"] = sig[2]
        out["name"] = sig[3:13].rstrip(b" \x00").decode("ascii", "replace")
    if len(sig) >= 17:
        out["pflash_end"] = int.from_bytes(sig[13:17], "little")
    if len(sig) >= 21:
        out["dflash_end"] = int.from_bytes(sig[17:21], "little")
    if len(sig) >= 24:
        # boot-ROM firmware version: 3 hex nibbles formatted as "X.XX"
        out["fw_version"] = f"{sig[21]:X}.{sig[22]:X}{sig[23]:X}"
    return out


def cmd_info(args: argparse.Namespace) -> int:
    p = _open_device(args)
    try:
        try:
            sig = p.silicon_signature(opcode=args.opcode)
        except IOError as e:
            print(f"signature query failed ({e})", file=sys.stderr)
            return 1
    finally:
        p.close()

    info = decode_signature(sig)
    entry = CHIPS.get(info.get("name", ""))
    blk = entry.get("block_size") if entry else None

    def blk_note(size_bytes: int) -> str:
        return f", {size_bytes // blk} blocks of {blk} B" if blk else ""

    print(f"raw    : {sig.hex(' ')}")
    if "name" in info:
        print(f"device : {info['name']}  "
              f"(type=0x{info['type']:02X}, ver=0x{info['version']:02X}, "
              f"count=0x{info['count']:02X})")
    if "pflash_end" in info:
        size = info["pflash_end"] + 1
        print(f"pflash : 0x00000000..0x{info['pflash_end']:08X}  "
              f"({size // 1024} KiB{blk_note(size)})")
    if "dflash_end" in info:
        # dflash region (on D70F3525) starts at 0x02000000; signature reports
        # the end as 0x02007FFF and the chip returns 64 KiB on a read of that
        # range, so we present the part as having 64 KiB of dflash byte-data.
        # Parts without data flash (e.g. D70F3539A) report dflash_end = 0.
        d_start = 0x02000000
        d_end = info["dflash_end"]
        if d_end == 0:
            print("dflash : (none reported)")
        elif d_end >= d_start:
            span = d_end - d_start + 1
            print(f"dflash : 0x{d_start:08X}..0x{d_end:08X}  "
                  f"({span * 2 // 1024} KiB{blk_note(span * 2)})")
        else:
            print(f"dflash : (raw end=0x{d_end:08X}, unparseable)")
    if "fw_version" in info:
        print(f"bootrom: v{info['fw_version']}")
    if entry and "bauds" in entry:
        rates = [9600] + sorted(entry["bauds"])
        print(f"bauds  : {', '.join(str(r) for r in rates)}")
    elif entry is None and "name" in info:
        print(f"bauds  : 9600 (chip not in CHIPS registry, add to enable --fast)")
    return 0


# ---------------------------------------------------------------------------
# main

SCHEMATIC = r"""
V850E2 single-wire UART boot programmer wiring

    ╔═══════╗                                     ╔═════════╗
    ║       ║ GND ◄━━━━━━━━━━━━━━━━━━━━━━━►   GND ║         ║
    ║       ║ VCC ◄━━━━━━━━━━━━━━━━━━━*━━━► FLMD0 ║         ║
    ║       ║                         ╰━━━►   VCC ║         ║
    ║  FTDI ║ TX  ━━[1 kΩ]━━━┳━━━━━━━━━━━━► TX/RX ║ 70F3xxx ║
    ║ FT232 ║ RX  ◄━━━━━━━━━━╯                    ║ TARGET  ║
    ║       ║ RTS ━━━━━━━━━━━━━━━━━━━━━━━━► RESET ║         ║
    ║       ║ DTR                                 ║         ║
    ╚═══════╝                                     ╚═════════╝

Notes:
  * May need external VCC supply or a powered Targetboard.
  * Match FTDI VCCIO to chip VCC (3.3 V or 5 V) - jumper on the module.
  * If the chip has an FLMD1 pin, tie it to GND.


Examples:
  v850flash.py id                            chip info
  v850flash.py dump   pflash -o backup       backup → backup_pflash.bin
  v850flash.py erase  pflash                 wipe pflash (destructive)
  v850flash.py program pflash firmware.bin   write (must be erased first)
  v850flash.py diffprogram pflash fw.bin     write only changed blocks
  v850flash.py watchprogram pflash fw.bin    re-diff-program on file change

Add `-h` to any subcommand for its specific flags.
"""


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="V850E2 boot-protocol tool" + SCHEMATIC,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = ap.add_subparsers(dest="mode")

    def _add_port_opts(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("-p", "--port", default="/dev/ttyUSB0")
        sp.add_argument("--timeout", type=float, default=2.0)
        sp.add_argument("--debug", action="store_true")

    def _add_speed_opts(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--fast", action="store_true", default=True,
                        help="step chip up to a higher baud before operating (default)")
        sp.add_argument("--slow", dest="fast", action="store_false",
                        help="stay at 9600 baud")
        sp.add_argument("-b", "--baud", type=int, default=None,
                        help="explicit baud to step up to "
                             "(default: chip's max in CHIPS table)")
        sp.add_argument("--osc", type=float, default=None, metavar="MHZ",
                        help="override the chip's oscillator frequency (MHz); "
                             "default: value from CHIPS table for this chip")

    p_read = sub.add_parser("read", help="read a memory range from a live device")
    _add_port_opts(p_read)
    p_read.add_argument("--start", required=True,
                        help="start address (e.g. 0x00000000)")
    p_read.add_argument("--end", required=True,
                        help="end address inclusive (e.g. 0x001FFFFF)")
    p_read.add_argument("-o", "--out", required=True)
    _add_speed_opts(p_read)
    p_read.set_defaults(func=cmd_read)

    p_info = sub.add_parser("id", aliases=["info"],
                            help="read silicon signature and print device info")
    _add_port_opts(p_info)
    p_info.add_argument("--opcode", type=lambda s: int(s, 0), default=0xC0,
                        help="signature command byte (default 0xC0)")
    p_info.set_defaults(func=cmd_info)

    p_dump = sub.add_parser("dump", help="dump pflash, dflash, or both (uses signature for ranges)")
    _add_port_opts(p_dump)
    p_dump.add_argument("region", choices=["pflash", "dflash", "both"])
    p_dump.add_argument("-o", "--out-prefix", default="dump",
                        help="prefix for output files (default 'dump')")
    _add_speed_opts(p_dump)
    p_dump.set_defaults(func=cmd_dump)

    p_erase = sub.add_parser("erase", help="erase pflash, dflash, or both (destructive)")
    _add_port_opts(p_erase)
    p_erase.add_argument("region", choices=["pflash", "dflash", "both"])
    p_erase.add_argument("--from", dest="from_", metavar="ADDR", default=None,
                         help="first byte of sub-range (default: region start; "
                              "block-aligned; only valid for a single region)")
    p_erase.add_argument("--to", metavar="ADDR", default=None,
                         help="last byte of sub-range, inclusive (default: region end; "
                              "must be (n*block_size - 1))")
    p_erase.add_argument("--from-block", dest="from_block", type=lambda s: int(s, 0),
                         metavar="N", default=None,
                         help="first block index within the region (0-based; "
                              "alternative to --from)")
    p_erase.add_argument("--to-block", dest="to_block", type=lambda s: int(s, 0),
                         metavar="N", default=None,
                         help="last block index within the region, inclusive "
                              "(alternative to --to)")
    p_erase.add_argument("--force-per-block", action="store_true",
                         help="issue one BLOCK_ERASE per block instead of one "
                              "command for the whole range (slower, but shows "
                              "per-block progress and isolates failures)")
    _add_speed_opts(p_erase)
    p_erase.set_defaults(func=cmd_erase)

    p_prog = sub.add_parser("program", help="write a file into pflash or dflash (destructive)")
    _add_port_opts(p_prog)
    p_prog.add_argument("region", choices=["pflash", "dflash"])
    p_prog.add_argument("input",
                        help="file with bytes to write (must match region size: "
                             "pflash = address span, dflash = 2 × address span)")
    p_prog.add_argument("--chunk", type=lambda s: int(s, 0), default=256,
                        help="data-frame chunk size (default 256, max per spec)")
    _add_speed_opts(p_prog)
    p_prog.set_defaults(func=cmd_program)

    p_diff = sub.add_parser("diffprogram",
                            help="read chip, diff vs file, program only changed blocks")
    _add_port_opts(p_diff)
    p_diff.add_argument("region", choices=["pflash", "dflash"])
    p_diff.add_argument("input",
                        help="file with the desired bytes (same size as `program`)")
    _add_speed_opts(p_diff)
    p_diff.set_defaults(func=cmd_diffprogram)

    p_watch = sub.add_parser("watchprogram",
                             help="diffprogram in a loop: watch the file, re-diff "
                                  "and re-program on change, then pulse the chip RESET")
    _add_port_opts(p_watch)
    p_watch.add_argument("region", choices=["pflash", "dflash"])
    p_watch.add_argument("input")
    p_watch.add_argument("--poll", type=float, default=1.0,
                         help="how often to check the file (seconds, default 1.0)")
    _add_speed_opts(p_watch)
    p_watch.set_defaults(func=cmd_watchprogram)

    args = ap.parse_args(argv)
    if not args.mode:
        ap.print_help()
        return 0
    debug = getattr(args, "debug", False)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\ninterrupted.", file=sys.stderr)
        return 130
    except Exception as e:
        if debug:
            raise
        msg, hint = _friendly_error(e)
        print(f"error: {msg}", file=sys.stderr)
        if hint:
            print(f"hint:  {hint}", file=sys.stderr)
        print("(re-run with --debug for the full Python traceback)",
              file=sys.stderr)
        return 1


def _friendly_error(exc: BaseException) -> tuple[str, str | None]:
    """Map a low-level exception into (one-line message, optional hint)."""
    # serial port problems
    if serial is not None and isinstance(exc, serial.SerialException):
        s = str(exc)
        if "could not open port" in s or "No such file" in s:
            return ("FTDI serial port not available",
                    "is the FTDI plugged in? check `ls /dev/ttyUSB*` "
                    "and that you have permission to access it")
        if "readiness to read" in s:
            return ("USB serial link dropped mid-operation",
                    "the FTDI got unplugged or reset; reconnect and retry")
        return (f"serial error: {s}", None)
    # input file problems
    if isinstance(exc, FileNotFoundError):
        return (f"file not found: {exc.filename}", None)
    if isinstance(exc, IsADirectoryError):
        return (f"expected a file, got a directory: {exc.filename}", None)
    # protocol/IO errors raised by our own code
    if isinstance(exc, IOError):
        s = str(exc)
        if "read timeout" in s:
            return ("no response from chip",
                    "check: chip powered? FLMD0=VCC? RESET line working? "
                    "is another programmer holding the bus?")
        if "echo timeout" in s:
            return ("our TX bytes did not echo back on RX",
                    "the FTDI's TX or RX wire is disconnected, "
                    "or the chip is driving the line constantly")
        if "bad header" in s:
            return (f"unexpected chip response framing ({s})",
                    "session may be desynchronised; pulse RESET and retry")
        if "bad footer" in s:
            return (f"chip response framing error ({s})",
                    "session may be desynchronised; pulse RESET and retry")
        if "bad checksum" in s:
            return (f"chip response failed checksum ({s})",
                    "line noise? lower baud or check wiring")
        if "expected ACK" in s:
            return (f"chip rejected the command: {s}", None)
        return (f"chip protocol error: {s}", None)
    if isinstance(exc, ValueError):
        return (str(exc), None)
    if isinstance(exc, RuntimeError):
        return (str(exc), None)
    return (f"{type(exc).__name__}: {exc}", None)


if __name__ == "__main__":
    raise SystemExit(main())
