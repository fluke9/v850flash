# v850flash

A small, single-file command-line tool to read, erase and program the
internal flash of Renesas **V850E2** microcontrollers over their
single-wire UART boot protocol — using nothing more than an FTDI USB‑to‑
serial adapter and a single resistor.

## What it does

| subcommand | description |
|---|---|
| `id` | identify the chip (signature, flash sizes, supported bauds) |
| `dump` | read pflash / dflash / both to a file |
| `erase` | erase pflash / dflash / both (block-granular) |
| `program` | write a file into a region (region must be erased first) |
| `diffprogram` | read chip, diff against file, only program changed blocks |
| `watchprogram` | edit-build-flash loop: watches a file, re-diff-programs on change |
| `read` | dump an arbitrary address range |

All operations work at 1 Mbps on hardware that supports it (most do); a
full 2 MiB pflash dump takes ~22 s, a full erase+program cycle ~90 s.

## Hardware setup

```
    ╔═══════╗                                     ╔═════════╗
    ║       ║ GND ◄━━━━━━━━━━━━━━━━━━━━━━━►   GND ║         ║
    ║       ║ VCC ◄━━━━━━━━━━━━━━━━━━━*━━━► FLMD0 ║         ║
    ║       ║                         ╰━━━►   VCC ║         ║
    ║  FTDI ║ TX  ━━[1 kΩ]━━━┳━━━━━━━━━━━━► TX/RX ║ 70F3xxx ║
    ║ FT232 ║ RX  ◄━━━━━━━━━━╯                    ║ TARGET  ║
    ║       ║ RTS ━━━━━━━━━━━━━━━━━━━━━━━━► RESET ║         ║
    ║       ║ DTR                                 ║         ║
    ╚═══════╝                                     ╚═════════╝
```

That's the whole BOM: a 3.3 V or 5 V FTDI breakout, **one 1 kΩ resistor**, a
few jumper wires, and a powered target board (or external VCC supply).

Notes:
* Match the FTDI's VCCIO to the chip's VCC (3.3 V or 5 V) — usually a
  jumper on the breakout.
* The 1 kΩ on TX is what makes single-wire half-duplex work: the chip's
  push-pull drive wins easily; FTDI's idle-HIGH only sources a few mA.
* If your chip has an `FLMD1` pin, tie it to GND.
* RTS is pulsed to drive the chip's RESET line.

## Software setup

Only requirement is `pyserial`:

```sh
pip install pyserial
```

Then run the tool directly:

```sh
python3 v850flash.py
```

## Quick start

```sh
# what chip is connected?
python3 v850flash.py id

# back up everything before doing anything destructive
python3 v850flash.py dump both -o backup

# wipe pflash
python3 v850flash.py erase pflash

# write new firmware into pflash
python3 v850flash.py program pflash new_firmware.bin

# faster: only rewrite blocks that differ
python3 v850flash.py diffprogram pflash new_firmware.bin

# dev loop: watch a file, re-flash-and-reset on every change
python3 v850flash.py watchprogram pflash build/firmware.bin
```

Add `-h` to any subcommand for its flags. See `python3 v850flash.py` (no
args) for the full schematic + examples in the terminal.

## Supported chips

Out of the box the tool ships with entries for two parts:

* **µPD70F3525** — V850E2/Fx4-L, 2 MiB pflash + 64 KiB dflash
* **µPD70F3539A** — V850E2/Dx4-3D, 2 MiB pflash, no dflash

Both were tested on real hardware end-to-end (read, erase, program,
verify).

## Adding a new chip

Most V850E2 parts speak the same protocol — adding support typically
means filling in a single dictionary entry. When the tool encounters a
chip it doesn't know it prints a copy-pasteable template, e.g.:

```
chip 'D70F3999' is not in the CHIPS registry (known: D70F3525, D70F3539A).
  add an entry to CHIPS in v850flash.py:
    "D70F3999": {
        "pflash":     (0x00000000, 0x????????),   # signature says end=0x003FFFFF
        # "dflash":   (0x02000000, 0x????????),   # if the chip has one
        "block_size": 0x1000,                     # 4 KiB on every V850E2 we have seen
        "osc_mhz":    4,                          # actual board oscillator frequency in MHz
        "bauds":      {115200: 0x01, 500000: 0x02, 1000000: 0x03},
    },
```

Fill in:
* the **pflash** end address from the chip's datasheet
* **dflash** (if present)
* **osc_mhz** for your board's actual oscillator (the only field that's
  truly board-specific)

Most other settings (block size, baud table, opcodes) are common across
the V850E2 family.

**Pull requests adding new chip entries are very welcome** — please
include a one-line note about which board/setup you tested on.

## Status

Working and used in production for restoring/reflashing automotive
instrument clusters. The protocol primitives (Frame encoding, command
flow, end-of-stream terminator handling) are well-understood. The CHIPS
table is the only thing that needs to grow.

## Credits

Co-authored with [Claude](https://claude.com/claude-code) (Anthropic) —
protocol reverse-engineering from sniffed traffic, frame decoding, and
the bulk of the tool's Python.

## License

MIT — see [LICENSE](LICENSE).
