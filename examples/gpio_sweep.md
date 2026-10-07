# `htool gpio sweep` User Guide

This guide explains how to configure and run `htool gpio sweep` to step through GPIO drive strengths for SPI interfaces (`spidev`, `spihost0`, `spihost1`) during signal integrity (SI) validation with an oscilloscope.

---

## 1. Overview

When tuning SPI signal integrity on OpenTitan / RoT platforms, an engineer needs to evaluate different drive strength settings (`0`, `1`, `2`, `3`) on the pads belonging to an SPI interface (`clk`, `cs`, `d0`, `d1`, `d2`, `d3`).

`htool gpio sweep` reads a simple, human-readable configuration file and interactively steps through each configured drive strength for the selected SPI interface:
1. `htool` connects to the RoT (typically over USB via `--transport usb`) and saves the initial GPIO drive strength of all 6 pads (`clk`, `cs`, `d0`–`d3`).
2. For each configured drive strength value (in the exact order listed in `<spi>.drive_strengths`), `htool` applies that drive strength to all configured pads (`clk`, `cs`, `d0`–`d3`) of the selected SPI target (`spidev`, `spihost0`, or `spihost1`), reading back each pad immediately after setting it and printing a warning if the readback value does not match.
3. `htool` pauses and waits for `Enter` from the user.
4. While paused, the engineer triggers SPI traffic on the bus and captures the waveforms on an oscilloscope.
5. Pressing `Enter` advances to the next drive strength value (or `q` + `Enter` exits early).
6. On exit—whether normal completion, `q`, `EOF`, a failed `set`, or `Ctrl-C` (`SIGINT` / `SIGTERM` / `SIGHUP`)—`htool` automatically restores the original drive strengths for all 6 pads. `Ctrl-C` (`SIGINT` / `SIGTERM` / `SIGHUP`) is held (blocked) during the initial save, during each 6-pad `set` step, and during restore so device transfers are never interrupted mid-command and all 6 pads are restored before exiting.

---

## 2. Configuration File Format

The configuration file uses flat `key = value` lines with zero external library dependencies.
- Lines starting with `#` or `;` are treated as comments.
- Blank lines and surrounding whitespace are ignored.

Look at [`gpio_sweep.conf.example`](./gpio_sweep.conf.example) for a complete template:

```ini
# 1. SPI Device (spidev)
spidev.clk = DIO12
spidev.cs = DIO13
spidev.d0 = DIO6
spidev.d1 = DIO7
spidev.d2 = DIO8
spidev.d3 = DIO9
spidev.drive_strengths = 0, 1, 2, 3

# 2. SPI Host 0 (spihost0)
spihost0.clk = DIO14
spihost0.cs = DIO15
spihost0.d0 = DIO2
spihost0.d1 = DIO3
spihost0.d2 = DIO4
spihost0.d3 = DIO5
spihost0.drive_strengths = 0, 1, 2, 3

# 3. SPI Host 1 (spihost1) - uncomment and set board-specific MIO pads
# spihost1.clk = MIO0
# spihost1.cs = MIO1
# spihost1.d0 = MIO2
# spihost1.d1 = MIO3
# spihost1.d2 = MIO4
# spihost1.d3 = MIO5
# spihost1.drive_strengths = 0, 1, 2, 3
```

### Supported Signal Names
All 6 signal mappings must be specified for a configured SPI interface (`<spi>` is `spidev`, `spihost0`, or `spihost1`):
- Clock: `<spi>.clk`
- Chip Select: `<spi>.cs`
- Data 0: `<spi>.d0`
- Data 1: `<spi>.d1`
- Data 2: `<spi>.d2`
- Data 3: `<spi>.d3`

### Supported Pad Names

Pads are specified as `DIO0`–`DIO15` or `MIO0`–`MIO46` (case-insensitive), matching the `--dio` and `--mio` indices used by `htool gpio set_drive_strength`:

| Pad Type | Config Specifier | Hardware Mapping |
| :--- | :--- | :--- |
| **DIO (Dedicated IO)** | `DIO0`–`DIO15` | `DIO0` (`USB_DP`)<br>`DIO1` (`USB_DN`)<br>`DIO2`–`DIO5` (`SPI_HOST0_D0`–`SPI_HOST0_D3`)<br>`DIO6`–`DIO9` (`SPI_DEV_D0`–`SPI_DEV_D3`)<br>`DIO10` (`EC_RST_L`)<br>`DIO11` (`FLASH_WP_L`)<br>`DIO12` (`SPI_DEV_CLK`)<br>`DIO13` (`SPI_DEV_CSB`)<br>`DIO14` (`SPI_HOST0_CLK`)<br>`DIO15` (`SPI_HOST0_CSB`) |
| **MIO (Muxed IO)** | `MIO0`–`MIO46` | `MIO0`–`MIO8` (`IOA0`–`IOA8`)<br>`MIO9`–`MIO21` (`IOB0`–`IOB12`)<br>`MIO22`–`MIO34` (`IOC0`–`IOC12`)<br>`MIO35`–`MIO42` (`IOR0`–`IOR7`)<br>`MIO43`–`MIO46` (`IOR10`–`IOR13`) |

### Supported Drive Strengths
- Valid values in `<spi>.drive_strengths`: **`0`, `1`, `2`, `3`**.
- Drive strengths are swept in the exact order written in `<spi>.drive_strengths` (e.g., `3, 2, 1, 0` sweeps from `3` down to `0`; duplicate entries are deduplicated to their first occurrence).
- Values outside `0..3` are rejected by the parser.

---

## 3. Running `htool gpio sweep`

### Command Syntax

```bash
htool --transport usb gpio sweep --config <path/to/config.conf> --spi <spidev|spihost0|spihost1> [--dry_run]
```

Short flags are also supported:
- `-c`: `--config`
- `-s`: `--spi`
- `-n`: `--dry_run` (preview the interactive sweep sequence and pad mapping without connecting to a physical RoT device)

### Examples

#### Preview Sweep with `--dry_run` (No Hardware Needed)
```bash
htool gpio sweep -c libhoth/examples/gpio_sweep.conf.example -s spihost0 --dry_run
```

#### Sweep `spidev` Drive Strengths
```bash
htool --transport usb gpio sweep -c libhoth/examples/gpio_sweep.conf.example -s spidev
```

#### Sweep `spihost0` Drive Strengths
```bash
htool --transport usb gpio sweep -c libhoth/examples/gpio_sweep.conf.example -s spihost0
```

#### Sweep `spihost1` Drive Strengths
```bash
htool --transport usb gpio sweep -c libhoth/examples/gpio_sweep.conf.example -s spihost1
```

### Example Interactive Session Output

```text
Saved original GPIO drive strengths for spihost0 pads (clk [DIO14]=0, cs [DIO15]=0, d0 [DIO2]=0, d1 [DIO3]=0, d2 [DIO4]=0, d3 [DIO5]=0).
[1/4] Applied drive_strength=0 to spihost0 pads (clk [DIO14]=0, cs [DIO15]=0, d0 [DIO2]=0, d1 [DIO3]=0, d2 [DIO4]=0, d3 [DIO5]=0).
Trigger SPI traffic and capture signals now. Press Enter for next combination (or 'q' + Enter to quit):
[2/4] Applied drive_strength=1 to spihost0 pads (clk [DIO14]=1, cs [DIO15]=1, d0 [DIO2]=1, d1 [DIO3]=1, d2 [DIO4]=1, d3 [DIO5]=1).
Trigger SPI traffic and capture signals now. Press Enter for next combination (or 'q' + Enter to quit):
[3/4] Applied drive_strength=2 to spihost0 pads (clk [DIO14]=2, cs [DIO15]=2, d0 [DIO2]=2, d1 [DIO3]=2, d2 [DIO4]=2, d3 [DIO5]=2).
Trigger SPI traffic and capture signals now. Press Enter for next combination (or 'q' + Enter to quit):
[4/4] Applied drive_strength=3 to spihost0 pads (clk [DIO14]=3, cs [DIO15]=3, d0 [DIO2]=3, d1 [DIO3]=3, d2 [DIO4]=3, d3 [DIO5]=3).
Trigger SPI traffic and capture signals now. Press Enter for next combination (or 'q' + Enter to quit):
GPIO drive strength sweep completed.
Restored original GPIO drive strengths for spihost0 pads (clk [DIO14]=0, cs [DIO15]=0, d0 [DIO2]=0, d1 [DIO3]=0, d2 [DIO4]=0, d3 [DIO5]=0).
```

*(If any pad's readback value differs from the requested drive strength, a warning is printed to `stderr` and the step line reports `Applied (with readback mismatch)` alongside the actual readback value for each pad. When running with `--dry_run`, each step prefixes `[Dry Run] `, lists the mapped pads without `=N` readback values, and still pauses for `Enter` so you can verify the parsed config and interactive flow without hardware.)*
