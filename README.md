# libhoth

This repository contains a libraries and example programs for interacting with
a hoth-class root of trust.

## Prerequisites

To build libhoth, you will need `meson`, `ninja`, and several development libraries. On Ubuntu/Debian, you can install them with:

```bash
sudo apt-get update
sudo apt-get install meson libusb-1.0-0-dev libsystemd-dev libcap-dev libgtest-dev
```

## Build via Meson

```bash
meson build
ninja -C build
./build/examples/htool
```

### Running Tests (Meson)

```bash
meson test -C build
```

### Optional: D-Bus Backend (Meson)

To enable the D-Bus backend:

```bash
meson build -Ddbus_backend=true
ninja -C build
```

## Build via Bazel

```bash
bazel build //...
./bazel-bin/examples/htool
```

### Running Tests (Bazel)

```bash
bazel test //...
```

### Optional: D-Bus Backend (Bazel)

To enable the D-Bus backend:

```bash
bazel build --define dbus_backend=true //examples:htool
```

## examples/htool

htool is a command line tool for performing basic actions against a hoth RoT.

```
$ htool
Available subcommands: (append --help to subcommand for details)
  usb list - List all RoTs connected via USB.
  reboot - Reboot the RoT.
  show firmware_version - Get the version of the RoT firmware.
  show chipinfo - Return details about this specific RoT chip.
  spi read - Read from SPI flash into a file
  spi update - Write a file to SPI flash (erase + program).
  spi passthrough on/off - Enable/Disable SPS->SPI passthrough.
  target reset on/off/pulse - Control the target device reset pin.
  console - Open a console for communicating with the RoT.
  payload status/update/read/info - Manage Titan payload images.
  dfu update/check - Directly install or verify PIE-RoT firmware updates.
  flash_spi_info - Get SPI NOR flash info.
  statistics - Show statistics.
  get_panic - Retrieve or clear the stored panic record.
  authz_record read/erase/build/set - Manage authorization records.
  i2c detect/read/write/muxctrl - Perform I2C transactions or control I2C mux.
  rot_usb muxctrl - Control USB mux select.
  jtag read_idcode/test_bypass/verify_pld - Perform JTAG operations.
  storage read/write/delete - Manage controlled storage.

Global flags:
  --transport (default: "")
        The method of connecting to the RoT; for example 'spidev'/'usb'/'mtd'/'dbus'
  --usb_loc (default: "")
        The full bus-portlist location of the RoT; for example '1-10.4.4.1'.
  --usb_product (default: "")
        If there is a single USB RoT with this substring in the USB product string, use it.
  --spidev_path (default: "")
        The full SPIDEV path of the RoT; for example '/dev/spidev0.0'.
  --spidev_atomic (default: "false")
        If true, force spidev to use a single atomic ioctl.
  --mtddev_path (default: "")
        The full MTD path of the RoT mailbox; for example '/dev/mtd0'.
  --mtddev_name (default: "hoth-mailbox")
        The MTD name of the RoT mailbox.
  --mailbox_location (default: "0")
        The location of the mailbox on the RoT.
  --dbus_hoth_id (default: "")
        The hoth ID associated with the RoT's hothd service.
  --connect_timeout (default: "10s")
        Maximum duration to retry opening a busy transport.
```

```
$ htool usb list
  --usb_loc 1-10.4.2 - Hoth D (foobar)
```

```
htool spi update --help
Usage: spi update <source-file>
  -s --start (default: "0")
        start address
  -v --verify (default: "true")
  -a --address_mode (default: "3B/4B")

$ echo "Hello world" > /tmp/hello
$ htool spi update -s 0x5000 /tmp/hello
Erasing/Programming:  100% - 0kB / 0kB  104 kB/sec; 0.0 s remaining
Verifying:  100% - 0kB / 0kB  503 kB/sec; 0.0 s remaining
```

```
$ htool spi read --help
Usage: spi read <dest-file>
  -s --start (default: "0")
        start address
  -n --length
  -a --address_mode (default: "3B/4B")

$ htool spi read -s 0x5000 -n 16 /dev/stdout | hexdump -C
Reading:  100% - 0kB / 0kB  514 kB/sec; 0.0 s remaining
00000000  48 65 6c 6c 6f 20 77 6f  72 6c 64 0a ff ff ff ff  |Hello world.....|
00000010
```

```
$ htool console --help
Usage: console
  -c --channel
        Which channel to talk to. Typically a fourcc code.
  -f --force_drive_tx (default: "0")
        Drive the UART's TX net even if Hoth isn't sure whether some other device else is driving it. Only use this option if you are CERTAIN there is no debugging hardware attached.
  -h --history (default: "false")
        Include data bufferred before the current time.
  -n --onlcr (default: "false")
        Translate received "\n" to "\r\n".
  -b --baud_rate (default: "0")
  -s --snapshot (default: "false")
        Print a snapshot of most recent console messages.
```

