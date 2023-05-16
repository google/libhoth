# libhoth

This repository contains a libraries and example programs for interacting with
a hoth-class root of trust.

# Build via meson

```
$ meson build
$ (cd build && ninja)
$ build/examples/htool
```

# Build via Bazel

```
$ bazel build ...
$ bazel-bin/examples/htool
```

# examples/htool

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
  target reset on - Put the target device into reset.
  target reset off - Take the target device out of reset
  target reset pulse - Quickly put the target device in and out of reset
  console - Open a console for communicating with the RoT or devices attached to the RoT.
  payload status - Show payload status
  flash_spi_info - Get SPI NOR flash info.
  statistics - Show statistics
  get_panic - Retrieve or clear the stored panic record.
  authz_record read - Read the current authorization record
  authz_record erase - Erase the current authorization record
  authz_record build - Build an empty authorization record for the chip
  authz_record set - Upload an authorization record to the chip

Global flags:
  --transport (default: "")
        The method of connecting to the RoT; for example 'spidev'/'usb'/'mtd'
  --usb_loc (default: "")
        The full bus-portlist location of the RoT; for example '1-10.4.4.1'.
  --usb_product (default: "")
        If there is a single USB RoT with this substring in the USB product string, use it.
  --spidev_path (default: "")
        The full SPIDEV path of the RoT; for example '/dev/spidev0.0'.
  --mtddev_path (default: "")
        The full MTD path of the RoT mailbox; for example '/dev/mtd0'. If unspecified, will attempt to detect the correct device automatically
  --mtddev_name (default: "hoth-mailbox")
        The MTD name of the RoT mailbox; for example 'hoth-mailbox'.
  --mailbox_location (default: "0")
        The location of the mailbox on the RoT, for 'spidev' or 'mtd' transports; for example '0x900000'.
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
```

