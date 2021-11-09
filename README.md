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
Unknown subcommand
Available subcommands: (append --help to subcommand for details)
  usb list - List all RoTs connected via USB.
  ec_reboot - Reboot the RoT.
  ec_get_version - Get the version of the RoT firmware.
  show chipinfo - Return details about this specific RoT chip.
  spi read - Read from SPI flash into a file
  spi update - Write a file to SPI flash (erase + program).
  target reset on - Put the target device into reset.
  target reset off - Take the target device out of reset
  target reset pulse - Quickly put the target device in and out of reset
  console - Open a console for communicating with the RoT or devices attached to the RoT

Global flags:
  --usb_loc (default: "")
        The full bus-portlist location of the RoT; for example '1-10.4.4.1'.
  --usb_product (default: "")
        If there is a single USB RoT with this substring in the USB product string, use it.
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

