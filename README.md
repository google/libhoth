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
Unknown subcommand
Available subcommands: (append --help to subcommand for details)
  usb list - List all RoTs connected via USB.
  reboot - Reboot the RoT.
  show firmware_version - Get the version of the RoT firmware.
  show chipinfo - Return details about this specific RoT chip.
  spi read - Read from SPI flash into a file
  spi update - Write a file to SPI flash (erase + program).
  spi passthrough off - Disable SPS->SPI passthrough
  spi passthrough on - Enable SPS->SPI passthrough
  target reset on - Put the target device into reset.
  target reset off - Take the target device out of reset
  target reset pulse - Quickly put the target device in and out of reset
  console - Open a console for communicating with the RoT or devices attached to the RoT.
  payload getstatus - Show the current payload update status
  payload status - Show payload status
  payload update - Perform payload update protocol for Titan images.
  payload read - Read content of staging flash for Titan images.
  payload info - Display payload info for a Titan image.
  firmware_update update_from_flash_and_reset - Installs a firmware update from a bundle staged in the external flash.
  dfu update - Directly install a PIE-RoT fwupdate.
  dfu check - Check that the device is running firmware matching a fwupdate bundle.
  flash_spi_info - Get SPI NOR flash info.
  statistics - Show statistics
  get_panic - Retrieve or clear the stored panic record.
  authz_record read - Read the current authorization record
  authz_record erase - Erase the current authorization record
  authz_record build - Build an empty authorization record for the chip
  authz_record set - Upload an authorization record to the chip
  authz_host_command build - Build an authorized host command
  authz_host_command send - Send an authorized host command
  arm_coordinated_reset - Arms the coordinated reset to hard reset when it receives a trigger.
  srtm - Pushes a measurement into PCR0.
  sbs_single get - Get status of SBS mux select
  sbs_single connect_flash_to_rot - Set mux to connect flash to RoT
  sbs_single connect_flash_to_target - Set mux to connect flash to target
  sbs_dual get - Get status of SBS mux select
  sbs_dual connect_target_to_spi_flash_0 - Set mux select pin to connect target to spi flash 0 (SBS Dual)
  sbs_dual connect_target_to_spi_flash_1 - Set mux select pin to connect target to spi flash 1 (SBS Dual)
  i2c detect - Detect I2C devices on bus
  i2c read - Perform I2C transaction
  i2c write - Perform I2C transaction
  i2c mux_ctrl get - Get status of I2C Mux sel (if present)
  i2c mux_ctrl select_rot - Change I2C Mux sel (if present) to select RoT as controller
  i2c mux_ctrl select_host - Change I2C Mux sel (if present) to select Host as controller
  rot_usb mux_ctrl get - Get status of USB mux select (if present)
  rot_usb mux_ctrl connect_rot_to_host - Change USB mux select (if present) so that RoT is connected to Host
  rot_usb mux_ctrl connect_rot_to_front_panel - Change USB mux select (if present) so that RoT is connected to Front panel
  raw_host_command - Stream raw host commands via stdin/stdout
  jtag read_idcode - Read IDCODE for a device over JTAG. Assumes only a single device in chain
  jtag test_bypass - Send test pattern of 64 bytes to JTAG device in BYPASS mode. Assumes only a single device in chain
  external_usb_host check_presence - Check presence of an External USB host connected to the system containing RoT
  jtag program_and_verify_pld - Program and verify a PLD over JTAG. Assumes only a single device in chain
  jtag verify_pld - Verify a PLD over JTAG. Assumes only a single device in chain
  storage read - Read from the controlled storage
  storage write - Write to the controlled storage
  storage delete - Delete from the controlled storage
  hello - A test function to send and receive an integer
  opentitan_version - Get OpenTitan version
  extract_ot_bundle - Get OpenTitan version
  key_rotation get status - Reads info from key rotation record and validation method and data.
  key_rotation get version - Gets key rotation header version.
  key_rotation payload status - Gets status regarding payload validation method and validation data.
  key_rotation update - Writes the key rotation record.
  key_rotation read - Read size bytes from key rotation record.
  key_rotation read_chunk - Read chunk of given type from the key rotation record.
  key_rotation chunk_type_count - Get the number of chunks of a given type in the key rotation record.
  key_rotation erase record - Erase the key rotation record from both halves of the flash if the mauv allows
  key_rotation set mauv - Set Key Rotation Record MAUV
  key_rotation get mauv - Get Key Rotation Record MAUV
  secure_boot get_enforcement - Get the current state of target secure boot enforcement.
  secure_boot enable_enforcement - Enable secure boot enforcement.
  security info - Retrieve the Info from firmware
  tpm_spi probe - Probe the TPM_SPI interface (DID/VID) over a spidev interface
  provisioning read - Get Provisioning Log
  provisioning validate_and_sign - Validate and Sign the provisioning log
  security get_alias_key_cert - Get the Alias Key Cert
  security get_device_id_cert - Get the Device ID Cert
  security get_attestation_pub_cert - Get the Attestation Public Cert
  security get_signed_attestation_pub_cert - Get the Signed Attestation Public Cert
  security attestation - Fetch attestation information, including tokens and certificates.

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
        If true, force spidev to send the request and receive the corresponding response with a single atomic ioctl.  This is required on some systems for correctness.
  --spidev_speed_hz (default: "0")
        Clock speed (in Hz) to use when using spidev transport. Default behavior (with input 0) is to not change the clock speed
  --spidev_device_busy_wait_timeout (default: "180000000")
        Maximum duration (in microseconds) to wait when SPI device indicates that it is busy
  --spidev_device_busy_wait_check_interval (default: "100")
        Interval duration (in microseconds) to wait before checking SPI device status again when it indicates that the device is busy
  --quadmode (default: "auto")
        Enable Quad SPI mode (auto|on|force|off). Default: auto
  --mtddev_path (default: "")
        The full MTD path of the RoT mailbox; for example '/dev/mtd0'. If unspecified, will attempt to detect the correct device automatically
  --mtddev_name (default: "hoth-mailbox")
        The MTD name of the RoT mailbox; for example 'hoth-mailbox'. 
  --mailbox_location (default: "0")
        The location of the mailbox on the RoT, for 'spidev' or 'mtd' transports; for example '0x900000'.
  --dbus_hoth_id (default: "")
        The hoth ID associated with the RoT's hothd service.
  --connect_timeout (default: "10s")
        Maximum duration to retry opening a busy libhoth transport (e.g., '1s', '1500ms').
  --version (default: "false")
        Print htool version.
```

```
$ htool usb list
  --usb_loc 1-10.4.2 - Hoth D (foobar)
```

```
$ htool spi update --help
Usage: spi update <source-file> 
  -s --start (default: "0")
        start address
  -v --verify (default: "true")
  -a --address_mode (default: "3B/4B")
        3B: 3 byte mode no enter/exit 4B supported
        3B/4B: 3 Byte current but enter 4B for SPI operation
        4B: 4 byte mode only, no enter/exit 4B supported

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
        the number of bytes to read
  -a --address_mode (default: "3B/4B")
        3B: 3 byte mode no enter/exit 4B supported
        3B/4B: 3 Byte current but enter 4B for SPI operation
        4B: 4 byte mode only, no enter/exit 4B supported

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
        Drive the UART's TX net even if the RoT isn't sure whether some other device else is driving it. Only use this option if you are CERTAIN there is no debugging hardware attached.
  -h --history (default: "false")
        Include data bufferred before the current time.
  -n --onlcr (default: "false")
        Translate received "\n" to "\r\n".
  -b --baud_rate (default: "0")
  -s --snapshot (default: "false")
        Print a snapshot of most recent console messages.
  --claim_timeout_secs (default: "60")
        How long we should attempt to claim the device before returning a fatal error.
  --yield_ms (default: "50")
        After releasing the device, how long we should wait before claiming it again. Decrease to reduce console latency. Increase to reduce contention between concurrent clients.
```

