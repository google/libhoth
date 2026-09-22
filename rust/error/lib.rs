// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![cfg_attr(not(test), no_std)]

use core::num::NonZero;

use ufmt::uDebug;
use ufmt::uDisplay;
use ufmt::uwrite;

#[derive(Eq, PartialEq, Clone, Copy)]
#[repr(transparent)]
pub struct ErrorPrefix(pub NonZero<u16>);
impl ErrorPrefix {
    pub const fn new_const(val: u16) -> Self {
        match NonZero::new(val) {
            Some(val) => Self(val),
            None => panic!("ErrorPrefixes must be non-zero"),
        }
    }

    pub const fn sub_error(self, sub_error_code: u16) -> ErrorCode {
        // Cannot panic because the higher 16 bits are guaranteed to be
        // non-zero by the type-system.
        ErrorCode::new_const(((self.0.get() as u32) << 16) | (sub_error_code as u32))
    }
}

#[derive(Eq, PartialEq, Clone, Copy)]
#[repr(transparent)]
pub struct ErrorCode(pub NonZero<u32>);
impl ErrorCode {
    pub const fn new_const(val: u32) -> Self {
        match NonZero::new(val) {
            Some(val) => Self(val),
            None => panic!("ErrorCodes must be non-zero"),
        }
    }
    pub const fn result_as_u32(value: Result<(), ErrorCode>) -> u32 {
        match value {
            Ok(()) => 0,
            Err(e) => e.0.get(),
        }
    }
    pub const fn u32_as_result(val: u32) -> Result<(), ErrorCode> {
        match NonZero::new(val) {
            Some(val) => Err(ErrorCode(val)),
            None => Ok(()),
        }
    }
}
impl TryFrom<u32> for ErrorCode {
    type Error = ();

    fn try_from(value: u32) -> Result<Self, ()> {
        Ok(Self(NonZero::new(value).ok_or(())?))
    }
}
impl From<ErrorCode> for u32 {
    fn from(value: ErrorCode) -> Self {
        value.0.get()
    }
}
impl From<ErrorCode> for usize {
    fn from(value: ErrorCode) -> Self {
        usize::try_from(u32::from(value)).unwrap()
    }
}
impl uDisplay for ErrorCode {
    #[inline(never)]
    fn fmt<W>(&self, f: &mut ufmt::Formatter<'_, W>) -> Result<(), W::Error>
    where
        W: ufmt::uWrite + ?Sized,
    {
        uwrite!(f, "0x{:x}", self.0.get())
    }
}
impl uDebug for ErrorCode {
    #[inline(always)]
    fn fmt<W>(&self, f: &mut ufmt::Formatter<'_, W>) -> Result<(), W::Error>
    where
        W: ufmt::uWrite + ?Sized,
    {
        uDisplay::fmt(self, f)
    }
}
impl core::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "0x{:x}", self.0.get())
    }
}
impl core::fmt::Debug for ErrorCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Display::fmt(self, f)
    }
}
impl core::error::Error for ErrorCode {}

pub const KERN_UNKNOWN: ErrorCode = ErrorCode::new_const(0xb6e8_0000);

pub const KERNEL_FAULT_EXCEPTION: ErrorPrefix = ErrorPrefix::new_const(0x78b3);

pub const KERNEL_FAULT_EXCEPTION_INSTRUCTION_ADDRESS_MISALIGNED: ErrorCode =
    KERNEL_FAULT_EXCEPTION.sub_error(0);
pub const KERNEL_FAULT_EXCEPTION_INSTRUCTION_ACCESS_FAULT: ErrorCode =
    KERNEL_FAULT_EXCEPTION.sub_error(1);
pub const KERNEL_FAULT_EXCEPTION_ILLEGAL_INSTRUCTION: ErrorCode =
    KERNEL_FAULT_EXCEPTION.sub_error(2);
pub const KERNEL_FAULT_EXCEPTION_BREAKPOINT: ErrorCode = KERNEL_FAULT_EXCEPTION.sub_error(3);
pub const KERNEL_FAULT_EXCEPTION_LOAD_ADDRESS_MISALIGNED: ErrorCode =
    KERNEL_FAULT_EXCEPTION.sub_error(4);
pub const KERNEL_FAULT_EXCEPTION_LOAD_ACCESS_FAULT: ErrorCode = KERNEL_FAULT_EXCEPTION.sub_error(5);
pub const KERNEL_FAULT_EXCEPTION_STORE_ADDRESS_MISALIGNED: ErrorCode =
    KERNEL_FAULT_EXCEPTION.sub_error(6);
pub const KERNEL_FAULT_EXCEPTION_STORE_ACCESS_FAULT: ErrorCode =
    KERNEL_FAULT_EXCEPTION.sub_error(7);
pub const KERNEL_FAULT_EXCEPTION_ECALL_USER: ErrorCode = KERNEL_FAULT_EXCEPTION.sub_error(8);
pub const KERNEL_FAULT_EXCEPTION_ECALL_SUPERVISOR: ErrorCode = KERNEL_FAULT_EXCEPTION.sub_error(9);
pub const KERNEL_FAULT_EXCEPTION_ECALL_MACHINE: ErrorCode = KERNEL_FAULT_EXCEPTION.sub_error(11);
pub const KERNEL_FAULT_EXCEPTION_INSTRUCTION_PAGE_FAULT: ErrorCode =
    KERNEL_FAULT_EXCEPTION.sub_error(12);
pub const KERNEL_FAULT_EXCEPTION_LOAD_PAGE_FAULT: ErrorCode = KERNEL_FAULT_EXCEPTION.sub_error(13);
pub const KERNEL_FAULT_EXCEPTION_STORE_PAGE_FAULT: ErrorCode = KERNEL_FAULT_EXCEPTION.sub_error(15);

pub const USER_FAULT_EXCEPTION: ErrorPrefix = ErrorPrefix::new_const(0x78b4);

pub const USER_FAULT_EXCEPTION_INSTRUCTION_ADDRESS_MISALIGNED: ErrorCode =
    USER_FAULT_EXCEPTION.sub_error(0);
pub const USER_FAULT_EXCEPTION_INSTRUCTION_ACCESS_FAULT: ErrorCode =
    USER_FAULT_EXCEPTION.sub_error(1);
pub const USER_FAULT_EXCEPTION_ILLEGAL_INSTRUCTION: ErrorCode = USER_FAULT_EXCEPTION.sub_error(2);
pub const USER_FAULT_EXCEPTION_BREAKPOINT: ErrorCode = USER_FAULT_EXCEPTION.sub_error(3);
pub const USER_FAULT_EXCEPTION_LOAD_ADDRESS_MISALIGNED: ErrorCode =
    USER_FAULT_EXCEPTION.sub_error(4);
pub const USER_FAULT_EXCEPTION_LOAD_ACCESS_FAULT: ErrorCode = USER_FAULT_EXCEPTION.sub_error(5);
pub const USER_FAULT_EXCEPTION_STORE_ADDRESS_MISALIGNED: ErrorCode =
    USER_FAULT_EXCEPTION.sub_error(6);
pub const USER_FAULT_EXCEPTION_STORE_ACCESS_FAULT: ErrorCode = USER_FAULT_EXCEPTION.sub_error(7);
pub const USER_FAULT_EXCEPTION_ECALL_USER: ErrorCode = USER_FAULT_EXCEPTION.sub_error(8);
pub const USER_FAULT_EXCEPTION_ECALL_SUPERVISOR: ErrorCode = USER_FAULT_EXCEPTION.sub_error(9);
pub const USER_FAULT_EXCEPTION_ECALL_MACHINE: ErrorCode = USER_FAULT_EXCEPTION.sub_error(11);
pub const USER_FAULT_EXCEPTION_INSTRUCTION_PAGE_FAULT: ErrorCode =
    USER_FAULT_EXCEPTION.sub_error(12);
pub const USER_FAULT_EXCEPTION_LOAD_PAGE_FAULT: ErrorCode = USER_FAULT_EXCEPTION.sub_error(13);
pub const USER_FAULT_EXCEPTION_STORE_PAGE_FAULT: ErrorCode = USER_FAULT_EXCEPTION.sub_error(15);

pub const USER_FAULT_UNKNOWN_OPCODE_PREFIX: ErrorPrefix = ErrorPrefix::new_const(0x78b5);

pub const USER_FAULT_SEND_TARGET_TASK_NOT_FOUND: ErrorCode = ErrorCode::new_const(0x78b6_0001);
pub const USER_FAULT_REPLY_TARGET_TASK_NOT_FOUND: ErrorCode = ErrorCode::new_const(0x78b6_0002);
pub const USER_FAULT_SEND_TO_LOWER_PRIORITY: ErrorCode = ErrorCode::new_const(0x78b6_0003);
pub const USER_FAULT_INVALID_TIMER_NOTIFICATION_MASK: ErrorCode = ErrorCode::new_const(0x78b6_0004);
pub const USER_FAULT_PERMISSION_DENIED: ErrorCode = ErrorCode::new_const(0x78b6_0005);
pub const USER_FAULT_LAUNCH_TASK_PERMISSION_DENIED: ErrorCode = ErrorCode::new_const(0x78b6_0006);
pub const USER_FAULT_LAUNCH_TASK_TASK_NOT_FOUND: ErrorCode = ErrorCode::new_const(0x78b6_0007);
pub const USER_FAULT_KILL_TASK_TASK_NOT_FOUND: ErrorCode = ErrorCode::new_const(0x78b6_0008);
pub const USER_FAULT_KILL_TASK_TASK_NOT_ALIVE: ErrorCode = ErrorCode::new_const(0x78b6_0009);
pub const USER_FAULT_KILL_TASK_INVALID_ERROR: ErrorCode = ErrorCode::new_const(0x78b6_000a);
pub const USER_FAULT_KILL_TASK_PERMISSION_DENIED: ErrorCode = ErrorCode::new_const(0x78b6_000b);
/// Indicates a kernel bug where recv() returned an message that didn't match the notification mask.
pub const USER_FAULT_USERLIB_IMPOSSIBLE_RECV_RESULT: ErrorCode = ErrorCode::new_const(0x78b6_000c);
pub const USER_FAULT_SERVICE_NOT_FOUND: ErrorCode = ErrorCode::new_const(0x78b6_000d);
pub const USER_FAULT_SERVICE_SEND_OP_TOO_LARGE: ErrorCode = ErrorCode::new_const(0x78b6_000e);
pub const USER_FAULT_INVALID_SOURCE_BUF: ErrorCode = ErrorCode::new_const(0x78b6_000f);
pub const USER_FAULT_INVALID_DESTINATION_BUF: ErrorCode = ErrorCode::new_const(0x78b6_0010);
pub const USER_FAULT_NOTIFY_PERMISSION_DENIED: ErrorCode = ErrorCode::new_const(0x78b6_0011);
pub const USER_FAULT_NOTIFY_INVALID_BIT: ErrorCode = ErrorCode::new_const(0x78b6_0012);

pub const USER_ERR_TARGET_FAULTED: ErrorCode = ErrorCode::new_const(0x78b7_0001);
pub const USER_ERR_BAD_REPLY_LENGTH: ErrorCode = ErrorCode::new_const(0x78b7_0002);
pub const USER_ERR_CANNOT_SEND_TO_SELF: ErrorCode = ErrorCode::new_const(0x78b7_0003);
pub const USER_ERR_INVALID_EXIT_INFO_FROM_KERNEL: ErrorCode = ErrorCode::new_const(0x78b7_0004);
pub const USER_ERR_LAUNCH_TASK_VM_BUSY: ErrorCode = ErrorCode::new_const(0x78b7_0005);
pub const USER_ERR_IPC_TARGET_EXITED: ErrorCode = ErrorCode::new_const(0x78b7_0006);
pub const USER_ERR_ECALL_SEND_RECEIVER_NOT_SCHEDULED: ErrorCode = ErrorCode::new_const(0x78b7_0007);
pub const USER_ERR_ECALL_SEND_RECEIVER_BUFFER_OVERFLOW: ErrorCode =
    ErrorCode::new_const(0x78b7_0008);
pub const USER_ERR_INVALID_ARGUMENT: ErrorCode = ErrorCode::new_const(0x78b7_0009);

pub const KERN_FAULT_VM_INDEX_OUT_OF_BOUNDS: ErrorCode = ErrorCode::new_const(0x78b8_0000);
pub const KERN_FAULT_RECV_VM_INDEX_OUT_OF_BOUND: ErrorCode = ErrorCode::new_const(0x78b8_0001);
pub const KERN_FAULT_UNEXPECTED_INTERRUPT: ErrorCode = ErrorCode::new_const(0x78b8_0002);
pub const KERN_FAULT_UNEXPECTED_SYNC_EXCEPTION: ErrorCode = ErrorCode::new_const(0x78b8_0003);
pub const KERN_FAULT_ECALL_RECV_SENDER_WRONG_MODE: ErrorCode = ErrorCode::new_const(0x78b8_0004);
pub const KERN_FAULT_ECALL_RECV_RECEIVER_WRONG_MODE: ErrorCode = ErrorCode::new_const(0x78b8_0005);
pub const KERN_FAULT_ECALL_SEND_SENDER_WRONG_MODE: ErrorCode = ErrorCode::new_const(0x78b8_0006);
pub const KERN_FAULT_ECALL_SEND_RECEIVER_NOT_SCHEDULED: ErrorCode =
    ErrorCode::new_const(0x78b8_0007);
pub const KERN_FAULT_LAUNCH_TASK_TASK_NOT_FOUND: ErrorCode = ErrorCode::new_const(0x78b8_0008);
pub const KERN_FAULT_LAUNCH_TASK_TASK_ALIVE: ErrorCode = ErrorCode::new_const(0x78b8_0009);
pub const KERN_FAULT_LAUNCH_TASK_INVALID_VM: ErrorCode = ErrorCode::new_const(0x78b8_000a);
pub const KERN_FAULT_LAUNCH_TASK_VM_BUSY: ErrorCode = ErrorCode::new_const(0x78b8_000b);
pub const KERN_FAULT_UNEXPECTED_TRAP: ErrorCode = ErrorCode::new_const(0x78b8_000c);
pub const KERN_FAULT_ENABLED_TIMER_INDEX_OUT_OF_BOUNDS: ErrorCode =
    ErrorCode::new_const(0x78b8_000d);
pub const KERN_FAULT_TRAP_WITH_CORRUPT_MSCRATCH: ErrorCode = ErrorCode::new_const(0x78b8_000e);
pub const KERN_FAULT_PLIC_CLAIM_NOT_FOUND: ErrorCode = ErrorCode::new_const(0x78b8_000f);
pub const KERN_FAULT_IRQ_COMPLETE_CALLED_NO_TASK_INDEX: ErrorCode =
    ErrorCode::new_const(0x78b8_0010);
pub const KERN_FAULT_BAD_CONFIG_IRQ_INDEX: ErrorCode = ErrorCode::new_const(0x78b8_0011);
pub const KERN_FAULT_BAD_ERROR_CODE: ErrorCode = ErrorCode::new_const(0x78b8_0012);
pub const KERN_FAULT_CHILD_FAULT_WRONG_PARENT_MODE: ErrorCode = ErrorCode::new_const(0x78b8_0013);
pub const KERN_FAULT_WATCHDOG_TIMEOUT: ErrorCode = ErrorCode::new_const(0x78b8_0014);
pub const KERN_FAULT_VM_STOP_WRONG_STATE: ErrorCode = ErrorCode::new_const(0x78b8_0015);
pub const KERN_FAULT_VM_STOP_TASK_NOT_FOUND: ErrorCode = ErrorCode::new_const(0x78b8_0016);
pub const KERN_FAULT_VM_TASK_EXITED_RECV_VM_IN_WRONG_MODE: ErrorCode =
    ErrorCode::new_const(0x78b8_0017);
pub const KERN_FAULT_VM_TASK_EXITED_VM_IN_WRONG_MODE: ErrorCode = ErrorCode::new_const(0x78b8_0018);
pub const KERN_FAULT_LAUNCH_TASK_CALLED_NO_TASK_INDEX: ErrorCode =
    ErrorCode::new_const(0x78b8_0019);
pub const KERN_FAULT_TASK_INDEX_OUT_OF_BOUNDS: ErrorCode = ErrorCode::new_const(0x78b8_001a);

pub const IO_GENERIC: ErrorPrefix = ErrorPrefix::new_const(0x89c7);
pub const IO_GENERIC_READ_OUT_OF_BOUNDS: ErrorCode = IO_GENERIC.sub_error(1);
pub const IO_GENERIC_ZEROCOPY_CONV_ALIGN: ErrorCode = IO_GENERIC.sub_error(2);
pub const IO_GENERIC_ZEROCOPY_CONV_SIZE: ErrorCode = IO_GENERIC.sub_error(3);
pub const IO_GENERIC_ZEROCOPY_CONV_VALID: ErrorCode = IO_GENERIC.sub_error(4);
pub const IO_GENERIC_WRITE_OUT_OF_BOUNDS: ErrorCode = IO_GENERIC.sub_error(5);

impl<A, S, V> From<zerocopy::ConvertError<A, S, V>> for ErrorCode {
    fn from(value: zerocopy::ConvertError<A, S, V>) -> Self {
        match value {
            zerocopy::ConvertError::Alignment(_) => IO_GENERIC_ZEROCOPY_CONV_ALIGN,
            zerocopy::ConvertError::Size(_) => IO_GENERIC_ZEROCOPY_CONV_SIZE,
            zerocopy::ConvertError::Validity(_) => IO_GENERIC_ZEROCOPY_CONV_VALID,
        }
    }
}

pub const FLASH_GENERIC: ErrorPrefix = ErrorPrefix::new_const(0x3326);
pub const FLASH_GENERIC_BUSY: ErrorCode = FLASH_GENERIC.sub_error(0);
pub const FLASH_GENERIC_ERASE_INVALID_ADDR: ErrorCode = FLASH_GENERIC.sub_error(1);
pub const FLASH_GENERIC_BAD_ALIGNMENT: ErrorCode = FLASH_GENERIC.sub_error(2);
pub const FLASH_GENERIC_READ_TOO_LONG: ErrorCode = FLASH_GENERIC.sub_error(3);
pub const FLASH_GENERIC_PROGRAM_EXCEEDS_WINDOW_SIZE: ErrorCode = FLASH_GENERIC.sub_error(4);
pub const FLASH_GENERIC_PROGRAM_SPANS_WINDOW_BOUNDARY: ErrorCode = FLASH_GENERIC.sub_error(5);
pub const FLASH_GENERIC_ADDR_OUT_OF_BOUNDS: ErrorCode = FLASH_GENERIC.sub_error(6);
pub const FLASH_GENERIC_INVALID_PAGE_SIZE: ErrorCode = FLASH_GENERIC.sub_error(7);
pub const FLASH_GENERIC_INVALID_SIZE: ErrorCode = FLASH_GENERIC.sub_error(8);
pub const FLASH_GENERIC_ERASE_START_NOT_PAGE_ALIGNED: ErrorCode = FLASH_GENERIC.sub_error(9);
pub const FLASH_GENERIC_ERASE_LEN_NOT_PAGE_ALIGNED: ErrorCode = FLASH_GENERIC.sub_error(10);

pub const FLASH_GENERIC_SFDP_INVALID_MEMORY_DENSITY: ErrorCode = FLASH_GENERIC.sub_error(1024);
pub const FLASH_GENERIC_SFDP_INVALID_SIGNATURE: ErrorCode = FLASH_GENERIC.sub_error(1025);
pub const FLASH_GENERIC_SFDP_NO_VALID_PARAMETER_HEADER_FOUND: ErrorCode =
    FLASH_GENERIC.sub_error(1026);
pub const FLASH_GENERIC_SFDP_PARAMETERS_TOO_SHORT: ErrorCode = FLASH_GENERIC.sub_error(1027);
pub const FLASH_GENERIC_SFDP_UNSUPPORTED_HEADER_MAJOR_REV: ErrorCode =
    FLASH_GENERIC.sub_error(1028);
pub const FLASH_GENERIC_SFDP_UNSUPPORTED_PARAMS_MAJOR_REV: ErrorCode =
    FLASH_GENERIC.sub_error(1029);
pub const FLASH_GENERIC_SFDP_PARAMETERS_TOO_LONG: ErrorCode = FLASH_GENERIC.sub_error(1030);

pub const FLASH_OPENTITAN: ErrorPrefix = ErrorPrefix::new_const(0xcd7e);

pub const IPC_BAD_REQ_LEN: ErrorCode = ErrorCode::new_const(0xae1e_0000);
pub const IPC_RESPONSE_TOO_LARGE: ErrorCode = ErrorCode::new_const(0xae1e_0001);
pub const IPC_UNKNOWN_OP: ErrorCode = ErrorCode::new_const(0xae1e_0002);
pub const IPC_RESPONSE_BAD_LEN: ErrorCode = ErrorCode::new_const(0xae1e_0003);
pub const IPC_BAD_REQ: ErrorCode = ErrorCode::new_const(0xae1e_0004);

pub const USB_TRANSFER: ErrorPrefix = ErrorPrefix::new_const(0x5a12);
pub const USB_TRANSFER_BUFFER_OVERFLOW: ErrorCode = USB_TRANSFER.sub_error(1);

pub const HOSTCMD_ERROR_PREFIX: ErrorPrefix = ErrorPrefix::new_const(0x5768);
pub const HOSTCMD_LEN_U16_OVERFLOW: ErrorCode = HOSTCMD_ERROR_PREFIX.sub_error(1);
pub const HOSTCMD_BUFFER_OVERFLOW: ErrorCode = HOSTCMD_ERROR_PREFIX.sub_error(2);

#[cfg(test)]
mod test {
    use super::*;

    struct Buffer<const N: usize> {
        buf: [u8; N],
        len: usize,
    }

    impl<const N: usize> Buffer<N> {
        fn new() -> Self {
            Self {
                buf: [0; N],
                len: 0,
            }
        }
        fn as_bytes(&self) -> &[u8] {
            &self.buf[..self.len]
        }
    }

    impl<const N: usize> ufmt::uWrite for Buffer<N> {
        type Error = ();
        fn write_str(&mut self, s: &str) -> Result<(), Self::Error> {
            let bytes = s.as_bytes();
            if self.len + bytes.len() > N {
                return Err(());
            }
            self.buf[self.len..self.len + bytes.len()].copy_from_slice(bytes);
            self.len += bytes.len();
            Ok(())
        }
    }

    #[test]
    fn test_error_prefix() {
        let prefix = ErrorPrefix::new_const(0x7fb4);
        assert_eq!(u32::from(prefix.sub_error(0x4183)), 0x7fb4_4183);
        assert_eq!(u32::from(prefix.sub_error(0x1cfb)), 0x7fb4_1cfb);
    }

    #[test]
    #[should_panic(expected = "ErrorPrefixes must be non-zero")]
    fn test_error_prefix_zero() {
        ErrorPrefix::new_const(0);
    }

    #[test]
    #[should_panic(expected = "ErrorCodes must be non-zero")]
    fn test_error_code_zero() {
        ErrorCode::new_const(0);
    }

    #[test]
    fn test_result_as_u32() {
        assert_eq!(
            ErrorCode::result_as_u32(Err(IO_GENERIC_READ_OUT_OF_BOUNDS)),
            0x89c7_0001,
        );
        assert_eq!(
            ErrorCode::result_as_u32(Err(KERN_FAULT_VM_INDEX_OUT_OF_BOUNDS)),
            0x78b8_0000,
        );
        assert_eq!(ErrorCode::result_as_u32(Ok(())), 0,);
    }

    #[test]
    fn test_u32_as_result() {
        assert_eq!(
            ErrorCode::u32_as_result(0x89c7_0001),
            Err(IO_GENERIC_READ_OUT_OF_BOUNDS)
        );
        assert_eq!(
            ErrorCode::u32_as_result(0x78b8_0000),
            Err(KERN_FAULT_VM_INDEX_OUT_OF_BOUNDS),
        );
        assert_eq!(ErrorCode::u32_as_result(0), Ok(()));
    }

    #[test]
    fn test_try_from_u32() {
        assert_eq!(
            ErrorCode::try_from(0x89c7_0001),
            Ok(IO_GENERIC_READ_OUT_OF_BOUNDS),
        );
        assert_eq!(
            ErrorCode::try_from(0x78b8_0000),
            Ok(KERN_FAULT_VM_INDEX_OUT_OF_BOUNDS),
        );
        assert_eq!(ErrorCode::try_from(0), Err(()),);
    }

    #[test]
    fn test_into_u32() {
        assert_eq!(u32::from(IO_GENERIC_READ_OUT_OF_BOUNDS), 0x89c7_0001,);
        assert_eq!(u32::from(KERN_FAULT_VM_INDEX_OUT_OF_BOUNDS), 0x78b8_0000,);
    }

    #[test]
    fn test_udisplay() {
        let mut buf = Buffer::<20>::new();
        uwrite!(&mut buf, "{}", IO_GENERIC_READ_OUT_OF_BOUNDS).unwrap();
        assert_eq!(buf.as_bytes(), b"0x89c70001")
    }

    #[test]
    fn test_udebug() {
        let mut buf = Buffer::<20>::new();
        uwrite!(&mut buf, "{:?}", IO_GENERIC_READ_OUT_OF_BOUNDS).unwrap();
        assert_eq!(buf.as_bytes(), b"0x89c70001")
    }

    #[test]
    fn test_display() {
        assert_eq!(format!("{IO_GENERIC_READ_OUT_OF_BOUNDS}"), "0x89c70001")
    }

    #[test]
    fn test_debug() {
        assert_eq!(format!("{IO_GENERIC_READ_OUT_OF_BOUNDS:?}"), "0x89c70001")
    }
}
