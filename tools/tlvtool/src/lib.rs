// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! A library and tool to create, inspect, and manage OpenPRoT TLV records.

extern crate alloc;

pub mod cli;
pub mod crypto;
pub mod inspect;
pub mod krr;
pub mod record;
pub mod signature;

pub use crypto::Algorithm;
pub use crypto::KeyBytes;
pub use inspect::inspect_file;
pub use inspect::inspect_words;
pub use krr::Krr;
pub use krr::RecordBuilder;
pub use krr::UnsignedRecord;
pub use record::RecordKind;
pub use record::Unsigned;
pub use signature::HybridMaterial;
pub use signature::HybridSignatureFiles;
pub use signature::SignedBuilder;
pub use signature::SignedRecord;
pub use signature::SignedRecordBuilder;
