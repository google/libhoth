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

pub mod builder;
pub mod cli;
pub mod crypto;
pub mod inspect;

pub use builder::RecordBuilder;
pub use builder::UnsignedRecord;
pub use inspect::inspect_file;
pub use inspect::inspect_words;
