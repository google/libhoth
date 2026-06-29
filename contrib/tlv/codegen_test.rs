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

// Integration test verifying the correctness of the generated TLV structs.

#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

#[test]
fn test_generated_code_compiles_and_aligns() {
    // If this test compiles and runs, it means our codegen generated completely valid Rust code.
    // Let's assert the exact size of the generated structs to verify alignment and padding logic:

    assert_eq!(core::mem::size_of::<soc_tlv::System>(), 44);
    assert_eq!(core::mem::size_of::<soc_tlv::CpuCore>(), 12);
    assert_eq!(core::mem::size_of::<soc_tlv::CacheInfo>(), 12);
    assert_eq!(core::mem::size_of::<soc_tlv::ExecutionUnit>(), 8);
    assert_eq!(core::mem::size_of::<soc_tlv::SystemBus>(), 16);
    assert_eq!(core::mem::size_of::<edge_cases_tlv::RegisterContainer>(), 8);
    assert_eq!(core::mem::size_of::<edge_cases_tlv::PackedRegister>(), 4);
    assert_eq!(core::mem::size_of::<edge_cases_tlv::Packed16Register>(), 2);
    assert_eq!(core::mem::size_of::<edge_cases_tlv::Packed8Register>(), 1);
    assert_eq!(core::mem::size_of::<edge_cases_tlv::SfixedTest>(), 8);
    assert_eq!(
        core::mem::size_of::<edge_cases_tlv::MessageCollisionContainer>(),
        4
    );
    assert_eq!(
        core::mem::size_of::<edge_cases_tlv::MessageCollisionContainer_PackedRegister>(),
        4
    );
    assert_eq!(core::mem::size_of::<edge_cases_tlv::U64AlignmentTest>(), 12);
    assert_eq!(core::mem::size_of::<edge_cases_tlv::AllTypesTest>(), 100);
}
