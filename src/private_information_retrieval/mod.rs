// Copyright 2024 Apple Inc. and the Swift Homomorphic Encryption project authors
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

//! Private Information Retrieval (PIR) module.
// TODO: Add module documentation
// TODO: Update crate visibility

pub mod cuckoo_table;
pub(crate) mod error;
pub mod hash_bucket;
pub(crate) mod index_pir_protocol;
pub mod keyword_database;
pub(crate) mod keyword_pir_protocol;
pub(crate) mod mul_pir;

#[cfg(test)]
mod pir_test_utils;
