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

//! Contains the homomorphic encryption scheme and related functionality.
// TODO: Add module documentation
// TODO: Update crate visibility
pub(crate) mod array_2d;
pub(crate) mod bfv;
pub(crate) mod ciphertext;
pub(crate) mod context;
pub(crate) mod encryption_parameters;
pub(crate) mod he_scheme;
pub(crate) mod keys;
pub(crate) mod modulus;
pub(crate) mod plaintext;
pub(crate) mod poly_rq;
pub(crate) mod scalar;
pub(crate) mod serialized_plaintext;
