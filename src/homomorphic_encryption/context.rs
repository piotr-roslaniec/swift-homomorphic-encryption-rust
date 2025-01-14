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

use std::marker::PhantomData;

use crate::homomorphic_encryption::{
    encryption_parameters::EncryptionParameters, he_scheme::HeScheme,
};

/// Pre-computation for the HE operations.
///
/// HE operations are typically only supported between objects, such as ``Ciphertext``,
/// ``Plaintext``, ``EvaluationKey``, ``SecretKey``,  with the same context.
pub struct Context<Scheme: HeScheme> {
    _marker: PhantomData<Scheme>,
}

impl<Scheme: HeScheme> Context<Scheme> {
    /// Creates a new `Context`.
    pub fn new(_encryption_parameters: &EncryptionParameters) -> Self {
        todo!()
    }
}
