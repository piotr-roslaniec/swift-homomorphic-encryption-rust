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

/// Secret key.
///
/// # Note
///
/// `HeScheme::generate_secret_key` or `Context::generate_secret_key` for more information.
pub struct SecretKey<Scheme> {
    _marker: PhantomData<Scheme>,
}

/// Cryptographic key used in performing some HE operations.
///
/// Associated with a specific `SecretKey`.
pub struct EvaluationKey<Scheme> {
    _marker: PhantomData<Scheme>,
}

/// A configuration for generating an `EvaluationKey`.
#[derive(Default)]
pub struct EvaluationKeyConfiguration {
    /// Galois elements.
    /// See also `GaloisElement` for more information.
    // TODO: Add a link to the `GaloisElement` and other documentation.
    galois_elements: Vec<u64>,
    /// Whether to generate a `RelinearizationKey`.
    /// See also `RelinearizationKey` for more information.
    // TODO: Add a link to the `RelinearizationKey` and other documentation.
    has_relinearization_key: bool,
}

impl EvaluationKeyConfiguration {
    pub fn union(&self, other: Self) -> EvaluationKeyConfiguration {
        let mut galois_elements = self.galois_elements.clone();
        for element in other.galois_elements {
            if !galois_elements.contains(&element) {
                galois_elements.push(element);
            }
        }
        let has_relinearization_key = self.has_relinearization_key || other.has_relinearization_key;
        EvaluationKeyConfiguration { galois_elements, has_relinearization_key }
    }
}

impl EvaluationKeyConfiguration {
    pub fn key_count(&self) -> usize {
        self.galois_elements.len() + if self.has_relinearization_key { 1 } else { 0 }
    }

    /// Creates a new `EvaluationKeyConfiguration`.
    ///
    /// # Parameters
    ///
    /// - `galois_elements`: Galois elements.
    /// - `has_relinearization_key`: Whether to generate a `RelinearizationKey`.
    ///
    /// See also `GaloisElement` for more information.
    /// See also `RelinearizationKey` for more information.
    // TODO: Add a link to the `GaloisElement` and other documentation.
    pub fn new(galois_elements: Vec<u64>, has_relinearization_key: bool) -> Self {
        Self { galois_elements, has_relinearization_key }
    }
}
