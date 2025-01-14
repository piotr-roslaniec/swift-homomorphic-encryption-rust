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

use crate::homomorphic_encryption::scalar::ScalarType;

/// Polynomial context that holds all the pre-computed values for doing efficient calculations on
/// `PolyRq` polynomials.
#[derive(Clone, Debug, PartialEq)]
pub struct PolyContext<T: ScalarType> {
    /// Number `N` of coefficients in the polynomial, must be a power of two.
    pub degree: u32,
    /// CRT-representation of the modulus `Q = product_{i=0}^{L-1} q_i`.
    pub moduli: Vec<T>,
    /// Precomputed roots of unity for modular arithmetic in NTT.
    pub root_of_unity_powers: Vec<Vec<T>>,
    /// Precomputed inverse roots of unity for the inverse NTT.
    pub inverse_root_of_unity_powers: Vec<Vec<T>>,
    /// Precomputed `degree^-1 mod q_i` for inverse NTT.
    pub inverse_degree: Vec<T>,

    // TODO:
    pub reduce_moduli: Vec<T>,
}

impl<T: ScalarType> PolyContext<T> {
    pub fn new(degree: u32, moduli: &[T]) -> Self {
        todo!()
    }

    pub fn serialization_byte_count(&self) -> usize {
        todo!()
    }
}
