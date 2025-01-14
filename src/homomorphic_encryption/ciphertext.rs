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
    context::Context,
    he_scheme::{HeScheme, PolyFormat},
    poly_rq::poly::PolyRq,
};

/// Ciphertext type.
pub struct Ciphertext<Scheme: HeScheme, Format: PolyFormat> {
    context: Context<Scheme>,
    polys: Vec<PolyRq<Scheme::Scalar>>,
    correction_factor: Scheme::Scalar,
    seed: Vec<u8>,
    _marker: PhantomData<Format>,
}

impl<Scheme: HeScheme, Format: PolyFormat> Ciphertext<Scheme, Format> {
    /// The number of polynomials in the ciphertext.
    ///
    /// After a fresh encryption, the ciphertext has `HeScheme::freshCiphertextPolyCount`
    /// polynomials. The count may change during the course of HE operations, e.g. increase
    /// during ciphertext multiplication, or decrease during relinearization,
    /// `Ciphertext::relinearize`.
    pub fn poly_count(&self) -> usize {
        self.polys.len()
    }

    pub fn new(
        _context: &Context<Scheme>,
        _polys: &[PolyRq<Scheme::Scalar>],
        _correction_factor: &Scheme::Scalar,
        _seed: &[u8],
    ) -> Self {
        todo!()
    }
}
