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

use crate::homomorphic_encryption::context::Context;
use crate::homomorphic_encryption::he_scheme::HeScheme;
use crate::homomorphic_encryption::poly_rq::poly_context::PolyContext;
use crate::homomorphic_encryption::poly_rq::poly_rq::PolyRq;
use crate::homomorphic_encryption::serialized_plaintext::SerializedPlaintext;
use eyre::Result;

pub trait PlaintextType<Scheme: HeScheme>: Sized {
    fn deserialize(
        serialized_plaintext: &SerializedPlaintext,
        context: &Context<Scheme>,
    ) -> Result<Self>;

    fn poly_context(&self) -> PolyContext<Scheme::Scalar>;
}

/// Plaintext struct.
#[derive(Clone)]
pub struct Plaintext<Scheme: HeScheme> {
    _marker: std::marker::PhantomData<Scheme>,
    poly_context: PolyContext<Scheme::Scalar>,
    pub poly: PolyRq<Scheme::Scalar>,
}

impl<Scheme: HeScheme> PlaintextType<Scheme> for Plaintext<Scheme> {
    fn deserialize(
        _serialized_plaintext: &SerializedPlaintext,
        _context: &Context<Scheme>,
    ) -> Result<Self> {
        todo!()
    }

    fn poly_context(&self) -> PolyContext<Scheme::Scalar> {
        todo!()
    }
}
