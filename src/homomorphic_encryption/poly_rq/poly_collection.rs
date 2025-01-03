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

use crate::homomorphic_encryption::{poly_rq::poly_context::PolyContext, scalar::ScalarType};

/// Trait for collection of `PolyRq` polynomials.

pub trait PolyCollection {
    /// Coefficient type
    type Scalar: ScalarType;

    /// Returns the polynomial's context
    fn poly_context(&self) -> PolyContext<Self::Scalar>;

    /// The polynomial's degree.
    fn degree(&self) -> usize {
        self.poly_context().degree as usize
    }

    /// The polynomial's scalar moduli.
    fn moduli(&self) -> Vec<Self::Scalar> {
        self.poly_context().moduli
    }

    /// The polynomial's moduli.
    fn reduce_moduli(&self) -> Vec<Self::Scalar> {
        self.poly_context().reduce_moduli
    }
}
