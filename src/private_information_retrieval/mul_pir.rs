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

use crate::{
    homomorphic_encryption::{
        encryption_parameters::EncryptionParameters, he_scheme::HeScheme,
        keys::EvaluationKeyConfiguration,
    },
    private_information_retrieval::index_pir_protocol::IndexPirParameter,
};

pub enum MulPir<Scheme> {
    _Phantom(PhantomData<Scheme>),
}

impl<Scheme: HeScheme> MulPir<Scheme> {
    pub fn evaluation_key_configuration(
        _parameter: &IndexPirParameter,
        _encryption_parameters: &EncryptionParameters,
    ) -> EvaluationKeyConfiguration {
        todo!()
    }
}
