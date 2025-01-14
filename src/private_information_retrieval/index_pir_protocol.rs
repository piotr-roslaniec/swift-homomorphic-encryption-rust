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
        he_scheme::HeScheme,
        keys::{EvaluationKeyConfiguration, SecretKey},
    },
    private_information_retrieval::keyword_pir_protocol::KeywordPirParameter,
};

pub enum PirAlgorithm {
    /// PIR using ciphertext word decomposition.
    ///
    /// # Note
    ///
    /// - [ePrint 2017/1142](https://eprint.iacr.org/2017/1142.pdf)
    AclsPir,
    /// PIR using ciphertext-ciphertext multiplication.
    ///
    /// # Note
    ///
    /// - [`MulPir`](https://eprint.iacr.org/2019/1483.pdf)
    MulPir,
}

/// Parameters for an index PIR lookup.
///
/// Must be the same between client and server for a correct database lookup.
pub struct IndexPirParameter {
    /// Number of entries in the database.
    pub(crate) entry_count: usize,
    /// Byte size of each entry in the database.
    entry_size_in_bytes: usize,
    /// Number of plaintexts in each dimension of the database.
    dimensions: Vec<usize>,
    /// Number of indices in a query to the database.
    batch_size: usize,
}

impl IndexPirParameter {
    pub fn dimension_count(&self) -> usize {
        self.dimensions.len()
    }

    pub fn expanded_query_count(&self) -> usize {
        self.dimensions.iter().sum()
    }

    /// Creates a new `IndexPirParameter`.
    ///
    /// # Parameters
    ///
    /// - `entry_count`: Number of entries in the database.
    /// - `entry_size_in_bytes`: Byte size of each entry in the database.
    /// - `dimensions`: Number of plaintexts in each dimension of the database.
    /// - `batch_size`: Number of indices in a query to the database.
    pub fn new(
        entry_count: usize,
        entry_size_in_bytes: usize,
        dimensions: Vec<usize>,
        batch_size: usize,
    ) -> Self {
        Self { entry_count, entry_size_in_bytes, dimensions, batch_size }
    }
}

/// A database after processing to prepare to PIR queries.
pub struct ProcessedDatabase<Scheme> {
    // TODO: Implement
    _marker: PhantomData<Scheme>, // TODO: Remove after implementing the struct.
}

/// A processed database along with PIR parameters describing the database.
pub struct ProcessedDatabaseWithParameters<Scheme> {
    /// Processed database.
    database: ProcessedDatabase<Scheme>,
    /// Evaluation key configuration.
    evaluation_key_configuration: EvaluationKeyConfiguration,
    /// Parameters for index PIR queries.
    pub pir_parameters: IndexPirParameter,
    /// Parameters for keyword-value PIR queries.
    pub keyword_pir_parameters: Option<KeywordPirParameter>,
}

impl<Scheme> ProcessedDatabaseWithParameters<Scheme> {
    /// Creates a new `ProcessedDatabaseWithParameters`.
    ///
    /// # Parameters
    ///
    /// - `database`: Processed database.
    /// - `evaluation_key_configuration`: Evaluation key configuration.
    /// - `pir_parameters`: Index PIR parameters.
    /// - `keyword_pir_parameters`: Optional keyword PIR parameters.
    pub fn new(
        database: ProcessedDatabase<Scheme>,
        evaluation_key_configuration: EvaluationKeyConfiguration,
        pir_parameters: IndexPirParameter,
        keyword_pir_parameters: Option<KeywordPirParameter>,
    ) -> Self {
        Self { database, evaluation_key_configuration, pir_parameters, keyword_pir_parameters }
    }
}

// An index PIR query.
pub struct Query<Scheme: HeScheme> {
    // Ciphertexts in the query.
    ciphertexts: Vec<Scheme::CanonicalCiphertext>,
    // Number of indices to query to an index PIR database.
    indices_count: usize,
}

impl<Scheme: HeScheme> Query<Scheme> {
    /// Creates a new index PIR `Query`.
    ///
    /// # Parameters
    ///
    /// - `ciphertexts`: Ciphertexts in the query.
    /// - `indices_count`: Number of indices to query.
    pub fn new(ciphertexts: Vec<Scheme::CanonicalCiphertext>, indices_count: usize) -> Self {
        Self { ciphertexts, indices_count }
    }
}

/// An index PIR response.
pub struct Response<Scheme: HeScheme> {
    // Ciphertexts in the response.
    ciphertexts: Vec<Scheme::CanonicalCiphertext>,
}

impl<Scheme: HeScheme> Default for Response<Scheme> {
    fn default() -> Self {
        Self { ciphertexts: Vec::new() }
    }
}

impl<Scheme: HeScheme> Response<Scheme> {
    /// Creates a new index PIR `Response`.
    ///
    /// # Parameters
    ///
    /// - `ciphertexts`: Ciphertexts in the response.
    pub fn new(ciphertexts: Vec<Scheme::CanonicalCiphertext>) -> Self {
        Self { ciphertexts }
    }

    pub fn noise_budget(&self, _secret_key: &SecretKey<Scheme>, _variable_time: bool) -> f64 {
        todo!()
    }
}
