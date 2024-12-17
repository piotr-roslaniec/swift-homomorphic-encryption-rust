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
use crate::homomorphic_encryption::encryption_parameters::EncryptionParameters;
use crate::homomorphic_encryption::he_scheme::HeScheme;
use crate::homomorphic_encryption::keys::{EvaluationKeyConfiguration, SecretKey};
use crate::homomorphic_encryption::plaintext::{Plaintext, PlaintextType};
use crate::homomorphic_encryption::serialized_plaintext::SerializedPlaintext;
use crate::private_information_retrieval::keyword_pir_protocol::KeywordPirParameter;
use eyre::Result;
use std::path::PathBuf;
use thiserror::Error;

// Which algorithm to use for PIR computation.
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

/// Index PIR config errors.
#[derive(Debug, Clone, Error, PartialEq)]
pub enum IndexPirConfigError {
    /// Invalid dimensions count.
    #[error("Invalid dimensions count: {dimension_count}, expected {expected}")]
    InvalidDimensionCount { dimension_count: usize, expected: String },
}

/// Configuration for an Index PIR database.
#[derive(Debug, Hash, PartialEq, Eq, Clone)]
pub struct IndexPirConfig {
    /// Number of entries in the database.
    pub entry_count: usize,
    /// Byte size of each entry in the database.
    pub entry_size_in_bytes: usize,
    /// Number of dimensions in the database.
    pub dimension_count: usize,
    /// Number of indices in a query to the database.
    pub batch_size: usize,
    /// Whether to enable `uneven_dimensions` optimization.
    pub uneven_dimensions: bool,
}

impl IndexPirConfig {
    /// Initializes an `IndexPirConfig`.
    ///
    /// # Parameters
    ///
    /// - `entry_count`: Number of entries in the database.
    /// - `entry_size_in_bytes`: Byte size of each entry in the database.
    /// - `dimension_count`: Number of dimensions in the database.
    /// - `batch_size`: Number of indices in a query to the database.
    /// - `uneven_dimensions`: Whether to enable `uneven dimensions` optimization.
    ///
    /// # Errors
    ///
    /// Returns an error if the `dimension_count` is not valid.
    pub fn new(
        entry_count: usize,
        entry_size_in_bytes: usize,
        dimension_count: usize,
        batch_size: usize,
        uneven_dimensions: bool,
    ) -> Result<Self> {
        let valid_dimensions_count = [1, 2];
        if !valid_dimensions_count.contains(&dimension_count) {
            return Err(IndexPirConfigError::InvalidDimensionCount {
                dimension_count,
                expected: format!("{:?}", valid_dimensions_count.to_vec()),
            }
            .into());
        }
        Ok(Self {
            entry_count,
            entry_size_in_bytes,
            dimension_count,
            batch_size,
            uneven_dimensions,
        })
    }
}

/// Parameters for an index PIR lookup.
///
/// Must be the same between client and server for a correct database lookup.
pub struct IndexPirParameter {
    /// Number of entries in the database.
    pub entry_count: usize,
    /// Byte size of each entry in the database.
    pub entry_size_in_bytes: usize,
    /// Number of plaintexts in each dimension of the database.
    pub dimensions: Vec<usize>,
    /// Number of indices in a query to the database.
    pub batch_size: usize,
}

impl IndexPirParameter {
    /// The number of dimensions in the database.
    pub fn dimension_count(&self) -> usize {
        self.dimensions.len()
    }

    /// The number of ciphertexts in each query after server-side expansion.
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

/// Index PIR database errors.
#[derive(Debug, Clone, Error, PartialEq)]
pub enum IndexPirDatabaseError {
    /// Invalid serialization plaintext tag.
    #[error("Invalid plaintext tag: {tag}")]
    InvalidSerializationPlaintextTag { tag: u8 },
    /// Invalid serialization version
    #[error("Invalid serialization version: {serialization_version}, expected {expected}")]
    InvalidDatabaseSerializationVersion { serialization_version: u8, expected: u8 },
    /// Empty database.
    #[error("Empty database")]
    EmptyDatabase,
}

/// Type of serialization version.
type SerializationVersionType = u8;

/// A database after processing to prepare to PIR queries.
pub struct ProcessedDatabase<Scheme: HeScheme> {
    /// Plaintexts in the database, including nil plaintexts used for padding.
    pub plaintexts: Vec<Option<Plaintext<Scheme>>>,
}

impl<Scheme: HeScheme<EvalPlaintext = Plaintext<Scheme>>> ProcessedDatabase<Scheme> {
    /// Serialization version.
    pub const SERIALIZATION_VERSION: SerializationVersionType = 1;
    /// Indicates a zero plaintext.
    pub const SERIALIZED_ZERO_PLAINTEXT_TAG: u8 = 0;
    /// Indicates a non-zero plaintext.
    pub const SERIALIZED_PLAINTEXT_TAG: u8 = 0;
    /// Number of plaintexts in the database, including padding plaintexts.
    pub fn count(&self) -> usize {
        self.plaintexts.len()
    }
    /// Whether the database is empty.
    pub fn is_empty(&self) -> bool {
        self.plaintexts.is_empty()
    }

    /// Creates a `ProcessedDatabase` from plaintexts.
    ///
    /// # Parameters
    ///
    /// - `plaintexts`: Plaintexts to build the database with.
    pub fn new(plaintexts: Vec<Option<Plaintext<Scheme>>>) -> Self {
        Self { plaintexts }
    }

    /// Creates a `ProcessedDatabase` from a filepath.
    ///
    /// # Parameters
    ///
    /// - `path`: Filepath storing serialized plaintexts.
    /// - `context`: Context for the HE computation.
    ///
    /// # Errors
    ///
    /// - If we fail to load the database.
    pub fn from_path(path: &PathBuf, context: &Context<Scheme>) -> Result<Self> {
        let file = std::fs::read(path)?;
        Self::from_bytes(&file, context)
    }

    /// Creates a `ProcessedDatabase` from bytes.
    ///
    /// # Parameters
    ///
    /// - `bytes`: Serialized plaintexts.
    /// - `context`: Context for the HE computation.
    ///
    /// # Errors
    ///
    /// - If we fail to deserialize.
    pub fn from_bytes(bytes: &[u8], context: &Context<Scheme>) -> Result<Self> {
        let mut offset = 0;

        // Read version number
        let version_number = bytes[offset];
        offset += std::mem::size_of::<SerializationVersionType>();
        if version_number != Self::SERIALIZATION_VERSION {
            return Err(IndexPirDatabaseError::InvalidDatabaseSerializationVersion {
                serialization_version: version_number,
                expected: Self::SERIALIZATION_VERSION,
            }
            .into());
        }

        // Read plaintext count
        let plaintext_count =
            u32::from_le_bytes(bytes[offset..offset + std::mem::size_of::<u32>()].try_into()?)
                as usize;
        offset += std::mem::size_of::<u32>();

        // Determine the byte size of each serialized plaintext
        let serialized_plaintext_byte_count =
            context.ciphertext_context().serialization_byte_count();

        // Deserialize plaintexts
        let mut plaintexts = Vec::with_capacity(plaintext_count);
        for _ in 0..plaintext_count {
            let tag = bytes[offset];
            offset += 1;
            match tag {
                tag if tag == Self::SERIALIZED_ZERO_PLAINTEXT_TAG => {
                    plaintexts.push(None);
                },
                tag if tag == Self::SERIALIZED_PLAINTEXT_TAG => {
                    let plaintext_bytes = &bytes[offset..offset + serialized_plaintext_byte_count];
                    offset += serialized_plaintext_byte_count;
                    let serialized_plaintext = SerializedPlaintext::new(plaintext_bytes);
                    let plaintext =
                        Scheme::EvalPlaintext::deserialize(&serialized_plaintext, context)?;
                    plaintexts.push(Some(plaintext));
                },
                _ => {
                    return Err(
                        IndexPirDatabaseError::InvalidSerializationPlaintextTag { tag }.into()
                    );
                },
            }
        }

        Ok(Self { plaintexts })
    }

    /// Returns the serialization size in bytes of the database.
    pub fn serialization_byte_count(&self) -> Result<usize> {
        let non_nil_plaintexts: Vec<&Plaintext<Scheme>> =
            self.plaintexts.iter().filter_map(|p| p.as_ref()).collect();
        let poly_context =
            non_nil_plaintexts.first().ok_or(IndexPirDatabaseError::EmptyDatabase)?.poly_context();
        let mut serialization_size = std::mem::size_of::<SerializationVersionType>();
        serialization_size += std::mem::size_of::<usize>(); // plaintext count
        serialization_size += non_nil_plaintexts.len() * poly_context.serialization_byte_count(); // non-nil plaintexts
        serialization_size += self.plaintexts.len() * std::mem::size_of::<u8>(); // "nil" or "non-nil" indicator

        Ok(serialization_size)
    }

    /// Saves the database to a file path.
    ///
    /// # Parameters
    ///
    /// - `path`: File path to save the database to.
    ///
    /// # Errors
    ///
    /// - If we fail to serialize the database.
    /// - If we fail to save it to a file.
    pub fn save(&self, path: &PathBuf) -> Result<()> {
        let serialized_data = self.serialize()?;
        std::fs::write(path, serialized_data)?;
        Ok(())
    }

    /// Serializes the database.
    ///
    /// # Errors
    ///
    /// - If we fail to serialize the database.
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut buffer: Vec<u8> = Vec::with_capacity(self.serialization_byte_count()?);
        buffer.push(Self::SERIALIZATION_VERSION);
        buffer.extend_from_slice(&(self.plaintexts.len() as u32).to_le_bytes());

        for plaintext in &self.plaintexts {
            if let Some(plaintext) = plaintext {
                buffer.push(Self::SERIALIZED_PLAINTEXT_TAG);
                buffer.extend_from_slice(&plaintext.poly.serialize());
            } else {
                buffer.push(Self::SERIALIZED_ZERO_PLAINTEXT_TAG);
            }
        }
        Ok(buffer)
    }
}

/// A processed database along with PIR parameters describing the database.
pub struct ProcessedDatabaseWithParameters<Scheme: HeScheme> {
    /// Processed database.
    database: ProcessedDatabase<Scheme>,
    /// Evaluation key configuration.
    evaluation_key_configuration: EvaluationKeyConfiguration,
    /// Parameters for index PIR queries.
    pub pir_parameters: IndexPirParameter,
    /// Parameters for keyword-value PIR queries.
    pub keyword_pir_parameters: Option<KeywordPirParameter>,
}

impl<Scheme: HeScheme> ProcessedDatabaseWithParameters<Scheme> {
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

/// Trait for queries to an integer-indexed database.
pub trait IndexPirProtocol {
    /// HE scheme used for PIR computation.
    type Scheme: HeScheme;

    /// Generates the PIR parameters for database.
    ///
    /// # Parameters
    ///
    /// - `config`: Database configuration.
    /// - `context`: Context for the HE computation.
    ///
    /// # Returns
    ///
    /// The PIR parameters for the database.
    fn generate_parameter(
        config: &IndexPirConfig,
        context: &Context<Self::Scheme>,
    ) -> IndexPirParameter;

    /// Computes the evaluation key configuration.
    ///
    /// The client and server must agree on the evaluation key configuration.
    ///
    /// # Parameters
    ///
    /// - `parameter`: Index PIR parameters.
    /// - `encryption_parameters`: Encryption parameters.
    ///
    /// # Returns
    ///
    /// The evaluation key configuration.
    fn evaluation_key_configuration(
        parameter: &IndexPirParameter,
        encryption_parameters: &EncryptionParameters<Self::Scheme>,
    ) -> EvaluationKeyConfiguration;
}

/// Trait for a server hosting index PIR databases for lookup.
///
/// The server hosts multiple databases, which are all compatible with a single PIR parameters.
pub trait IndexPirServer<IndexPir> {
    /// Index PIR type backing the keyword PIR computation.
    type IndexPir: IndexPirProtocol;

    /// HE scheme to be used by the database.
    type Scheme: HeScheme;

    /// The processed databases.
    fn databases(&self) -> &Vec<ProcessedDatabase<Self::Scheme>>;

    /// The index PIR parameters, suitable for use with any of the databases.
    fn parameter(&self) -> &IndexPirParameter;

    /// Evaluation key configuration.
    ///
    /// This tells the client what to include in the evaluation key. Must be the same between client and server.
    fn evaluation_key_configuration(&self) -> &EvaluationKeyConfiguration;
}

/// Client which can perform an Index PIR lookup.
pub trait IndexPirClient<IndexPir> {}

#[cfg(test)]
mod test {
    use rand::Rng;

    // use crate::test_utilities::get_test_context;

    fn get_database_for_testing(
        number_of_entries: usize,
        entry_size_in_bytes: usize,
    ) -> Vec<Vec<u8>> {
        let mut rng = rand::thread_rng();
        (0..number_of_entries)
            .map(|_| (0..entry_size_in_bytes).map(|_| rng.gen()).collect())
            .collect()
    }

    // fn test_generate_parameter() -> Result<()> {
    //     let context: Context<Bfv<u64>> = get_test_context()?;
    //     // unevenDimensions: false
    //     {
    //         let config = IndexPirConfig::new(16, context.bytes_per_plaintext(), 2, 1, false)?;
    //         let parameter = MulPir::generate_parameter(&config, &context);
    //         assert_eq!(parameter.dimensions, vec![4, 4]);
    //     }
    //     {
    //         let config = IndexPirConfig::new(10, context.bytes_per_plaintext(), 2, 2, false)?;
    //         let parameter = MulPir::generate_parameter(&config, &context);
    //         assert_eq!(parameter.dimensions, vec![4, 3]);
    //     }
    //     // unevenDimensions: true
    //     {
    //         let config = IndexPirConfig::new(15, context.bytes_per_plaintext(), 2, 1, true)?;
    //         let parameter = MulPir::generate_parameter(&config, &context);
    //         assert_eq!(parameter.dimensions, vec![5, 3]);
    //     }
    //     {
    //         let config = IndexPirConfig::new(15, context.bytes_per_plaintext(), 2, 2, true)?;
    //         let parameter = MulPir::generate_parameter(&config, &context);
    //         assert_eq!(parameter.dimensions, vec![5, 3]);
    //     }
    //     {
    //         let config = IndexPirConfig::new(17, context.bytes_per_plaintext(), 2, 2, true)?;
    //         let parameter = MulPir::generate_parameter(&config, &context);
    //         assert_eq!(parameter.dimensions, vec![9, 2]);
    //     }
    //     Ok(())
    // }

    // fn index_pir_test_for_parameter<Server, Client>(
    //     _server: &Server,
    //     _client: &Client,
    //     parameter: &IndexPirParameter,
    //     context: &Context<Server::Scheme>,
    // ) -> Result<()>
    // where
    //     Server: IndexPirServer,
    //     Client: IndexPirClient<IndexPir=Server::IndexPir>,
    // {
    //     let database = get_database_for_testing(parameter.entry_count(), parameter.entry_size_in_bytes());
    //     let processed_db = Server::process(&database, context, parameter)?;
    //
    //     let server = Server::new(parameter, context, &processed_db)?;
    //     let client = Client::new(parameter, context);
    //
    //     let secret_key = context.generate_secret_key()?;
    //     let evaluation_key = client.generate_evaluation_key(&secret_key)?;
    //
    //     for _ in 0..10 {
    //         let mut indices: Vec<usize> = (0..parameter.batch_size()).collect();
    //         indices.shuffle(&mut rand::thread_rng());
    //         let batch_size = rand::thread_rng().gen_range(1..=parameter.batch_size());
    //         let query_indices: Vec<usize> = indices.iter().take(batch_size).cloned().collect();
    //         let query = client.generate_query(&query_indices, &secret_key)?;
    //         let response = server.compute_response(&query, &evaluation_key)?;
    //         if !Server::Scheme::is_no_op() {
    //             assert!(!response.is_transparent());
    //         }
    //         let decrypted_response = client.decrypt(&response, &query_indices, &secret_key)?;
    //         for (i, &index) in query_indices.iter().enumerate() {
    //             assert_eq!(decrypted_response[i], database[index]);
    //         }
    //     }
    //     Ok(())
    // }
    //
    // fn index_pir_test<Server, Client>() -> Result<()>
    // where
    //     Server: IndexPirServer,
    //     Client: IndexPirClient<IndexPir=Server::IndexPir>,
    // {
    //     let config1 = IndexPirConfig::new(100, 1, 2, 2, false)?;
    //     let config2 = IndexPirConfig::new(100, 8, 2, 2, false)?;
    //     let config3 = IndexPirConfig::new(100, 24, 2, 2, true)?;
    //     let config4 = IndexPirConfig::new(100, 24, 1, 2, true)?;
    //
    //     let context: Context<Server::Scheme> = TestUtils::get_test_context()?;
    //     let parameter1 = Server::generate_parameter(&config1, &context);
    //     index_pir_test_for_parameter::<Server, Client>(&Server, &Client, &parameter1, &context)?;
    //
    //     let parameter2 = Server::generate_parameter(&config2, &context);
    //     index_pir_test_for_parameter::<Server, Client>(&Server, &Client, &parameter2, &context)?;
    //
    //     let parameter3 = Server::generate_parameter(&config3, &context);
    //     index_pir_test_for_parameter::<Server, Client>(&Server, &Client, &parameter3, &context)?;
    //
    //     let parameter4 = Server::generate_parameter(&config4, &context);
    //     index_pir_test_for_parameter::<Server, Client>(&Server, &Client, &parameter4, &context)?;
    //
    //     Ok(())
    // }
    //
    // fn mul_index_pir_test<Scheme>() -> Result<()>
    // where
    //     Scheme: HeScheme,
    // {
    //     index_pir_test::<MulPirServer<Scheme>, MulPirClient<Scheme>>()
    // }
    //
    // #[test]
    // fn test_index_pir() -> Result<(), Box<dyn Error>> {
    //     mul_index_pir_test::<NoOpScheme>()?;
    //     mul_index_pir_test::<Bfv<u32>>()?;
    //     mul_index_pir_test::<Bfv<u64>>()?;
    //     Ok(())
    // }
}
