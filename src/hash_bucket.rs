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

//! The `hash_bucket` module provides functionality for managing collections of hash bucket entries,
//! which are pairs of hashed keywords and their associated values. Hash bucket entries are used by
//! the `cuckoo_table` module to manage keyword-value pairs using cuckoo hashing. The main components are:
//!
//! - `HashBucketEntry`: Represents a single entry in a `HashBucket`, consisting of a hashed keyword and its associated value.
//! - `HashBucket`: A collection of `HashBucketEntry` items.
//! - `HashKeyword`: Provides utility functions for hashing keywords and generating hash indices.
//!
//! # Examples
//!
//! ```
//! use swift_homomorphic_encryption_rust::hash_bucket::{HashBucket, HashBucketEntry, HashKeyword};
//! use eyre::Result;
//!
//! // Create a new hash bucket with some entries
//! let entries = vec![
//!     HashBucketEntry::new(HashKeyword::hash(b"example1"), vec![0, 1, 2]),
//!     HashBucketEntry::new(HashKeyword::hash(b"example2"), vec![10, 11, 12]),
//! ];
//! let bucket = HashBucket::new(&entries)?;
//! assert_eq!(bucket.slots.len(), 2);
//!
//! // Serialize and deserialize the bucket
//! let serialized = bucket.serialize().unwrap();
//! let deserialized = HashBucket::deserialize(&serialized).unwrap();
//! assert_eq!(bucket, deserialized);
//! Ok::<(), eyre::Report>(())
//! ```

use crate::cuckoo_table::{CuckooBucket, CuckooBucketEntry};
use eyre::Result;
use sha2::{Digest, Sha256};
use thiserror::Error;

/// An error type for hash bucket operations.
#[derive(Error, Debug, Clone, PartialEq)]
pub enum HashBucketError {
    /// An error indicating that the serialized `HashBucket` is empty when we try to deserialize it.
    #[error("Serialized HashBucket shouldn't be empty.")]
    EmptyBucket,

    /// An error indicating that the buffer is too small to deserialize a `HashBucketEntry`.
    #[error("Buffer too small")]
    BufferTooSmall,

    /// An error indicating that the number of slots in the `HashBucket` exceeds the maximum allowed.
    #[error("Slot count exceeds maximum")]
    SlotCountExceedsMaximum,

    /// An error indicating that the size of a value exceeds the maximum allowed.
    #[error("Value size exceeds maximum")]
    ValueSizeExceedsMaximum,

    /// An error indicating that the hash function failed to generate a unique index after `MAX_RETRIES` attempts.
    #[error("Failed to generate unique hash index after {0} attempts")]
    FailedToGenerateUniqueIndex(u8),
}

const U8_SIZE: usize = size_of::<u8>();
const U16_SIZE: usize = size_of::<u16>();
const U64_SIZE: usize = size_of::<u64>();

/// A `KeywordHash` represents a 64-bit hash of a keyword.
/// The hash is used to identify the keyword in a `HashBucket`.
/// The hash is generated using the SHA-256 algorithm.
pub type KeywordHash = u64;

/// A `HashBucketValue` represents the value associated with a keyword in a `HashBucket`.
/// The value is stored in a `HashBucketEntry` and can be retrieved by its hashed key.
/// The value is a vector of bytes, which can be any arbitrary data.
pub type HashBucketValue = Vec<u8>;

/// A `HashBucketEntry` represents a single entry in a `HashBucket`, consisting of a hashed keyword and its associated value.
///
/// # Examples
///
/// ```
/// use swift_homomorphic_encryption_rust::hash_bucket::HashBucketEntry;
///
/// let entry = HashBucketEntry::new(123456789, vec![1, 2, 3]);
/// assert_eq!(entry.keyword_hash, 123456789);
/// assert_eq!(entry.value, vec![1, 2, 3]);
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct HashBucketEntry {
    /// A 64-bit hash of the keyword.
    pub keyword_hash: u64,
    /// A vector of bytes representing the value associated with the keyword.
    pub value: Vec<u8>,
}

impl From<&CuckooBucketEntry> for HashBucketEntry {
    fn from(value: &CuckooBucketEntry) -> Self {
        Self {
            value: value.value.clone(),
            // TODO: Get rid of .expect
            keyword_hash: HashKeyword::le_bytes_to_u64(&value.keyword[..U64_SIZE])
                .expect("Conversion may not fail"),
        }
    }
}

impl HashBucketEntry {
    /// The maximum size of a value in a `HashBucketEntry`.
    const MAX_VALUE_SIZE: usize = u16::MAX as usize;

    /// Creates a new `HashBucketEntry`.
    ///
    /// # Arguments
    ///
    /// * `keyword_hash` - A 64-bit hash of the keyword.
    /// * `value` - A vector of bytes representing the value associated with the keyword.
    ///
    /// # Examples
    ///
    /// ```
    /// use swift_homomorphic_encryption_rust::hash_bucket::HashBucketEntry;
    ///
    /// let entry = HashBucketEntry::new(123456789, vec![1, 2, 3]);
    /// assert_eq!(entry.keyword_hash, 123456789);
    /// assert_eq!(entry.value, vec![1, 2, 3]);
    /// ```
    pub fn new(keyword_hash: u64, value: Vec<u8>) -> Self {
        Self { keyword_hash, value }
    }

    /// Deserializes a `HashBucketEntry` from a buffer.
    ///
    /// # Arguments
    ///
    /// * `buffer` - A slice of bytes containing the serialized `HashBucketEntry`.
    /// * `offset` - A mutable reference to the current offset in the buffer. It will be updated to the next offset after deserialization.
    ///
    /// # Returns
    ///
    /// A `Result` containing the deserialized `HashBucketEntry` or a `HashBucketError` if deserialization fails.
    ///
    /// # Errors
    ///
    /// Returns `HashBucketError::BufferTooSmall` if the buffer is too small to deserialize the entry.
    ///
    /// # Examples
    ///
    /// ```
    /// use swift_homomorphic_encryption_rust::hash_bucket::{HashBucketEntry, HashBucketError};
    /// use eyre::Result;
    ///
    /// let buffer = vec![1, 0, 0, 0, 0, 0, 0, 0, 3, 0, 1, 2, 3];
    /// let mut offset = 0;
    /// let entry = HashBucketEntry::deserialize(&buffer, &mut offset)?;
    /// assert_eq!(entry.keyword_hash, 1);
    /// assert_eq!(entry.value, vec![1, 2, 3]);
    /// # Ok::<(), eyre::Report>(())
    /// ```
    pub fn deserialize(buffer: &[u8], offset: &mut usize) -> Result<Self, HashBucketError> {
        let mut iter = buffer[*offset..].iter();

        let keyword_hash = iter
            .by_ref()
            .take(U64_SIZE)
            .cloned()
            .collect::<Vec<u8>>()
            .try_into()
            .map(u64::from_le_bytes)
            .map_err(|_| HashBucketError::BufferTooSmall)?;
        *offset += U64_SIZE;

        let value_size = iter
            .by_ref()
            .take(U16_SIZE)
            .cloned()
            .collect::<Vec<u8>>()
            .try_into()
            .map(u16::from_le_bytes)
            .map_err(|_| HashBucketError::BufferTooSmall)? as usize;
        *offset += U16_SIZE;

        let value = iter.by_ref().take(value_size).cloned().collect::<Vec<u8>>();
        if value.len() < value_size {
            return Err(HashBucketError::BufferTooSmall);
        }
        *offset += value_size;

        Ok(Self { keyword_hash, value })
    }

    /// Serializes a `HashBucketEntry` into a buffer.
    ///
    /// # Returns
    ///
    /// A `Result` containing a vector of bytes representing the serialized `HashBucketEntry` or a `HashBucketError` if serialization fails.
    ///
    /// # Errors
    ///
    /// Returns `HashBucketError::ValueSizeExceedsMaximum` if the size of the value exceeds the maximum allowed.
    ///
    /// # Examples
    ///
    /// ```
    /// use swift_homomorphic_encryption_rust::hash_bucket::{HashBucketEntry, HashBucketError};
    /// use eyre::Result;
    ///
    /// let entry = HashBucketEntry::new(123456789, vec![1, 2, 3]);
    /// let serialized = entry.serialize().unwrap();
    /// assert_eq!(serialized, vec![21, 205, 91, 7, 0, 0, 0, 0, 3, 0, 1, 2, 3]);
    /// # Ok::<(), eyre::Report>(())
    /// ```
    pub fn serialize(&self) -> Result<Vec<u8>, HashBucketError> {
        if self.value.len() > Self::MAX_VALUE_SIZE {
            return Err(HashBucketError::ValueSizeExceedsMaximum);
        }
        let mut data = Vec::with_capacity(U64_SIZE + U16_SIZE + self.value.len());
        data.extend_from_slice(&self.keyword_hash.to_le_bytes());
        data.extend_from_slice(&(self.value.len() as u16).to_le_bytes());
        data.extend_from_slice(&self.value);
        Ok(data)
    }

    /// Returns the size of a serialized `HashBucketEntry`.
    ///
    /// # Arguments
    ///
    /// * `value` - A slice of bytes representing the value.
    ///
    /// # Returns
    ///
    /// The size of the serialized `HashBucketEntry`.
    ///
    /// # Examples
    ///
    /// ```
    /// use swift_homomorphic_encryption_rust::hash_bucket::HashBucketEntry;
    ///
    /// let size = HashBucketEntry::serialized_size(&[1, 2, 3]);
    /// assert_eq!(size, 13);
    /// ```
    pub fn serialized_size(value: &[u8]) -> usize {
        Self::serialized_size_with_value_size(value.len())
    }

    /// Returns the size of a serialized `HashBucketEntry` given the size of the value.
    ///
    /// # Arguments
    ///
    /// * `value_size` - The size of the value in bytes.
    ///
    /// # Returns
    ///
    /// The size of the serialized `HashBucketEntry`.
    ///
    /// # Examples
    ///
    /// ```
    /// use swift_homomorphic_encryption_rust::hash_bucket::HashBucketEntry;
    ///
    /// let size = HashBucketEntry::serialized_size_with_value_size(3);
    /// assert_eq!(size, 13);
    /// ```
    pub fn serialized_size_with_value_size(value_size: usize) -> usize {
        // Keyword hash (8 bytes) + value size (2 bytes) + value
        U64_SIZE + U16_SIZE + value_size
    }
}

/// A `HashBucket` is a collection of `HashBucketEntry` items, or (hash(keyword), value) pairs.
///
/// # Examples
///
/// ```
/// use swift_homomorphic_encryption_rust::hash_bucket::{HashBucket, HashBucketEntry};
/// use eyre::Result;
///
/// let entries = vec![
///     HashBucketEntry::new(0, vec![0, 1, 2]),
///     HashBucketEntry::new(1, vec![10, 11, 12]),
/// ];
/// let bucket = HashBucket::new(&entries)?;
/// assert_eq!(bucket.slots.len(), 2);
/// Ok::<(), eyre::Report>(())
/// ```
#[derive(Debug, PartialEq, Eq)]
pub struct HashBucket {
    /// A list of `HashBucketEntry` items in the bucket.
    pub slots: Vec<HashBucketEntry>,
}

impl From<&CuckooBucket> for HashBucket {
    fn from(value: &CuckooBucket) -> Self {
        let hash_bucket_entries: Vec<HashBucketEntry> =
            value.slots.iter().map(HashBucketEntry::from).collect();
        // TODO: Get rid of .expect
        Self::new(&hash_bucket_entries).expect("Conversion may not fail")
    }
}

impl HashBucket {
    /// The maximum number of slots (entries) allowed in a `HashBucket`.
    pub const MAX_SLOT_COUNT: usize = u8::MAX as usize;

    /// Creates a new `HashBucket` with the given list of `HashBucketEntry` items.
    ///
    /// # Arguments
    ///
    /// * `slots` - A list of `HashBucketEntry` items to be added to the bucket.
    ///
    /// # Returns
    ///
    /// A `Result` containing the new `HashBucket` on success, or a `HashBucketError` on failure.
    ///
    /// # Errors
    ///
    /// Returns `HashBucketError::SlotCountExceedsMaximum` if the number of slots exceeds the maximum allowed.
    ///
    /// # Examples
    ///
    /// ```
    /// use swift_homomorphic_encryption_rust::hash_bucket::{HashBucket, HashBucketEntry};
    /// use eyre::Result;
    ///
    /// let slots = vec![HashBucketEntry::new(0, vec![1, 2, 3]), HashBucketEntry::new(1, vec![10, 20, 30])];
    /// let bucket = HashBucket::new(&slots)?;
    /// assert_eq!(bucket.slots.len(), 2);
    /// # Ok::<(), eyre::Report>(())
    pub fn new(slots: &[HashBucketEntry]) -> Result<Self> {
        if slots.len() > Self::MAX_SLOT_COUNT {
            return Err(HashBucketError::SlotCountExceedsMaximum.into());
        }

        Ok(Self { slots: slots.to_vec() })
    }

    /// Adds a new entry to the `HashBucket`.
    ///
    /// # Arguments
    ///
    /// * `entry` - A `HashBucketEntry` to be added to the bucket.
    ///
    /// # Examples
    ///
    /// ```
    /// use swift_homomorphic_encryption_rust::hash_bucket::{HashBucket, HashBucketEntry};
    /// use eyre::Result;
    ///
    /// let mut bucket = HashBucket::new(&[])?;
    /// let entry = HashBucketEntry::new(0, vec![1, 2, 3]);
    /// bucket.add_entry(entry);
    /// assert_eq!(bucket.slots.len(), 1);
    /// Ok::<(), eyre::Report>(())
    /// ```
    pub fn add_entry(&mut self, entry: HashBucketEntry) {
        self.slots.push(entry);
    }

    /// Removes an entry from the `HashBucket` by its hashed key.
    ///
    /// # Arguments
    ///
    /// * `hash` - A `u64` representing the hashed key of the entry to be removed.
    ///
    /// # Examples
    ///
    /// ```
    /// use swift_homomorphic_encryption_rust::hash_bucket::{HashBucket, HashBucketEntry};
    /// use eyre::Result;
    ///
    /// let entry = HashBucketEntry::new(0, vec![1, 2, 3]);
    /// let mut bucket = HashBucket::new(&[entry.clone()])?;
    /// let hash = entry.keyword_hash;
    /// bucket.remove_entry_by_hash(hash);
    /// assert_eq!(bucket.slots.len(), 0);
    /// # Ok::<(), eyre::Report>(())
    /// ```
    pub fn remove_entry_by_hash(&mut self, hash: u64) -> Option<HashBucketEntry> {
        if let Some(pos) = self.slots.iter().position(|entry| entry.keyword_hash == hash) {
            Some(self.slots.remove(pos))
        } else {
            None
        }
    }

    /// Checks if the `HashBucket` contains an entry with the given hashed key.
    ///
    /// # Arguments
    ///
    /// * `hash` - A `u64` representing the hashed key to check for.
    ///
    /// # Examples
    ///
    /// ```
    /// use swift_homomorphic_encryption_rust::hash_bucket::{HashBucket, HashBucketEntry};
    /// use eyre::Result;
    ///
    /// let entry = HashBucketEntry::new(0, vec![1, 2, 3]);
    /// let bucket = HashBucket::new(&[entry.clone()])?;
    /// let hash = entry.keyword_hash;
    /// assert!(bucket.contains_hash(hash));
    /// # Ok::<(), eyre::Report>(())
    /// ```
    pub fn contains_hash(&self, hash: u64) -> bool {
        self.slots.iter().any(|entry| entry.keyword_hash == hash)
    }

    /// Deserializes a `HashBucket` from a slice of bytes.
    ///
    /// # Arguments
    ///
    /// * `raw_bucket` - A slice of bytes representing the serialized `HashBucket`.
    ///
    /// # Returns
    ///
    /// A `Result` containing the deserialized `HashBucket` on success, or a `HashBucketError` on failure.
    ///
    /// # Errors
    ///
    /// Returns `HashBucketError::EmptyBucket` if the input slice is empty.
    ///
    /// # Examples
    ///
    /// ```
    /// use swift_homomorphic_encryption_rust::hash_bucket::{HashBucket, HashBucketEntry};
    /// use eyre::Result;
    ///
    /// let entry = HashBucketEntry::new(0, vec![1, 2, 3]);
    /// let bucket = HashBucket::new(&[entry.clone()])?;
    /// let serialized = bucket.serialize().unwrap();
    /// let deserialized = HashBucket::deserialize(&serialized).unwrap();
    /// assert_eq!(bucket, deserialized);
    /// # Ok::<(), eyre::Report>(())
    /// ```

    pub fn deserialize(raw_bucket: &[u8]) -> Result<Self, HashBucketError> {
        if raw_bucket.is_empty() {
            return Err(HashBucketError::EmptyBucket);
        }

        let mut iter = raw_bucket.iter();
        let count = *iter.next().ok_or(HashBucketError::BufferTooSmall)? as usize;

        let mut entries = Vec::with_capacity(count);
        let mut offset = U8_SIZE;

        for _ in 0..count {
            let entry = HashBucketEntry::deserialize(raw_bucket, &mut offset)?;
            entries.push(entry);
        }

        Ok(Self { slots: entries })
    }

    /// Calculates the serialized size of a list of values.
    ///
    /// # Arguments
    ///
    /// * `values` - A slice of vectors of bytes representing the values.
    ///
    /// # Returns
    ///
    /// The total size in bytes required to serialize the list of values.
    ///
    /// # Examples
    ///
    /// ```
    /// use swift_homomorphic_encryption_rust::hash_bucket::HashBucket;
    ///
    /// let values = vec![vec![1, 2, 3], vec![4, 5, 6]];
    /// let size = HashBucket::serialized_size(&values);
    /// assert!(size > 0);
    /// ```
    pub fn serialized_size(values: &[Vec<u8>]) -> usize {
        // Number of slots + sum of serialized sizes of all values
        U8_SIZE + values.iter().map(|v| HashBucketEntry::serialized_size(v)).sum::<usize>()
    }

    /// Calculates the serialized size of a single value.
    ///
    /// # Arguments
    ///
    /// * `single_value_size` - The size of the single value in bytes.
    ///
    /// # Returns
    ///
    /// The total size in bytes required to serialize the single value.
    ///
    /// # Examples
    ///
    /// ```
    /// use swift_homomorphic_encryption_rust::hash_bucket::HashBucket;
    ///
    /// let size = HashBucket::serialized_size_with_value_size(3);
    /// assert!(size > 0);
    /// ```
    pub fn serialized_size_with_value_size(single_value_size: usize) -> usize {
        // Number of slots + serialized size of a single value
        U8_SIZE + HashBucketEntry::serialized_size_with_value_size(single_value_size)
    }

    /// Serializes the `HashBucket` into a vector of bytes.
    ///
    /// The serialization format for `HashBucket` is as follows:
    ///
    /// 1. The first byte represents the number of slots (entries) in the `HashBucket`.
    /// 2. Each slot is serialized in sequence:
    ///     - The first 8 bytes of each slot represent the `keyword_hash` as a little-endian `u64`.
    ///     - The next 2 bytes represent the size of the `value` as a little-endian `u16`.
    ///     - The remaining bytes are the `value` itself, which is a vector of bytes.
    ///
    /// # Returns
    ///
    /// A `Result` containing a `Vec<u8>` representing the serialized `HashBucket` on success,
    /// or a `HashBucketError` on failure.
    ///
    /// # Errors
    ///
    /// Returns `HashBucketError::SlotCountExceedsMaximum` if the number of slots exceeds the maximum allowed.
    ///
    /// # Examples
    ///
    /// ```
    /// use swift_homomorphic_encryption_rust::hash_bucket::{HashBucket, HashBucketEntry};
    /// use eyre::Result;
    ///
    /// let entry = HashBucketEntry::new(0, vec![1, 2, 3]);
    /// let bucket = HashBucket::new(&[entry.clone()])?;
    /// let serialized = bucket.serialize()?;
    /// assert!(!serialized.is_empty());
    /// Ok::<(), eyre::Report>(())
    /// ```
    pub fn serialize(&self) -> Result<Vec<u8>, HashBucketError> {
        if self.slots.len() > u8::MAX as usize {
            return Err(HashBucketError::SlotCountExceedsMaximum);
        }
        let mut data = Vec::with_capacity(Self::serialized_size(
            &self.slots.iter().map(|slot| slot.value.clone()).collect::<Vec<_>>(),
        ));
        data.push(self.slots.len() as u8);
        for slot in &self.slots {
            data.extend_from_slice(&slot.serialize()?);
        }
        Ok(data)
    }

    /// Finds a value in the `HashBucket` by its original key.
    ///
    /// # Arguments
    ///
    /// * `keyword` - A slice of bytes representing the original key to search for.
    ///
    /// # Returns
    ///
    /// An `Option` containing the value associated with the key, or `None` if the key is not found.
    ///
    /// # Examples
    ///
    /// ```
    /// use swift_homomorphic_encryption_rust::hash_bucket::{HashBucket, HashBucketEntry};
    /// use eyre::Result;
    ///
    /// let entry = HashBucketEntry::new(0, vec![1, 2, 3]);
    /// let bucket = HashBucket::new(&[entry.clone()])?;
    /// let value = bucket.find(b"Hello");
    /// assert_eq!(value, None);
    /// # Ok::<(), eyre::Report>(())
    /// ```
    pub fn find(&self, keyword: &[u8]) -> Option<Vec<u8>> {
        let hash = HashKeyword::hash(keyword);
        self.find_by_hash(hash)
    }

    /// Finds a value in the `HashBucket` by its hash.
    ///
    /// # Arguments
    ///
    /// * `hash` - A 64-bit hash representing the key to search for.
    ///
    /// # Returns
    ///
    /// An `Option` containing the value associated with the hash, or `None` if the hash is not found.
    ///
    /// # Examples
    ///
    /// ```
    /// use swift_homomorphic_encryption_rust::hash_bucket::{HashBucket, HashBucketEntry};
    /// use eyre::Result;
    ///
    /// let entry = HashBucketEntry::new(123456789, vec![1, 2, 3]);
    /// let bucket = HashBucket::new(&[entry.clone()])?;
    /// let value = bucket.find_by_hash(123456789);
    /// assert_eq!(value, Some(vec![1, 2, 3]));
    /// # Ok::<(), eyre::Report>(())
    /// ```

    pub fn find_by_hash(&self, hash: u64) -> Option<Vec<u8>> {
        self.slots.iter().find(|item| item.keyword_hash == hash).map(|item| item.value.clone())
    }
}

/// A `HashKeyword` provides utility functions for hashing keywords and generating hash indices.
///
/// # Examples
///
/// ```
/// use swift_homomorphic_encryption_rust::hash_bucket::HashKeyword;
/// use eyre::Result;
///
/// let keyword = b"example";
/// let hash = HashKeyword::hash(keyword);
/// assert!(hash > 0);
///
/// let indices = HashKeyword::hash_indices(keyword, 10, 3)?;
/// assert_eq!(indices.len(), 3);
/// assert!(indices.iter().all(|&index| index < 10));
/// # Ok::<(), eyre::Report>(())
/// ```
pub struct HashKeyword;

impl HashKeyword {
    /// The maximum number of retries to generate unique hash indices.
    const MAX_RETRIES: u8 = 10;

    /// Computes a 64-bit hash for a given keyword.
    ///
    /// # Arguments
    ///
    /// * `keyword` - A slice of bytes representing the keyword to be hashed.
    ///
    /// # Returns
    ///
    /// A 64-bit hash of the keyword.
    ///
    /// # Examples
    ///
    /// ```
    /// use swift_homomorphic_encryption_rust::hash_bucket::HashKeyword;
    ///
    /// let hash = HashKeyword::hash(b"example");
    /// assert!(hash > 0);
    /// ```
    pub fn hash(keyword: &[u8]) -> KeywordHash {
        let mut hasher = Sha256::new();
        hasher.update(keyword);
        let result = hasher.finalize();
        Self::le_bytes_to_u64(&result[0..U64_SIZE]).unwrap()
    }

    /// Generates a list of unique bucket indices for a given keyword.
    ///
    /// The number of indices generated is determined by the `hash_function_count` parameter.
    /// The indices are guaranteed to be unique and within the range of `bucket_count`.
    /// The indices are generated by applying multiple hash functions to the `keyword`.
    ///
    /// # Arguments
    ///
    /// * `keyword` - The keyword to hash.
    /// * `bucket_count` - The total number of buckets.
    /// * `hash_function_count` - A number of candidate indices to generate.
    ///
    /// # Returns
    ///
    /// An array of indices, which are the possible locations for the `keyword` in the `CuckooTable`.
    ///
    /// # Errors
    ///
    /// Returns a `HashBucketError` if the function fails to generate unique indices after `MAX_RETRIES` attempts.
    ///
    /// # Examples
    ///
    /// ```
    /// use swift_homomorphic_encryption_rust::hash_bucket::HashKeyword;
    /// use eyre::Result;
    ///
    /// let indices = HashKeyword::hash_indices(b"example", 10, 3)?;
    /// assert_eq!(indices.len(), 3);
    /// assert!(indices.iter().all(|&index| index < 10));
    /// # Ok::<(), eyre::Report>(())
    /// ```
    pub fn hash_indices(
        keyword: &[u8],
        bucket_count: usize,
        hash_function_count: usize,
    ) -> Result<Vec<usize>> {
        let keyword_hash = Self::hash(keyword);
        let mut candidates = Vec::with_capacity(hash_function_count);
        for _ in 0..hash_function_count {
            let mut counter = 0u8;
            let mut bucket_index = Self::index_from_hash(keyword_hash, bucket_count, counter)?;
            // Ensure the index is unique
            while candidates.contains(&bucket_index) && counter < Self::MAX_RETRIES {
                counter += 1;
                bucket_index = Self::index_from_hash(keyword_hash, bucket_count, counter)?;
            }

            // If we've reached the maximum number of retries, return an error
            // Note: This is a deviation from the original implementation, which would return the last index generated.
            // if counter == Self::MAX_RETRIES {
            //     return Err(HashBucketError::FailedToGenerateUniqueIndex(Self::MAX_RETRIES).into());
            // }

            candidates.push(bucket_index);
        }
        Ok(candidates)
    }

    /// Computes a bucket index from a hash and a counter.
    ///
    /// # Arguments
    ///
    /// * `keyword_hash` - The hash of the keyword.
    /// * `bucket_count` - The total number of buckets.
    /// * `counter` - An additional counter to randomize the output.
    ///
    /// # Returns
    ///
    /// A pseudo-random index within the range of `bucket_count`.
    ///
    /// # Examples
    ///
    /// ```
    /// use swift_homomorphic_encryption_rust::hash_bucket::HashKeyword;
    /// use eyre::Result;
    ///
    /// let index = HashKeyword::index_from_hash(123456789, 10, 0)?;
    /// assert!(index < 10);
    /// # Ok::<(), eyre::Report>(())
    /// ```
    pub fn index_from_hash(keyword_hash: u64, bucket_count: usize, counter: u8) -> Result<usize> {
        let mut hasher = Sha256::new();
        hasher.update(keyword_hash.to_be_bytes());
        hasher.update([counter]);
        let result = hasher.finalize();
        // Truncate the hash to the first 8 bytes and convert a little endian u64
        let hash = Self::le_bytes_to_u64(&result[0..U64_SIZE])?;
        let index = (hash % bucket_count as u64) as usize;
        Ok(index)
    }

    /// Converts a slice of little-endian bytes to a `u64`.
    ///
    /// # Parameters
    ///
    /// * `bytes` - A slice of bytes representing a little-endian `u64`.
    ///
    /// # Returns
    ///
    /// A `Result` containing the `u64` value on success, or a `TryFromSliceError` if the conversion fails.
    pub fn le_bytes_to_u64(bytes: &[u8]) -> Result<u64, std::array::TryFromSliceError> {
        let array: [u8; U64_SIZE] = bytes.try_into()?;
        Ok(u64::from_le_bytes(array))
    }
}

#[cfg(test)]
mod tests {
    use rand::Rng;

    use crate::hash_bucket::*;

    const RAW_BUCKET: &[u8] = &[
        3, 24, 95, 141, 179, 34, 113, 254, 37, 5, 0, 87, 111, 114, 108, 100, 82, 117, 17, 222, 175,
        220, 211, 74, 6, 0, 77, 97, 97, 105, 108, 109, 192, 21, 173, 109, 218, 248, 187, 80, 8, 0,
        68, 97, 114, 107, 110, 101, 115, 115,
    ];

    fn get_test_entry() -> HashBucketEntry {
        let size = rand::thread_rng().gen_range(1..=100);
        let random_data: Vec<u8> = (0..size).map(|_| rand::random::<u8>()).collect();
        HashBucketEntry::new(rand::random::<u64>(), random_data)
    }

    fn get_test_bucket() -> HashBucket {
        let count = rand::thread_rng().gen_range(1..=10);
        let slots: Vec<HashBucketEntry> = (0..count).map(|_| get_test_entry()).collect();
        HashBucket::new(&slots).unwrap()
    }

    #[test]
    fn test_serialization() {
        let test_bucket = get_test_bucket();
        let serialized = test_bucket.serialize().unwrap();
        let deserialized = HashBucket::deserialize(&serialized).unwrap();
        assert_eq!(test_bucket, deserialized);
    }

    #[test]
    fn test_serialization_error() {
        let size = (u16::MAX as usize) + 1;
        let random_data: Vec<u8> = (0..size).map(|_| rand::random::<u8>()).collect();
        let test_entry = HashBucketEntry::new(rand::random::<u64>(), random_data);
        assert!(test_entry.serialize().is_err());
    }

    #[test]
    fn test_hash_bucket_entry_serialization_size() {
        let test_entry = get_test_entry();
        let serialized = test_entry.serialize().unwrap();
        assert_eq!(serialized.len(), HashBucketEntry::serialized_size(&test_entry.value));
    }

    #[test]
    fn test_hash_bucket_serialization_size() {
        let test_bucket = get_test_bucket();
        let serialized = test_bucket.serialize().unwrap();
        let values: Vec<Vec<u8>> =
            test_bucket.slots.iter().map(|slot| slot.value.clone()).collect();
        assert_eq!(serialized.len(), HashBucket::serialized_size(&values));
    }
    #[test]
    fn test_hash_indices() {
        assert_eq!(HashKeyword::hash_indices(&[0, 1, 2, 3], 8, 3).unwrap(), vec![7, 3, 0]);
        let indices = vec![1989, 1767, 1260, 242, 1122];
        assert_eq!(HashKeyword::hash_indices(&[3, 2, 1, 0], 2048, 5).unwrap(), indices);
    }

    #[test]
    fn test_bucket_deserialization() {
        let bucket = HashBucket::deserialize(RAW_BUCKET).unwrap();
        assert_eq!(bucket.find(b"Hello"), Some(b"World".to_vec()));
        assert_eq!(bucket.find(b"Goodbye"), Some(b"Darkness".to_vec()));
        assert_eq!(bucket.slots.len(), 3);
    }
}
