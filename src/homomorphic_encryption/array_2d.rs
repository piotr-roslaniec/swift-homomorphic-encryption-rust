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

use std::{
    marker::Send,
    ops::{Add, Index, IndexMut, Range},
};

/// Stores values in a 2 dimensional array.
#[derive(PartialEq, Clone, Debug)]
pub struct Array2d<T: PartialEq + Add<Output = T> + Send + Clone + Default> {
    data: Vec<T>,
    pub row_count: usize,
    pub column_count: usize,
}

impl<T: PartialEq + Add<Output = T> + Send + Clone + Default> Array2d<T> {
    /// Returns the shape of the array as a tuple (row_count, column_count).
    pub fn shape(&self) -> (usize, usize) {
        (self.row_count, self.column_count)
    }

    /// Returns the total number of elements in the array.
    pub fn count(&self) -> usize {
        self.row_count * self.column_count
    }

    /// Creates a new `Array2d` with the given data and dimensions.
    pub fn new(data: Vec<T>, row_count: usize, column_count: usize) -> Self {
        assert_eq!(data.len(), (row_count * column_count), "Data size does not match dimensions");
        Self { data, row_count, column_count }
    }

    /// Calculates the linear index for a given (row, column) pair.
    pub fn index(&self, row: usize, column: usize) -> usize {
        row * self.column_count + column
    }

    /// Returns the range of indices for a given row.
    pub fn row_indices(&self, row: usize) -> Range<usize> {
        let start = self.index(row, 0);
        let end = start + self.column_count;
        start..end
    }

    /// Returns an iterator over the columns of the array.
    pub fn columns_iter(&self) -> impl Iterator<Item = Vec<&T>> {
        (0..self.column_count).map(move |col| {
            (0..self.row_count).map(move |row| &self.data[self.index(row, col)]).collect()
        })
    }
}

impl<T: PartialEq + Add<Output = T> + Send + Clone + Default> Index<usize> for Array2d<T> {
    type Output = [T];

    fn index(&self, row: usize) -> &Self::Output {
        let start = self.index(row, 0);
        let end = start + self.column_count;
        &self.data[start..end]
    }
}

impl<T: PartialEq + Add<Output = T> + Send + Clone + Default> IndexMut<usize> for Array2d<T> {
    fn index_mut(&mut self, row: usize) -> &mut Self::Output {
        let start = self.index(row, 0);
        let end = start + self.column_count;
        &mut self.data[start..end]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_array2d() {
        let data = vec![1, 2, 3, 4, 5, 6];
        let mut array = Array2d::new(data, 2, 3);

        // Test shape and count
        assert_eq!(array.shape(), (2, 3));
        assert_eq!(array.count(), 6);

        // Test double indexing
        assert_eq!(array[0][0], 1);
        assert_eq!(array[0][1], 2);
        assert_eq!(array[0][2], 3);
        assert_eq!(array[1][0], 4);
        assert_eq!(array[1][1], 5);
        assert_eq!(array[1][2], 6);

        // Test mutability
        array[1][2] = 42;
        assert_eq!(array[1][2], 42);

        // Test row_indices
        let row_1_indices = array.row_indices(1);
        assert_eq!(row_1_indices, 3..6);
    }
}
