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

use std::marker::Send;
use std::ops::{Add, Range};

/// Stores values in a 2 dimensional array.
#[derive(PartialEq, Clone, Debug)]
pub struct Array2d<T: PartialEq + Add<Output=T> + Send + PartialEq> {
    data: Vec<T>,
    pub row_count: u32,
    pub column_count: u32,
}

impl<T: PartialEq + Add<Output=T> + Send> Array2d<T> {
    /// Returns the shape of the array as a tuple (row_count, column_count).
    pub fn shape(&self) -> (u32, u32) {
        (self.row_count, self.column_count)
    }

    /// Returns the total number of elements in the array.
    pub fn count(&self) -> u32 {
        self.row_count * self.column_count
    }

    /// Creates a new `Array2d` with the given data and dimensions.
    pub fn new(data: Vec<T>, row_count: u32, column_count: u32) -> Self {
        assert_eq!(data.len(), (row_count * column_count) as usize, "Data size does not match dimensions");
        Self { data, row_count, column_count }
    }

    pub fn index(&self, row: u32, column: u32) -> u32 {
        row.wrapping_mul(self.column_count).wrapping_add(column)
    }

    pub fn row_indices(&self, row: u32) -> Range<u32> {
        self.index(row, 0)..self.index(row, self.column_count)
    }

}

use std::ops::{Index, IndexMut};

impl<T: PartialEq + Add<Output=T> + Send> Index<usize> for Array2d<T> {
    type Output = T;

    fn index(&self, index: usize) -> &Self::Output {
        let row = index / self.column_count as usize;
        let col = index % self.column_count as usize;
        &self.data[row * self.column_count as usize + col]
    }
}

impl<T: PartialEq + Add<Output=T> + Send> IndexMut<usize> for Array2d<T> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        let row = index / self.column_count as usize;
        let col = index % self.column_count as usize;
        &mut self.data[row * self.column_count as usize + col]
    }
}
