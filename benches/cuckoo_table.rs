use criterion::{criterion_group, criterion_main, Criterion};
use rand::rngs::StdRng;
use rand::Rng;
use rand_core::SeedableRng;
use std::collections::HashSet;
use swift_homomorphic_encryption_rust::cuckoo_table::{
    BucketCountConfig, CuckooBucketEntry, CuckooTable, CuckooTableConfig,
};

fn generate_random_data<R: Rng>(size: usize, rng: &mut R) -> Vec<u8> {
    (0..size).map(|_| rng.gen()).collect()
}

fn get_test_table<R: Rng>(
    row_count: usize,
    value_size: usize,
    rng: &mut R,
) -> Vec<CuckooBucketEntry> {
    let keyword_size = 30;
    let mut keywords = HashSet::new();
    let mut rows = Vec::with_capacity(row_count);

    while rows.len() < row_count {
        let keyword = generate_random_data(keyword_size, rng);
        if keywords.contains(&keyword) {
            continue;
        }
        keywords.insert(keyword.clone());
        let value = generate_random_data(value_size, rng);
        let entry = CuckooBucketEntry::new(keyword.clone(), value.clone());
        rows.push(entry);
    }

    rows
}

fn bench_cuckoo_table_insert(c: &mut Criterion) {
    let mut rng = Box::new(StdRng::seed_from_u64(0));
    let test_database = get_test_table(1000, 100, &mut rng);

    let hash_function_counts = vec![2, 4, 6];
    for &hash_function_count in &hash_function_counts {
        let config = CuckooTableConfig {
            hash_function_count,
            max_eviction_count: 100,
            max_serialized_bucket_size: 1000,
            bucket_count: BucketCountConfig::AllowExpansion {
                expansion_factor: 1.1,
                target_load_factor: 0.5,
            },
            multiple_tables: true,
        };
        let mut cuckoo_table = CuckooTable::new(config, vec![], rng.clone()).unwrap();

        c.bench_function(&format!("cuckoo_table_insert__hash_fc={}", hash_function_count), |b| {
            b.iter(|| {
                for entry in test_database.iter() {
                    cuckoo_table.insert(entry).unwrap();
                }
            });
        });
    }
}

fn bench_cuckoo_table_insert_get(c: &mut Criterion) {
    let mut rng = Box::new(StdRng::seed_from_u64(0));
    let test_database = get_test_table(1000, 100, &mut rng);

    let hash_function_counts = vec![2, 4, 6];
    for &hash_function_count in &hash_function_counts {
        let config = CuckooTableConfig {
            hash_function_count,
            max_eviction_count: 100,
            max_serialized_bucket_size: 1000,
            bucket_count: BucketCountConfig::AllowExpansion {
                expansion_factor: 1.1,
                target_load_factor: 0.5,
            },
            multiple_tables: true,
        };
        let mut cuckoo_table = CuckooTable::new(config, vec![], rng.clone()).unwrap();
        for entry in test_database.iter() {
            cuckoo_table.insert(entry).unwrap();
        }

        c.bench_function(&format!("cuckoo_table_get__hash_fc={}", hash_function_count), |b| {
            b.iter(|| {
                for entry in test_database.iter() {
                    cuckoo_table.get(&entry.keyword).unwrap();
                }
            });
        });
    }
}

criterion_group!(benches, bench_cuckoo_table_insert, bench_cuckoo_table_insert_get);
criterion_main!(benches);
