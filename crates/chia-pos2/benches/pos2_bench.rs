//! Throughput benchmarks for `chia_pos2` FFI-heavy APIs.
//!
//! **Plot file:** expects the same file the `test_plot_roundtrip` unit test creates for
//! mainnet, `index == 0`, `meta_group == 0`:
//! `{std::env::temp_dir()}/pos2_chia_test_k20_i0_g0.plot`
//!
//! If it is missing, the benchmark exits with a short message. Generate the plot first, e.g.:
//! ```text
//! cargo test -p chia-pos2 'test_plot_roundtrip::testnet_1_false::index_1_0u16::meta_group_1_0u8' -- --ignored
//! ```

use std::env;
use std::hint::black_box;
use std::path::Path;
use std::process;

use criterion::{Criterion, criterion_group, criterion_main};

use chia_pos2::{
    Bytes32, PlotQualityChain, Prover, QualityChain, plot_id_for_index, quality_string_from_proof,
    solve_proof, validate_proof_v2,
};

fn default_plot_path() -> std::path::PathBuf {
    env::temp_dir().join("pos2_chia_test_k20_i0_g0.plot")
}

fn exit_missing_plot(path: &Path) -> ! {
    eprintln!(
        "Benchmark plot file not found.\n\
         Expected path: {}\n\
         This file is created by the `test_plot_roundtrip` test in `crates/chia-pos2/src/lib.rs` \
         (mainnet, index=0, meta_group=0).\n\
         Generate it with:\n\
           cargo test -p chia-pos2 --release 'test_plot_roundtrip::testnet_1_false::index_1_0u16::meta_group_1_0u8' -- --ignored\n",
        path.display()
    );
    process::exit(1);
}

struct Fixture {
    prover: Prover,
    plot_group_id: Bytes32,
    plot_index: u16,
    k: u8,
    strength: u8,
    meta_group: u8,
    challenge: Bytes32,
    quality: QualityChain,
    proof: Vec<u8>,
}

fn load_fixture() -> Fixture {
    let path = default_plot_path();
    if !path.exists() {
        exit_missing_plot(&path);
    }
    let prover = Prover::new(&path).unwrap_or_else(|e| {
        eprintln!("Failed to open plot {}: {e}", path.display());
        process::exit(1);
    });
    let plot_group_id = *prover.plot_group_id();
    let k = prover.size();
    let strength = prover.get_strength();
    let meta_group = prover.get_meta_group();

    let mut challenge = [0u8; 32];
    let mut found: Option<(Bytes32, PlotQualityChain)> = None;
    for challenge_idx in 0u32..4096 {
        challenge[0..4].copy_from_slice(&challenge_idx.to_le_bytes());
        let qualities = prover
            .get_qualities_for_challenge(&challenge)
            .expect("get_qualities_for_challenge");
        if let Some(q) = qualities.into_iter().next() {
            found = Some((challenge, q));
            break;
        }
    }
    let (challenge, quality) = found.expect(
        "Fixture plot produced no qualities for challenges 0..4096; delete the plot and regenerate \
         with test_plot_roundtrip.",
    );

    let proof = solve_proof(&quality.chain, &prover.plot_id_for_index(0), k, strength);
    assert!(
        !proof.is_empty(),
        "solve_proof returned an empty proof for the fixture challenge — plot may be corrupt"
    );

    Fixture {
        prover,
        plot_group_id,
        plot_index: 0,
        k,
        strength,
        meta_group,
        challenge,
        quality: quality.chain,
        proof,
    }
}

fn pos2_benchmarks(c: &mut Criterion) {
    let f = load_fixture();

    c.bench_function("get_qualities_for_challenge", |b| {
        b.iter(|| {
            black_box(
                f.prover
                    .get_qualities_for_challenge(black_box(&f.challenge))
                    .unwrap(),
            )
        })
    });

    c.bench_function("solve_proof", |b| {
        b.iter(|| {
            black_box(solve_proof(
                black_box(&f.quality),
                black_box(
                    &plot_id_for_index(&f.plot_group_id, f.plot_index, f.meta_group).unwrap(),
                ),
                f.k,
                f.strength,
            ))
        })
    });

    c.bench_function("validate_proof_v2", |b| {
        b.iter(|| {
            black_box(validate_proof_v2(
                black_box(&f.plot_group_id),
                f.plot_index,
                f.k,
                f.strength,
                f.meta_group,
                black_box(&f.challenge),
                black_box(f.proof.as_slice()),
            ))
        })
    });

    c.bench_function("quality_string_from_proof", |b| {
        b.iter(|| {
            black_box(quality_string_from_proof(
                black_box(
                    &plot_id_for_index(&f.plot_group_id, f.plot_index, f.meta_group).unwrap(),
                ),
                f.k,
                f.strength,
                black_box(f.proof.as_slice()),
            ))
        })
    });
}

criterion_group!(benches, pos2_benchmarks);
criterion_main!(benches);
