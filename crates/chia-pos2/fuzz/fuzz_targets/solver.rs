#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use chia_pos2::{Bytes32, QualityChain, solve_proof};
use libfuzzer_sys::{Corpus, fuzz_target};

fuzz_target!(|data: &[u8]| -> Corpus {
    let mut unstructured = Unstructured::new(data);

    let Ok(k_size) = unstructured.int_in_range::<u8>(12..=32) else {
        return Corpus::Reject;
    };
    let Ok(strength) = unstructured.int_in_range::<u8>(2..=64) else {
        return Corpus::Reject;
    };
    let Ok(plot_id) = Bytes32::arbitrary(&mut unstructured) else {
        return Corpus::Reject;
    };
    let Ok(quality) = QualityChain::arbitrary(&mut unstructured) else {
        return Corpus::Reject;
    };
    let _ = solve_proof(&quality, &plot_id, k_size, strength);
    Corpus::Keep
});
