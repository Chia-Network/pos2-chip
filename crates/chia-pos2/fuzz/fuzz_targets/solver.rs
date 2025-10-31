#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use chia_pos2::{Bytes32, PartialProof, solve_proof};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);

    let Ok(k_size) = unstructured.int_in_range::<u8>(12..=32) else {
        return;
    };
    let Ok(plot_id) = Bytes32::arbitrary(&mut unstructured) else {
        return;
    };
    let Ok(partial_proof) = PartialProof::arbitrary(&mut unstructured) else {
        return;
    };
    let _ = solve_proof(&partial_proof, &plot_id, k_size);
});
