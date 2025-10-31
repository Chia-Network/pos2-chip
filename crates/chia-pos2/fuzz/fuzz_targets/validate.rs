#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use chia_pos2::{Bytes32, validate_proof_v2};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);

    let Ok(plot_id) = Bytes32::arbitrary(&mut unstructured) else {
        return;
    };
    let Ok(k_size) = unstructured.int_in_range::<u8>(12..=32) else {
        return;
    };
    let Ok(challenge) = Bytes32::arbitrary(&mut unstructured) else {
        return;
    };
    let Ok(strength) = unstructured.int_in_range::<u8>(2..=64) else {
        return;
    };
    let Ok(proof_fragment_scan_filter) = u8::arbitrary(&mut unstructured) else {
        return;
    };
    let Ok(proof) = Vec::<u8>::arbitrary(&mut unstructured) else {
        return;
    };

    let _ = validate_proof_v2(
        &plot_id,
        k_size,
        &challenge,
        strength,
        proof_fragment_scan_filter,
        &proof,
    );
});
