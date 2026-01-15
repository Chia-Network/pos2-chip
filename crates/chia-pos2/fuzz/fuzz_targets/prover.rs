#![no_main]

use chia_pos2::validate_proof_v2;
use chia_pos2::{Bytes32, Prover, create_v2_plot, serialize_quality, solve_proof};
use libfuzzer_sys::fuzz_target;
use std::fs::exists;
use std::path::Path;
use std::sync::OnceLock;

static PLOTS: OnceLock<Vec<Prover>> = OnceLock::new();

fn create_test_plots() {
    let mut p = Vec::<Prover>::with_capacity(10);
    for i in 0..10 {
        let filename = format!("fuzzing-plot-{i}.plot2");
        let path = Path::new(&filename);
        if !exists(path).expect("exists") {
            let strength = 2 + i % 3;
            let k = 18;
            let index = 0;
            let meta_group = 0;
            let plot_id: Vec<u8> = std::iter::repeat_n(i, 32).collect();
            let memo = [0_u8; 112];
            create_v2_plot(
                path,
                k,
                strength,
                &plot_id.try_into().unwrap(),
                index,
                meta_group,
                &memo,
            )
            .expect("create_v2_plot()");
        }
        p.push(Prover::new(path).expect("Prover::new()"));
    }

    let _ = PLOTS.set(p);
}

fuzz_target!(init: { create_test_plots(); }, |challenge: Bytes32| {

    for plot in PLOTS.get().unwrap() {
        let qualities = plot.get_qualities_for_challenge(&challenge).expect("get_qualities_for_challenge()");

        let strength = plot.get_strength();
        let plot_id = plot.plot_id();
        let k = plot.size();
        for quality in qualities {
            let _ = serialize_quality(&quality.chain_links, strength);
            let proof = solve_proof(&quality, plot_id, k, strength);
            assert!(validate_proof_v2(plot_id, k, &challenge, strength, &proof).is_some());
        }
    }
});
