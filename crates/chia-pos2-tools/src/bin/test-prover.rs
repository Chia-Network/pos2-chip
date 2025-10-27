use chia_pos2::{Prover, create_v2_plot, solve_proof, validate_proof_v2};
use clap::Parser;
use sha2::{Digest, Sha256};
use std::fs::exists;
use std::path::Path;

/// Exercise getting qualities from v2 plots
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// The challenge seed
    #[arg(short, long, default_value_t = 0)]
    seed: u64,

    /// The seed for the test plot-file
    #[arg(short, long, default_value_t = 1337)]
    plot_seed: u64,

    /// Disable solving and validating proofs
    #[arg(long, default_value_t = false)]
    disable_solving: bool,
}

fn main() {
    let args = Args::parse();

    let plot_id: [u8; 32] = Sha256::digest(args.plot_seed.to_be_bytes()).into();

    let k = 18;
    let plot_filename = format!("k-18-test-{}.plot2", hex::encode(plot_id));
    let plot_filename = Path::new(&plot_filename);
    if !exists(plot_filename).expect("exists failed") {
        println!("generating plot: {}", plot_filename.display());
        create_v2_plot(plot_filename, k, 2, &plot_id, &[32; 64 + 48]).expect("create_v2_plot");
    }

    let mut seed = args.seed;

    let prover = Prover::new(plot_filename).expect("failed to create prover");

    loop {
        if (seed & 0x1ff) == 0 {
            println!("seed={seed}");
        }
        let challenge: [u8; 32] = Sha256::digest(seed.to_be_bytes()).into();
        let qualities = prover
            .get_qualities_for_challenge(&challenge, 4)
            .expect("get_qualities_for_challenge");

        if qualities.len() > 1 {
            println!("found {} qualities", qualities.len());
        }
        for q in qualities {
            // We pretend the qualities pass just to exercise more partial
            // proofs
            let partial_proof = prover.get_partial_proof(&q).expect("get_partial_proofs");
            if !args.disable_solving {
                let full_proof = solve_proof(&partial_proof, &plot_id, k);

                assert!(validate_proof_v2(&plot_id, k, &challenge, 2, 4, &full_proof).is_some());
            }
        }
        seed += 1;
    }
}
