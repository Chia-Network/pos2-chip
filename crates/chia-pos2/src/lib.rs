use std::ffi::CString;
use std::fs::File;
use std::io::{Error, ErrorKind, Read, Result};
use std::path::{Path, PathBuf};

mod bits;

pub const NUM_CHAIN_LINKS: usize = 16;

pub const OUTSIDE_FRAGMENT_IS_LR: u8 = 0; // outside t3 index is RL
pub const OUTSIDE_FRAGMENT_IS_RR: u8 = 1; // outside t3 index is RR

#[derive(Clone)]
pub struct PartialProof {
    proof_fragments: [u64; NUM_CHAIN_LINKS * 4],
    strength: u8,
}

impl Default for PartialProof {
    fn default() -> Self {
        Self {
            proof_fragments: [0; 64],
            strength: 0,
        }
    }
}

#[repr(C)]
#[derive(Default, Clone)]
struct Result256 {
    r: [u32; 8],
}

#[repr(C)]
#[derive(Default, Clone)]
struct QualityLink {
    // there are 2 patterns: either LR or RR is included in the fragment, but never both.
    // our 3 proof fragments that form a chain, always in order: LL, LR, RL, RR
    fragments: [u64; 3],
    // Either OUTSIDE_FRAGMENT_IS_LR or OUTSIDE_FRAGMENT_IS_RR
    pattern: u64,
    outside_t3_index: u64,
}

#[repr(C)]
#[derive(Default, Clone)]
/// This object contains a quality proof along with metadata required to look
/// up the remaining proof fragments from the plot, to form a partial proof
pub struct QualityChain {
    chain_links: [QualityLink; NUM_CHAIN_LINKS],
    chain_hash: Result256,
    strength: u8,
}

unsafe extern "C" {
    // these C functions are defined in src/api.cpp

    fn validate_proof(
        plot_id: *const u8,
        k_size: u8,
        strength: u8,
        challenge: *const u8,
        proof_fragment_scan_filter: u8,
        proof: *const u32,
        quality: *mut QualityChain,
    ) -> bool;

    fn qualities_for_challenge(
        plot_file: *const i8,
        challenge: *const u8,
        proof_fragment_scan_filter: u8,
        output: *mut QualityChain,
        num_outputs: u32,
    ) -> u32;

    // proof must point to exactly 64 proof fragments (each a uint64_t)
    // plot ID must point to exactly 32 bytes
    // output must point to exactly 512 32 bit integers
    fn solve_partial_proof(
        partial_proof: *const u64,
        plot_id: *const u8,
        k: u8,
        strength: u8,
        output: *mut u32,
    ) -> bool;

    fn get_partial_proof(
        plot_file: *const i8,
        input: *const QualityChain,
        output: *mut u64,
    ) -> bool;

    fn create_plot(
        filename: *const i8,
        k: u8,
        strength: u8,
        plot_id: *const u8,
        memo: *const u8,
    ) -> bool;
}

pub type Bytes32 = [u8; 32];

pub fn solve_proof(partial_proof: &PartialProof, plot_id: &Bytes32, k: u8) -> Vec<u8> {
    let mut proof = [0_u32; 512];
    // SAFETY: Calling into pos2 C++ library. See src/api.cpp for requirements
    // proof must point to exactly 64 proof fragments (each a uint64_t)
    // plot ID must point to exactly 32 bytes
    // output must point to exactly 512 32-bit integers
    if !unsafe {
        solve_partial_proof(
            partial_proof.proof_fragments.as_ptr(),
            plot_id.as_ptr(),
            k,
            partial_proof.strength,
            proof.as_mut_ptr(),
        )
    } {
        return vec![];
    }

    bits::compact_bits(&proof, k, partial_proof.strength)
}

pub fn validate_proof_v2(
    plot_id: &Bytes32,
    size: u8,
    challenge: &Bytes32,
    required_plot_strength: u8,
    proof_fragment_scan_filter: u8,
    proof: &[u8],
) -> Option<[u8; 385]> {
    let (x_values, strength) = bits::expand_bits(proof, 512, size);

    if x_values.len() != NUM_CHAIN_LINKS * 32 {
        // a full proof has exactly 512 x-values. This is invalid or incomplete
        return None;
    }

    if strength > 255 {
        // strength is supposed to fit in 8 bits
        return None;
    }
    let strength = strength as u8;
    if strength < required_plot_strength {
        // strength is not high enough
        return None;
    }

    let mut quality = QualityChain {
        strength,
        ..Default::default()
    };
    // SAFETY: Calling into pos2 C++ library. See src/api.cpp for requirements
    // plot_id must point to 32 bytes
    // challenge must point to 32 bytes
    // proof must point to 512 uint32_t
    let valid = unsafe {
        validate_proof(
            plot_id.as_ptr(),
            size,
            strength,
            challenge.as_ptr(),
            proof_fragment_scan_filter,
            x_values.as_ptr(),
            &mut quality,
        )
    };
    if valid {
        Some(quality.serialize())
    } else {
        None
    }
}

pub fn create_v2_plot(
    filename: &Path,
    k: u8,
    strength: u8,
    plot_id: &Bytes32,
    memo: &[u8; 32 + 48 + 32],
) -> Result<()> {
    let Some(filename) = filename.to_str() else {
        return Err(Error::new(ErrorKind::Other, "invalid path"));
    };

    let filename = CString::new(filename)?;
    // SAFETY: Calling into pos2 C++ library. See src/api.cpp for requirements
    // filename is the full path, null terminated
    // plot_id must point to 32 bytes of plot ID
    // memo must point to 32 + 48 + 32 bytes, containing the:
    // * pool contract puzzle hash
    // * farmer public key
    // * plot secret key
    // returns true on success
    let success: bool = unsafe {
        create_plot(
            filename.as_ptr(),
            k,
            strength,
            plot_id.as_ptr(),
            memo.as_ptr(),
        )
    };
    if success {
        Ok(())
    } else {
        Err(Error::new(ErrorKind::Other, "failed to create plot file"))
    }
}

impl QualityChain {
    /// out must point to exactly 385 bytes
    /// serializes the QualityProof into the form that will be hashed together with
    /// the challenge to determine the quality of ths proof. The quality is used to
    /// check if it passes the current difficulty. The format is:
    /// 1 byte: plot strength
    /// repeat 16 * 3 times:
    ///   8 bytes: little-endian proof fragment
    pub fn serialize(&self) -> [u8; 385] {
        let mut ret = [0_u8; 385];

        ret[0] = self.strength;
        let mut idx = 1;
        for cl in &self.chain_links {
            for f in &cl.fragments {
                ret[idx..(idx + 8)].clone_from_slice(&f.to_le_bytes());
                idx += 8;
            }
        }
        ret
    }
}

/// Farmer wide state for prover
pub struct Prover {
    path: PathBuf,
    plot_id: Bytes32,
    puzzle_hash: [u8; 32],
    farmer_pk: [u8; 48],
    local_sk: [u8; 32],
    strength: u8,
    size: u8,
}

impl Prover {
    pub fn new(plot_path: &Path) -> Result<Prover> {
        let mut file = File::open(plot_path)?;

        // Read PlotData from a binary file. The v2 plot header format is as
        // follows:
        // 4 bytes:  "pos2"
        // 1 byte:   version. 0=invalid, 1=fat plots, 2=benesh plots (compressed)
        // 32 bytes: plot ID
        // 1 byte:   k-size
        // 1 byte:   strength, defaults to 2
        // 32 bytes: puzzle hash
        // 48 bytes: farmer public key
        // 32 bytes: local secret key
        let mut header = [0_u8; 4 + 1 + 32 + 1 + 1 + 32 + 48 + 32];
        file.read_exact(&mut header)?;

        let mut offset: usize = 0;
        if &header[offset..(offset + 4)] != b"pos2" {
            return Err(Error::new(ErrorKind::Other, "Not a plotfile"));
        }
        offset += 4;
        if header[offset] != 1 {
            return Err(Error::new(ErrorKind::Other, "unsupported plot version"));
        }
        offset += 1;
        let plot_id: [u8; 32] = header[offset..(offset + 32)].try_into().unwrap();
        offset += 32;
        let size = header[offset];
        if !(18..=32).contains(&size) || (size % 2) != 0 {
            return Err(Error::new(ErrorKind::Other, "invalid k-size"));
        }
        offset += 1;

        let strength = header[offset];
        if strength < 2 {
            return Err(Error::new(ErrorKind::Other, "invalid strength"));
        }
        offset += 1;

        let puzzle_hash: [u8; 32] = header[offset..(offset + 32)].try_into().unwrap();
        offset += 32;
        let farmer_pk: [u8; 48] = header[offset..(offset + 48)].try_into().unwrap();
        offset += 48;
        let local_sk: [u8; 32] = header[offset..(offset + 32)].try_into().unwrap();
        //offset += 32;

        Ok(Prover {
            path: plot_path.to_path_buf(),
            plot_id,
            puzzle_hash,
            farmer_pk,
            local_sk,
            strength,
            size,
        })
    }

    pub fn get_qualities_for_challenge(
        &self,
        challenge: &Bytes32,
        proof_fragment_scan_filter: u8,
    ) -> Result<Vec<QualityChain>> {
        let Some(plot_path) = self.path.to_str() else {
            return Err(Error::new(ErrorKind::Other, "invalid path"));
        };

        let plot_path = CString::new(plot_path)?;

        let mut results = Vec::<QualityChain>::with_capacity(10);
        // SAFETY: Calling into pos2 C++ library. See src/api.cpp for requirements
        // find quality proofs for a challenge.
        // challenge must point to 32 bytes
        // plot_file must be a null-terminated string
        // output must point to "num_outputs" objects
        unsafe {
            let num_results = qualities_for_challenge(
                plot_path.as_ptr(),
                challenge.as_ptr(),
                proof_fragment_scan_filter,
                results.as_mut_ptr(),
                10,
            );
            results.set_len(num_results as usize);
        }
        Ok(results)
    }

    pub fn get_partial_proof(&self, quality: &QualityChain) -> Result<PartialProof> {
        let Some(plot_path) = self.path.to_str() else {
            return Err(Error::new(ErrorKind::Other, "invalid path"));
        };

        let plot_path = CString::new(plot_path)?;

        let mut proof_fragments = [0_u64; NUM_CHAIN_LINKS * 4];
        // SAFETY: Calling into pos2 C++ library. See src/api.cpp for requirements
        // turn a quality proof into a partial proof, which can then be solved
        // into a full proof. output must point to exactly 64 uint64 objects.
        // They will all be initialized as the partial proof returns true on
        // success, false on failure
        if unsafe { get_partial_proof(plot_path.as_ptr(), quality, proof_fragments.as_mut_ptr()) } {
            Ok(PartialProof {
                proof_fragments,
                strength: self.strength,
            })
        } else {
            Err(Error::new(ErrorKind::Other, "failed to get partial proof"))
        }
    }

    pub fn size(&self) -> u8 {
        self.size
    }

    pub fn plot_id(&self) -> &Bytes32 {
        &self.plot_id
    }

    pub fn get_strength(&self) -> u8 {
        self.strength
    }

    pub fn get_filename(&self) -> String {
        // This conversion should be safe because the path is constructed from a
        // string
        self.path.to_string_lossy().into_owned()
    }

    pub fn get_memo(&self) -> ([u8; 32], [u8; 48], [u8; 32]) {
        (self.puzzle_hash, self.farmer_pk, self.local_sk)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    fn serialize_quality(
        #[values(1, 0xff00, 0x777777)] step_size: u64,
        #[values(0, 0xffffffff00000000, 0xff00ff00ff00ff00)] fragment_start: u64,
        #[values(
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 23, 26, 28, 33, 63, 64, 100, 200, 240, 255
        )]
        strength: u8,
    ) {
        let mut quality = QualityChain {
            strength,
            ..Default::default()
        };

        let mut idx = fragment_start;
        for link in &mut quality.chain_links {
            for frag in &mut link.fragments {
                *frag = idx;
                idx += step_size;
            }
        }

        let quality_str = quality.serialize();
        assert_eq!(quality_str[0], strength);
        idx = fragment_start;
        for i in (1..(NUM_CHAIN_LINKS * 3 * 8 + 1)).step_by(8) {
            assert_eq!(
                u64::from_le_bytes(quality_str[i..(i + 8)].try_into().unwrap()),
                idx
            );
            idx += step_size;
        }
    }
}
