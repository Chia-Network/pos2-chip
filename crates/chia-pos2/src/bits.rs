// returns the compacted buffer
pub(crate) fn compact_bits(x_values: &[u32], k: u8) -> Vec<u8> {
    // each u32 is only using k-bits. pack them to make the proof smaller

    // when k is smaller than 8, the padding bits at the end can be interpreted
    // as a compacted value. Since our plot k-values are always greater than 8,
    // just keep things simple by disallowing k < 8 in this function
    assert!(k >= 8);

    let mut full_proof = Vec::<u8>::with_capacity((x_values.len() * usize::from(k)).div_ceil(8));

    let mut val = 0_u8;
    let mut bits_left = 8;
    for x in x_values {
        let mut mask = ((1_u64 << k) - 1) as u32;
        let mut x_bits = k;
        // we don't expect any other bits to be set
        assert!((x | mask) == mask);

        while x_bits > 0 {
            let bits_to_copy = std::cmp::min(bits_left, x_bits);

            if x_bits > bits_left {
                val |= ((x & mask) >> (x_bits - bits_left)) as u8;
            } else {
                val |= ((x & mask) << (bits_left - x_bits)) as u8;
            }

            mask >>= bits_to_copy;
            bits_left -= bits_to_copy;
            x_bits -= bits_to_copy;

            if bits_left == 0 {
                full_proof.push(val);
                val = 0;
                bits_left = 8;
            }
        }
    }
    if bits_left < 8 {
        full_proof.push(val);
    }
    full_proof
}

/// extracts all k-size values from the proof buffer and returns them as a
/// vector of u32
pub(crate) fn expand_bits(proof: &[u8], k: u8) -> Option<Vec<u32>> {
    let mut x_values = Vec::<u32>::with_capacity(proof.len() * 8 / usize::from(k));

    let mut val = 0_u32;
    let mut bits_left = k;
    for byte in proof {
        let mut byte_bits = 8;
        let mut byte_mask = 0xff_u8;

        while byte_bits > 0 {
            if bits_left > byte_bits {
                val |= u32::from(byte & byte_mask) << (bits_left - byte_bits);
            } else {
                val |= u32::from(byte & byte_mask) >> (byte_bits - bits_left);
            }
            let bits_copied = std::cmp::min(byte_bits, bits_left);
            bits_left -= bits_copied;
            byte_bits -= bits_copied;
            if byte_bits > 0 {
                byte_mask >>= bits_copied;
            }
            if bits_left == 0 {
                x_values.push(val);
                bits_left = k;
                val = 0;
            }
        }
    }

    if val != 0 { None } else { Some(x_values) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn print_bits(input: &[u8]) -> String {
        let mut ret = String::new();
        for b in input {
            ret += format!("{b:08b}").as_str();
        }
        ret
    }

    #[rstest]
    fn compact_bits_fields(
        #[values(8, 9, 10, 11, 12, 13, 14, 15, 16, 18, 19, 20, 28, 29, 30, 31, 32)] num_bits: u8,
        #[values(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10)] field: u32,
        #[values(false, true)] tail: bool,
    ) {
        // make sure each field is confined to exactly "num_bits" bits
        let mask: u32 = 0xffffffff >> (32 - num_bits);
        let mut input = [0_u32; 11];
        input[field as usize] = mask;

        let zero = "0".repeat(num_bits.into());
        let one = "1".repeat(num_bits.into());

        let mut expect = String::new();
        for i in 0..11 {
            if i == field {
                expect += &one;
            } else {
                expect += &zero;
            }
        }
        let padding = expect.len() % 8;
        let padding = if padding == 0 { padding } else { 8 - padding };

        expect += &(if tail { "1" } else { "0" }).repeat(padding);

        let mut bits = compact_bits(&input, num_bits);
        if padding > 0 && tail {
            *bits.last_mut().unwrap() |= 0xff >> (8 - padding);
        }

        assert_eq!(expect.len() % 8, 0);
        assert_eq!(print_bits(bits.as_slice()), expect);

        if padding > 0 && tail {
            if let Some(round_trip) = expand_bits(bits.as_slice(), num_bits) {
                assert!(round_trip.len() > input.len());
            }
        } else {
            let round_trip = expand_bits(bits.as_slice(), num_bits).expect("expand_bits");
            assert_eq!(round_trip, input);
        }
    }

    #[rstest]
    fn compact_bits_values(#[values(8, 9, 10, 11, 12, 13, 14, 15)] num_bits: u8) {
        // make sure the values are preserved
        let mask: u32 = 0xffffffff >> (32 - num_bits);
        let mut input = [0_u32; 11];

        let mut expect = String::new();
        for (idx, ref mut v) in &mut input.iter_mut().enumerate() {
            **v = idx as u32 & mask;
            let bits = format!("{:0width$b}", idx as u32 & mask, width = num_bits as usize);
            expect += bits.as_str();
        }

        let padding = expect.len() % 8;
        let padding = if padding == 0 { padding } else { 8 - padding };
        expect += &"0".repeat(padding);

        let result = compact_bits(&input, num_bits);
        assert_eq!(print_bits(result.as_slice()), expect);

        let round_trip = expand_bits(result.as_slice(), num_bits).expect("expand_bits");
        assert_eq!(round_trip, input);
    }
}
