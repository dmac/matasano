extern crate serialize;
extern crate openssl;

use std::collections::{HashMap, HashSet};
use serialize::base64::{Config, Standard, ToBase64};
use serialize::hex::{FromHex};

use openssl::crypto::symm;

pub fn hex_to_base64(s: &str) -> String {
    let config = Config{
        char_set: Standard,
        pad: false,
        line_length: None,
    };
    s.from_hex().unwrap().as_slice().to_base64(config)
}

pub fn fixed_xor(b: &[u8], key: &[u8]) -> Vec<u8> {
    assert!(b.len() == key.len());
    let mut result = Vec::new();
    for i in range(0, b.len()) {
        result.push(b[i] ^ key[i]);
    }
    result
}

fn english_score_char_counts(s: &str) -> uint {
    let mut score = 0;
    for c in s.chars() {
        let cl = c.to_lowercase();
        if (cl >= 'a' && cl <= 'z') || cl == ' ' {
            score += 1;
        }
    }
    score
}

fn english_score_char_freq(s: &str) -> uint {
    let mut char_freq: HashMap<char, uint> = HashMap::new();
    for c in s.chars() {
        if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == ' ' {
          char_freq.insert_or_update_with(c.to_lowercase(), 1, |_, count| *count += 1);
        }
    }
    let mut tuples: Vec<(char, uint)> = char_freq.iter().map(|(&k, &v)| (k, v)).collect();
    tuples.sort_by(|&(_, v1), &(_, v2)| v2.cmp(&v1));
    let top_chars: String = tuples.iter().take(6).map(|&(k, _)| k).collect();
    let bot_chars: String = tuples.iter().skip(tuples.len() - 6).map(|&(k, _)| k).collect();
    let mut score = 0u;
    for eng_char in "etaoin ".chars() {
        if top_chars.as_slice().chars().any(|c| eng_char == c) {
            score += 5;
        }
    }
    for eng_char in "shrdlu".chars() {
        if top_chars.as_slice().chars().any(|c| eng_char == c) {
            score += 2;
        }
    }
    for eng_char in "vkjxqz".chars() {
        if bot_chars.as_slice().chars().any(|c| eng_char == c) ||
            char_freq.find(&eng_char).is_none() {
            score += 2;
        }
    }
    score
}

pub fn english_score(s: &str) -> uint {
    english_score_char_counts(s) + english_score_char_freq(s)
}

// Given a ciphertext XOR'd against a single character, returns the key and decrypted plaintext.
pub fn decrypt_single_byte_xor(buf: &[u8]) -> (String, u8, int) {
    let mut best_score = -1;
    let mut best_key = 0u8;
    let mut best_plaintext = String::new();
    for key_char in range(0u8, 255) {
        let key = Vec::from_elem(buf.len(), key_char);
        let plaintext = fixed_xor(buf.as_slice(), key.as_slice());
        match String::from_utf8(plaintext) {
            Ok(plaintext_string) => {
                let score = english_score(plaintext_string.as_slice()) as int;
                if score > best_score {
                    best_score = score;
                    best_key = key_char;
                    best_plaintext = plaintext_string;
                }
            }
            Err(_) => {}
        }
    }
    (best_plaintext, best_key as u8, best_score)
}

pub fn repeating_key_xor(b: &[u8], key: &[u8]) -> Vec<u8> {
    let mut key_buf = Vec::new();
    let mut ki = 0;
    for _ in range(0, b.len()) {
        key_buf.push(key[ki]);
        ki = (ki + 1) % key.len();
    }
    fixed_xor(b, key_buf.as_slice())
}

fn hamming(b1: &[u8], b2: &[u8]) -> uint {
    assert!(b1.len() == b2.len());
    let mut distance = 0;
    for i in range(0, b1.len()) {
        for j in range(0u, 8) {
            if (b1[i] ^ b2[i]) & (1 << j) >= 1 {
                distance += 1
            }
        }
    }
    distance
}

// Given a path to a base64-encoded file encrypted with repeating-key XOR, returns the plaintext
// and key used to encrypt it.
pub fn decrypt_repeating_key_xor(buf: Vec<u8>) -> (String, Vec<u8>) {
    // Determine likely keysize
    let mut keysize = 0u;
    let mut best_hamming = std::uint::MAX as f64;
    for keysize_guess in range(2u, 40) {
        let mut hamming_sum = 0u;
        let mut hamming_count = 0u;
        loop {
            let left1 = hamming_count * keysize_guess;
            let right1 = (hamming_count + 1) * keysize_guess;
            let left2 = right1;
            let right2 = (hamming_count + 2) * keysize_guess;
            if right2 >= buf.len() {
                break;
            }
            hamming_sum += hamming(buf.slice(left1, right1), buf.slice(left2, right2));
            hamming_count += 1;
        }
        let hamming_score = hamming_sum as f64 / hamming_count as f64 / keysize_guess as f64;
        if hamming_score < best_hamming {
            best_hamming = hamming_score;
            keysize = keysize_guess;
        }
    }

    // Break buf into blocks each of length keysize
    let mut blocks: Vec<Vec<u8>> = Vec::new();
    let mut ki = 0u;
    for b in buf.iter() {
        if ki == 0 {
            blocks.push(Vec::new());
        }
        blocks.mut_last().unwrap().push(*b);
        ki += 1;
        if ki == keysize {
            ki = 0;
        }
    }

    // Transpose the blocks
    let mut transposed_blocks: Vec<Vec<u8>> = Vec::new();
    for ki in range(0, keysize) {
        transposed_blocks.push(Vec::new());
    }
    for block in blocks.iter() {
        for i in range(0, block.len()) {
            transposed_blocks.get_mut(i).push(block[i]);
        }
    }

    // Solve for each byte of the key
    let mut key = Vec::<u8>::new();
    for i in range(0, keysize) {
        let (_, c, _) = decrypt_single_byte_xor(transposed_blocks[i].as_slice());
        key.push(c as u8);
    }

    (String::from_utf8(repeating_key_xor(buf.as_slice(), key.as_slice())).unwrap(), key)
}

pub fn decrypt_aes_ecb(buf: &[u8], key: &[u8]) -> Vec<u8> {
    symm::decrypt(symm::AES_128_ECB, key, Vec::new(), buf.as_slice())
}

pub fn detect_aes_ecb<'a>(bufs: &'a [&[u8]]) -> (&'a [u8], int) {
    let mut max_buf: &[u8] = &[];
    let mut max_dups = 0u;
    let mut max_i = -1;
    let num_chunks = 16;

    for (i, buf) in bufs.iter().enumerate() {
        let mut num_dups = 0u;
        let mut dups_set: HashSet<&[u8]> = HashSet::new();
        for chunk in buf.as_slice().chunks(num_chunks) {
            if dups_set.contains_equiv(&chunk) {
                num_dups += 1;
            } else {
                dups_set.insert(chunk);
            }
        }
        if num_dups > max_dups {
            max_dups = num_dups;
            max_buf = buf.as_slice();
            max_i = i as int;
        }
    }

    (max_buf, max_i)
}
