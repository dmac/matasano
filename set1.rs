// Alternate implementation of Set 1 using libraries for serialization.
extern crate serialize;

use std::collections::HashMap;
use serialize::hex::{FromHex, ToHex};
use serialize::base64::{Config, Standard, ToBase64, FromBase64};

use std::io::{BufferedReader, File};

fn hex_to_base64(s: &str) -> String {
    let config = Config{
        char_set: Standard,
        pad: false,
        line_length: None,
    };
    s.from_hex().unwrap().as_slice().to_base64(config)
}

#[test]
fn test_hex_to_base64() {
    assert_eq!("TWFu",
               hex_to_base64("4d616e").as_slice());
    assert_eq!(
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
        hex_to_base64("\
49276d206b696c6c696e6720796f757220627261696e206c\
696b65206120706f69736f6e6f7573206d757368726f6f6d").as_slice());
}

fn fixed_xor(b: &[u8], key: &[u8]) -> Vec<u8> {
    assert!(b.len() == key.len());
    let mut result = Vec::new();
    for i in range(0, b.len()) {
        result.push(b[i] ^ key[i]);
    }
    result
}

#[test]
fn test_fixed_xor() {
    assert_eq!("746865206b696420646f6e277420706c6179",
               fixed_xor("1c0111001f010100061a024b53535009181c".from_hex().unwrap().as_slice(),
                         "686974207468652062756c6c277320657965".from_hex().unwrap().as_slice())
               .as_slice().to_hex().as_slice());
}

fn score_text_naive(s: &str) -> uint {
    let mut score = 0;
    for c in s.chars() {
        if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == ' ' {
            score += 1;
        }
    }
    score
}

fn score_text_char_freq(s: &str) -> uint {
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

fn score_text_char_counts(s: &str) -> uint {
    let mut score = 0;
    for c in s.chars() {
        let cl = c.to_lowercase();
        if (cl >= 'a' && cl <= 'z') || cl == ' ' {
            score += 1;
        }
    }
    score
}

fn score_text_digraph_counts(s: &str) -> uint {
    let mut score = 0;
    let mut digraphs = s.chars().zip(s.chars().skip(1));
    for (c1, c2) in digraphs {
        let c1l = c1.to_lowercase();
        let c2l = c2.to_lowercase();
        let eng_digraphs = ["th", "er", "on", "an", "re", "he", "in", "ed", "nd", "ha", "at", "en", "es",
                            "of", "or", "nt", "ea", "ti", "to", "it", "st", "io", "le", "is", "ou", "ar",
                            "as", "de", "rt", "ve"];
        if eng_digraphs.iter().any(|dg| dg.char_at(0) == c1l && dg.char_at(1) == c2l) {
            score += 1;
        }
    }
    score
}

fn score_text_count_spaces(s: &str) -> uint {
    let mut score = 0;
    let mut trigraphs = s.chars().zip(s.chars().skip(1)).zip(s.chars().skip(2));
    for ((c1, c2), c3) in trigraphs {
        if c2 == ' ' &&
            (c1 >= 'A' && c1 <= 'Z') || (c1 >= 'a' && c1 <= 'z') &&
            (c3 >= 'A' && c3 <= 'Z') || (c3 >= 'a' && c3 <= 'z') {
                score += 1;
            }
    }
    score
}

fn score_text_smart(s: &str) -> uint {
    score_text_char_counts(s) +
        score_text_char_freq(s)
    // score_text_digraph_counts(s)
    // score_text_count_spaces(s)
}

// Given a hex-encoded ciphertext XOR'd against a single character, returns the plaintext, key, and score.
fn single_byte_xor_cipher(buf: &[u8]) -> (String, char, int) {
    let mut best_score = -1;
    let mut best_key = 0u8;
    let mut best_plaintext = String::new();
    for key_char in range(0u8, 255) {
        let key = Vec::from_elem(buf.len(), key_char);
        let plaintext = fixed_xor(buf.as_slice(), key.as_slice());
        match String::from_utf8(plaintext) {
            Ok(plaintext_string) => {
                let score = score_text_smart(plaintext_string.as_slice()) as int;
                if score > best_score {
                    best_score = score;
                    best_key = key_char;
                    best_plaintext = plaintext_string;
                }
            }
            Err(_) => {}
        }
    }
    (best_plaintext, best_key as char, best_score)
}

fn detect_single_character_xor(filename: &str) -> (String, char, int) {
    let mut file = BufferedReader::new(File::open(&Path::new(filename)));
    let lines: Vec<String> = file.lines().map(|x| x.unwrap().as_slice().trim().to_string()).collect();
    let mut best_score = -1i;
    let mut best_key = 'a';
    let mut best_plaintext = String::new();
    for line in lines.iter() {
        let buf = line.as_slice().trim().from_hex().unwrap();
        let (plaintext, key, score) = single_byte_xor_cipher(buf.as_slice());
        if score > best_score {
            best_score = score;
            best_key = key;
            best_plaintext = plaintext.as_slice().trim().to_string();
        }
    }
    (best_plaintext, best_key, best_score)
}

fn repeating_key_xor(b: &[u8], key: &[u8]) -> Vec<u8> {
    let mut key_buf = Vec::new();
    let mut ki = 0;
    for _ in range(0, b.len()) {
        key_buf.push(key[ki]);
        ki = (ki + 1) % key.len();
    }
    fixed_xor(b, key_buf.as_slice())
}

#[test]
fn test_repeating_key_xor() {
    assert_eq!("\
0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272\
a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f",
               repeating_key_xor("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal".as_bytes(),
                                 "ICE".as_bytes()).as_slice().to_hex().as_slice());
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

#[test]
fn test_hamming() {
    assert_eq!(37, hamming("this is a test".as_bytes(), "wokka wokka!!!".as_bytes()));
}

// Given a path to a base64-encoded file encrypted with repeating-key XOR, returns the key used to encrypt
// and the plaintext.
fn decrypt_repeating_key_xor(filename: &str) -> (Vec<u8>, String) {
    // Read file into flat vector of bytes, then base64-decode
    let mut file = File::open(&Path::new(filename)).unwrap();
    let buf = file.read_to_end().unwrap().as_slice().from_base64().unwrap();

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
        let (s, c, _) = single_byte_xor_cipher(transposed_blocks[i].as_slice());
        key.push(c as u8);
    }

    // println!("{}", String::from_utf8(repeating_key_xor(buf.as_slice(), key.as_slice())).unwrap());
    println!("{}", String::from_utf8(key).unwrap());

    (Vec::new(), String::new())
}

fn main() {
    println!("{}", single_byte_xor_cipher("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
                                          .from_hex().unwrap().as_slice()));
    println!("{}", detect_single_character_xor("4.txt"));
    decrypt_repeating_key_xor("6.txt");
}
