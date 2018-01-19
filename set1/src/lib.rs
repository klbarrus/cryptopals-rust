extern crate crypto;

use std::error::Error;
use std::collections::HashSet;
use std::fs::File;
use std::io::Read;
use std::io::BufRead;
use std::io::BufReader;
use std::str;

use crypto::{ symmetriccipher, buffer, aes, blockmodes };
use crypto::buffer::{ ReadBuffer, WriteBuffer, BufferResult };

const BASE64: [char; 64] = [
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
    'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
    'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
    'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 
    'w', 'x', 'y', 'z', '0', '1', '2', '3',
    '4', '5', '6', '7', '8', '9', '+', '/'
];

pub struct Config {
//    pub string_1: String,
//    pub string_2: String
}

impl Config {
    pub fn new(args: &[String]) -> Result<Config, &'static str> {
//        if args.len() < 2 {
//            return Err("Not enough arguments");
//        }

//        let string_1 = args[1].clone();
//        let string_2 = args[2].clone();

        Ok(Config {
//            string_1: string_1,
//            string_2: string_2
        })
    }
}

pub fn run(config: Config) -> Result<(), Box<Error>> {

    // challenge 1 - convert hex to base64
    {
        let input = String::from("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
        let output = to_base64(input);

        println!("Challenge 1");
        println!("{}", output);
        println!("");
    
    }

    // challenge 2 - fixed XOR
    {
        let input_1 = String::from("1c0111001f010100061a024b53535009181c");
        let input_2 = String::from("686974207468652062756c6c277320657965");
        let msg_1 = hex_decode(input_1);
        let msg_2 = hex_decode(input_2);
        let output = fixed_xor(&msg_1, &msg_2);

        println!("Challenge 2");
        println!("{}", hex_encode(output));
        println!("");
    }

    let common_letters = setup_common_letter_table();
 
    {
     
        // challenge 3 - single-byte XOR cipher
        {
            let encrypted_message = String::from("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
            let e_msg = hex_byte_decode(encrypted_message);

            let (max, key, msg) = score_xor_decryption_loop(&e_msg, &common_letters);
    
            println!("Challenge 3");
            println!("max score {} using key {}", max, key);
            println!("{}", msg);
            println!("");    
        }

        // challenge 4 - detect single-character XOR
        {
            let f = File::open("4.txt").unwrap();
            let file = BufReader::new(&f);
    
            let mut d_max: u32 = 0;
            let mut d_key: u8 = 0;
            let mut d_msg: String = String::from("");
    
            for line in file.lines() {
                let e_line = hex_byte_decode(line.unwrap()); 
                let (line_max, line_key, line_msg) = score_xor_decryption_loop(&e_line, &common_letters);

                if line_max > d_max {
                    d_max = line_max;
                    d_key = line_key;
                    d_msg = line_msg;
                }        
            }
    
            println!("Challenge 4");
            println!("max score {} using key {}", d_max, d_key);
            println!("{}", d_msg);
//            println!("");
        }
    }

    // challenge 5 - repeating-key XOR
    {
        let msg = String::from("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal").into_bytes();
        let key = String::from("ICE").into_bytes();
        let output = repeating_key_xor(&msg, &key);

        println!("Challenge 5");
        println!("{}", to_hex_string(output));
        println!("");
    }

    // challenge 6 - break repeating-key XOR
    {
//        let msg_1 = String::from("this is a test").into_bytes();
//        let msg_2 = String::from("wokka wokka!!!").into_bytes();
//        let msg_1 = String::from("?").into_bytes();
//        let msg_2 = String::from("A").into_bytes();
//        let hd = hamming_distance(&msg_1, &msg_2);
//        println!("hamming distance: {}", hd);

        let f = File::open("6.txt").unwrap();
        let file = BufReader::new(&f);
        let mut file_contents_vec: Vec<String> = vec!["".to_string()];

        for line in file.lines() {
            file_contents_vec.push(line.unwrap());
        }
        let file_contents = file_contents_vec.join("");
//        println!("file bytes");
//        println!("{} {:?}", file_contents.len(), file_contents);
//        println!("");

        let expanded_bytes = from_base64(&file_contents.into_bytes());
//        println!("from base64");
//        println!("{} {:?}", expanded_bytes.len(), expanded_bytes);
//        println!("");
    
        // find keysize corresponding to minimum hamming distance 

        let mut min_hamm_d = 100.0;
        let mut min_keysize = 0;

        for trial_keysize in 2..41 {
            // compare 50 chunks of test (1st and 2nd trial_keysize chunks, 2nd and 3rd, etc.)
            let mut hamm_d_cumulative = 0;
            for chunk in 0..51 {
                let chunk_1: Vec<_> = expanded_bytes.iter().cloned().skip(trial_keysize * chunk).take(trial_keysize).collect();
                let chunk_2: Vec<_> = expanded_bytes.iter().cloned().skip(trial_keysize * (chunk + 1)).take(trial_keysize).collect();
//                println!("chunk 1");
//                println!("{:?}", chunk_1);
//                println!("chunk 2");
//                println!("{:?}", chunk_2);
                let hamm_d = hamming_distance(&chunk_1, &chunk_2);
                hamm_d_cumulative += hamm_d;
            }
            // normalize the hamming distance (factor of 50 from the number of chunks)
            let norm_hamm_d = (hamm_d_cumulative as f32) / (50.0 * trial_keysize as f32);
//            println!("key size {}, normalized hamming distance {}", trial_keysize, norm_hamm_d);

            if norm_hamm_d < min_hamm_d {
                min_hamm_d = norm_hamm_d;
                min_keysize = trial_keysize;
            }
        }
        let keysize = min_keysize;

        // treat each keysize'th step as a block of single-byte XOR cipher
        // (cryptopals step 6)
        // solve for the decryption key one byte at a time

        let mut decrypt_key: Vec<u8> = Vec::new();

//        for i in 2..41 {
            for index in 0..keysize {
                let block = get_nth_step(&expanded_bytes, index, keysize);
                let (max, key, msg) = score_xor_decryption_loop(&block, &common_letters);
    
//                println!("step {}, key {}", index, key);
//                println!("{:?}", block);
//                println!("");
    //            println!("{}", msg);
                decrypt_key.push(key);
            }

//            println!("keysize {}, {:?}", min_keysize, hex_byte_encode(decrypt_key.clone()));
//            decrypt_key.clear();
//        }

        let output = repeating_key_xor(&expanded_bytes, &decrypt_key);
//
        println!("Challenge 6");
        println!("key size {}, normalized hamming distance {}", min_keysize, min_hamm_d);
        println!("decryption key: {}", hex_byte_encode(decrypt_key));
        println!("{}", hex_byte_encode(output));
        println!("");
    }

    // challenge 7 - AES in ECB mode
    {
        let f = File::open("7.txt").unwrap();
        let file = BufReader::new(&f);
        let mut file_contents_vec: Vec<String> = vec!["".to_string()];

        for line in file.lines() {
            file_contents_vec.push(line.unwrap());
        }
        let file_contents = file_contents_vec.join("");
        let expanded_bytes = from_base64(&file_contents.into_bytes());

        let key = String::from("YELLOW SUBMARINE").into_bytes();

//        println!("key: {:?}", key);
//        println!("{:?}", expanded_bytes);

        let decrypted_data = aes_ecb_decrypt(&expanded_bytes[..], &key).ok().unwrap();

        println!("Challenge 7");
        println!("{}", hex_byte_encode(decrypted_data));
    }

    // challenge 8 - detect AES in ECB mode
    {
        let f = File::open("8.txt").unwrap();
        let file = BufReader::new(&f);
//        let mut file_contents_vec: Vec<String> = vec!["".to_string()];

        // since ECB is stateless and deterministic (cryptopals hint) and the same 16 byte plaintext will result in the same 16 byte ciphertext
        // then a repeat in the plaintext will result in a repeat in the ciphertext
        // search each string for an repeats of a 16 byte slice

        let mut ecb_line = String::from("");
        let mut slice_repeat = String::from("");
        let mut index_1 = 0;
        let mut index_2 = 0;

        for line in file.lines() {
            let ciphertext = line.unwrap();
//            println!("line:");
//            println!("{}", ciphertext);
//            println!("");
            let len = ciphertext.len();
            let mut i = 0;

            while i < len - 16 + 1 {
                let slice_16 = &ciphertext[i..i+16];
                let rest_of_line = &ciphertext[i+1..];
//                println!("{:?}", slice_16);

                match rest_of_line.find(slice_16) {
                    Some(x) => {
                        ecb_line = ciphertext.clone();
                        slice_repeat = slice_16.to_string();
                        index_1 = i;
                        index_2 = x;
//                        println!("match found!");
//                        println!("{:?} at index {} and {}", slice_16, i, x);
                        break;
                    },
                    None    => ()

                };

                i += 1;
            }
        }

        println!("Challenge 8");
        println!("AES in ECB mode detected in line:");
        println!("{}", ecb_line);
        println!("Block {} repeated at index {} and {}", slice_repeat, index_1, index_2);
    }

    Ok(())
}

// challenge 2
pub fn fixed_xor(vec_1: &Vec<u8>, vec_2: &Vec<u8>) -> Vec<u8> {
    let both_vecs = vec_1.iter().zip(vec_2.iter());
    let output: Vec<u8> = both_vecs.map(|(x,y)| x ^ y).collect();

    output
}

// challenge 3 and 4
pub fn single_byte_xor(msg: &Vec<u8>, key: u8) -> Vec<u8> {
    let output = msg.iter().map(|x| x ^ key).collect();

    output
}

// challenge 3 and 4
pub fn score_xor_decryption(e_msg: &Vec<u8>, key: u8, common_letters: &HashSet<u8>) -> (u32, Vec<u8>) {
//    let mut score: u32 = 0;

    let d_msg = single_byte_xor(&e_msg, key);
    let score = score_letter_freq(&d_msg, &common_letters);

    (score, d_msg)
}

// challenge 3 and 4
// try all single-byte keys and return the overall highest score, key, decrypted message
pub fn score_xor_decryption_loop(e_msg: &Vec<u8>, common_letters: &HashSet<u8>) -> (u32, u8, String) {
    let mut d_max: u32 = 0;
    let mut d_key: u8 = 0;
    let mut d_msg: String = String::from("");

    for key in 0x00..0xFF {
        let (score, output) = score_xor_decryption(&e_msg, key as u8, &common_letters);

        if score > d_max {
            d_max = score;
            d_key = key as u8;
            d_msg = hex_byte_encode(output);
        }
    }

    (d_max, d_key, d_msg)
}

// challenge 5
pub fn repeating_key_xor(msg: &Vec<u8>, key: &Vec<u8>) -> Vec<u8> {
    let both_vecs = msg.iter().zip(key.iter().cycle());
//    let output: String = both_vecs.map(|(x,y)| x ^ y).map(|x| format!("{:02x}", x)).collect();
    let output: Vec<u8> = both_vecs.map(|(x,y)| x ^ y).collect();

    output
}

// challenge 6
pub fn hamming_distance(vec_1: &Vec<u8>, vec_2: &Vec<u8>) -> u32 {
    let both_vecs = vec_1.iter().zip(vec_2.iter());
    let hd: u32 = both_vecs.map(|(x,y)| x ^ y).map(|x| x.count_ones()).sum();

    hd
}

// challenge 6
pub fn get_nth_step(input: &Vec<u8>, index: usize, keysize: usize) -> Vec<u8> {
    let mut output: Vec<u8> = Vec::new();
    let len = input.len();
    let mut i = index;

    while i < len {
        let val = input.get(i).unwrap();
        output.push(*val);
        i += keysize;
    }

    output
}

// challenge 7
fn aes_ecb_decrypt(encrypted_data: &[u8], key: &[u8]) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    let mut decryptor = aes::ecb_decryptor(
            aes::KeySize::KeySize128,
            key,
            blockmodes::PkcsPadding
        );

    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(encrypted_data);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = try!(decryptor.decrypt(&mut read_buffer, &mut write_buffer, true));
        final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => { }
        }
    }

    Ok(final_result)
}

pub fn to_hex_string(vec: Vec<u8>) -> String {
    let output = vec.iter().map(|x| format!("{:02x}", x)).collect();

    output
}

// count the most common English letters (ETAOINRSHDLU) 
pub fn score_letter_freq(input: &Vec<u8>, common_letters: &HashSet<u8>) -> u32 {
    let mut score = 0;

    for ch in input.iter() {
        // frequent chars score 10 points, 9 now and 1 later
        if common_letters.contains(ch) {
            score += 9;
        }

        // A-Z scores 1 point
        if ch >= &41u8 && ch <= &90u8 {
            score += 1;
        }

        // a-z score 1 point
        if ch >= &97u8 && ch <= &122u8 {
            score += 1;
        }

        // CTRL chars and extended chars cause overall score to be 0
//        if *ch < 32u8 || *ch >= 127u8 {
//        if *ch >= 127u8 {
//            score = 0;
//            break;
//        }
    }

    score
}

pub fn hex_to_string(input: Vec<u8>) -> String {
    let output = input.iter().map(|b| format!("{:02x}", b)).collect();

    output
}

pub fn hex_decode(input: String) -> Vec<u8> {
    let output = input.into_bytes().iter().map(|&x| hex_char_to_digit(x)).collect();

    output
}

pub fn hex_encode(input: Vec<u8>) -> String {
    let output = input.iter().map(|&x| digit_to_hex_char(x)).collect();

    output
}

pub fn hex_byte_decode(input: String) -> Vec<u8> {
    let mut output: Vec<u8> = Vec::new();
    let input_bytes: Vec<u8> = input.into_bytes();
    let mut i: usize = 0;
    let len = input_bytes.len();

    while i < len {
        let d1 = input_bytes[i];
        let d2 = input_bytes[i+1];
        let hex_byte = hex_char_to_digit(d1)*16 + hex_char_to_digit(d2);
        output.push(hex_byte);
        i += 2
    }

    output
}

pub fn hex_byte_encode(input: Vec<u8>) -> String {
//    let output = String::from_utf8(input).unwrap();
    let output = input.iter().map(|&x| x as char).collect();

    output
}

pub fn hex_char_to_digit(ch: u8) -> u8 {
    let num = match ch {
        b'0'...b'9' => ch - b'0',
        b'a'...b'f' => ch - b'a' + 10,
        b'A'...b'F' => ch - b'A' + 10,
        b'\0'       => 0,
        _           => 0
    };

    num
}

pub fn digit_to_hex_char(num: u8) -> char {
    let digit = match num {
        0...9   => (num + b'0') as char,
        10...15 => (num - 10 + b'a') as char,
        _       => '?'
    };

    digit
}

// challenge 1
pub fn to_base64(input: String) -> String {
    let input_vec = hex_decode(input);
    let padded_input = pad(&input_vec.clone(), 3);
    let output: String = padded_input.chunks(3).map(|x| bits_to_base64(x)).map(|(x,y)| base64_lookup(x,y)).collect();

    output
}

// challenge 1
pub fn bits_to_base64(x: &[u8]) -> (u8, u8) {
    let i0 = x[0];
    let i1 = x[1];
    let i2 = x[2];

    let (a, b) = 
        (
            ((i0 as u8) << 2) + (((i1 & 0xC) as u8) >> 2),
            ((i1 & 0x3) << 4) + i2
        );

    (a, b)
}

// challenge 1
pub fn base64_lookup(x: u8, y: u8) -> String {
    let mut output = String::from("");

    output.push(BASE64[x as usize]);
    output.push(BASE64[y as usize]);

    output
}

// challenge 6
pub fn from_base64(input: &Vec<u8>) -> Vec<u8> {
    let padded_input = pad(&input.clone(), 4);
    let output: Vec<_> = padded_input.chunks(4).flat_map(|x| base64_to_bits(x)).collect();

//    println!("{:?}", output);

    output
}

// challenge 6
pub fn base64_to_bits(x: &[u8]) -> Vec<u8> {
    let mut output: Vec<u8> = Vec::new();

    let i0 = to_base64_index(x[0]);
    let i1 = to_base64_index(x[1]);
    let i2 = to_base64_index(x[2]);
    let i3 = to_base64_index(x[3]);

    let (a, b, c) =
    (
        ((i0 as u8) << 2) + (((i1 & 0x30) as u8) >> 4),
        (((i1 & 0xF) as u8) << 4) + (((i2 & 0x3F) as u8) >> 2),
        (((i2 & 0x3) as u8) << 6) + i3
    );

//    println!("{} {} {} {} -> {:2x} {:2x} {:2x}", i1, i2, i3, i4, a, b, c);

    output.push(a);
    output.push(b);
    output.push(c);

    output
}

// challenge 6
// contants taken from base64 index table
pub fn to_base64_index(x: u8) -> u8 {
    let num = match x {
        b'0'...b'9' => x - b'0' + 52,
        b'A'...b'Z' => x - b'A',
        b'a'...b'z' => x - b'a' + 26,
        b'+' => 62,
        b'/' => 63,
        _    => 0
    };

    num
}

// return a vector padded to a length that is a multiple of mult
pub fn pad(input: &Vec<u8>, padding: usize) -> Vec<u8> {
    let mut output = input.clone();
    let len = input.len();

    if len % padding != 0 {
        let num = padding - (len % padding);
        for _ in 0..num {
            output.push(0);
        }
    }

    output
}

// challenge 1
//   note: assumes padding length of a multiple of 3
//pub fn to_base64(input: Vec<u8>) -> String {
//    let mut output = String::from("");
//    let mut i: usize = 0;
//    let len = input.len();
//
//    while i < len {
//        let b1 = input[i];
//        let b2 = input[i+1];
//        let b3 = input[i+2];
//
//        let (out_1, out_2) =
//            (
//                ((b1 as u8) << 2) + (((b2 & 0xC) as u8) >> 2),
//                ((b2 & 0x3) << 4) + b3
//            );
//
//        output.push(BASE64[out_1 as usize]);
//        output.push(BASE64[out_2 as usize]);
//
//        i += 3
//    };
//
//    output
//}

// pad to a multiple of 6 bytes 
// base64 encoding encodes 3 bytes to 4 bytes
// we expect pairs of hex digits as input so 3 hex digits are 6 bytes
//pub fn pad(mut input: String) -> String {
//    let len = input.len();
//
//    if len % 6 != 0 {
//        let pad = 6 - (len % 6);
//
//        for _ in 0..pad {
//            input.push('\0');
//        }
//    }
//
//    input    
//}

pub fn setup_common_letter_table() -> HashSet<u8> {
    let mut common_letters = HashSet::new();

    common_letters.insert(b'E');
    common_letters.insert(b'e');
    common_letters.insert(b'T');
    common_letters.insert(b't');
    common_letters.insert(b'A');
    common_letters.insert(b'a');
    common_letters.insert(b'O');
    common_letters.insert(b'o');
    common_letters.insert(b'I');
    common_letters.insert(b'i');
    common_letters.insert(b'N');
    common_letters.insert(b'n');
    common_letters.insert(b'R');
    common_letters.insert(b'r');
    common_letters.insert(b'S');
    common_letters.insert(b's');
    common_letters.insert(b'H');
    common_letters.insert(b'h');
    common_letters.insert(b'D');
    common_letters.insert(b'd');
    common_letters.insert(b'L');
    common_letters.insert(b'l');
    common_letters.insert(b'U');
    common_letters.insert(b'u');
    common_letters.insert(b' ');

    common_letters
}