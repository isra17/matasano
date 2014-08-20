extern crate serialize;
use serialize::hex::{FromHex, ToHex};
use serialize::base64::{ToBase64, STANDARD};
use std::io::BufferedReader;
use std::io::File;
use std::iter::AdditiveIterator;

static LETTER_FREQUENCY: &'static [f32] = & [0.0855, 0.0160, 0.0316, 0.0387, 0.1210, 0.0218, 0.0209, 0.0496, 0.0733, 0.0022, 0.0081, 0.0421, 0.0253, 0.0717, 0.0747, 0.0207, 0.0010, 0.0633, 0.0673, 0.0894, 0.0268, 0.0106, 0.0183, 0.0019, 0.0172, 0.0011];

#[deriving(Clone)]
struct ByteAnalysisResult {
    key : u8,
    score : f32,
    message : Vec<u8>
}


fn hex_to_base64(hex : &str) -> String {
    let config = STANDARD;
    hex.from_hex().unwrap().as_slice().to_base64(config)
}

fn xor(v1 : &[u8], v2 : &[u8]) -> Vec<u8> {
    v1.iter().zip(v2.iter()).map(|(b1, b2)| *b1 ^ *b2).collect::<Vec<u8>>()
}

fn byte_decrypt(c : &[u8], k : u8) -> Vec<u8> {
    c.iter().map(|b| b ^ k).collect::<Vec<u8>>()
}

fn score_message(m : &[u8]) -> f32 {
    if m.iter().any(|&x|(x<32u8||x>126u8) && x != 10) {
        return -10e10;
    }
    let mut letter_count : [uint, ..26] = [0, ..26];
    let mut m_iter = m.iter().filter_map(|&b| {
        match b {
            65..90 => Some(b-65),
            97..122 => Some(b-97),
            _ => None
        }
    });
    for b in m_iter {
        letter_count[b as uint] += 1;
    }
    let len : uint = letter_count.iter().map(|&x|x).sum();
    let message_freq = letter_count.iter().map(|&f| f as f32/len as f32);
    -message_freq.zip(LETTER_FREQUENCY.iter()).fold(0f32, |score, (m_freq, english_freq)| {
        score + std::num::abs(english_freq - m_freq)
    })
}

fn print_message(m : Vec<u8>) {
    let m_str = String::from_utf8(m);
    match m_str {
        Ok(s) => println!("Message: {}", s),
        _ => ()
    }
}

fn best_key(c : &[u8]) -> ByteAnalysisResult {
    let mut best_message : Vec<u8> = vec!();
    let mut best_message_score = -10e10f32;
    let mut key = 0;
    for k in std::iter::range_inclusive(0, 255) {
        let message = byte_decrypt(c, k);
        let message_score = score_message(message.as_slice());
        if message_score > best_message_score {
            best_message = message;
            best_message_score = message_score;
            key = k;
        }
    }

    ByteAnalysisResult { key: key, score: best_message_score, message: best_message }
}

fn best_message(clist : &[Vec<u8>]) -> ByteAnalysisResult {
    let mut analysis_list = clist.iter()
        .map(|c| best_key(c.as_slice()))
        .collect::<Vec<ByteAnalysisResult>>();
    analysis_list.sort_by(|a,b| b.score.partial_cmp(&a.score).unwrap_or(Equal));
    analysis_list[0].clone()
}

fn block_encrypt(k : &[u8], m : &[u8]) -> Vec<u8> {
    range(0, m.len()).zip(m.iter()).map(|(i,b)| b ^ k[i%k.len()]).collect()
}

fn ch1() {
    println!("------- 1 ---------");
    let hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let base64 = hex_to_base64(hex);
    assert!("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t" == base64.as_slice());
}

fn ch2() {
    println!("------- 2 ---------");
    let v1 = "1c0111001f010100061a024b53535009181c".from_hex().unwrap();
    let v2 = "686974207468652062756c6c277320657965".from_hex().unwrap();
    let xor_vec = xor(v1.as_slice(), v2.as_slice());
    println!("{}", xor_vec);
    assert!("746865206b696420646f6e277420706c6179" == xor_vec.as_slice().to_hex().as_slice());
}

fn ch3() {
    println!("------- 3 ---------");
    let c = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736".from_hex().unwrap();
    let analysis = best_key(c.as_slice());

    println!("Key: {}", [analysis.key].to_hex());
    println!("Score: {}", analysis.score);
    print_message(analysis.message.clone());
    assert!("Cooking MC's like a pound of bacon" == String::from_utf8(analysis.message).unwrap().as_slice());
}

fn ch4() {
    println!("------- 4 ---------");
    let path = Path::new("./4.txt");
    let mut file = BufferedReader::new(File::open(&path));
    let analysis = best_message(file.lines().map(|x| x.unwrap().as_slice().trim().from_hex().unwrap()).collect::<Vec<Vec<u8>>>().as_slice());

    println!("Key: {}", [analysis.key].to_hex());
    println!("Score: {}", analysis.score);
    print_message(analysis.message.clone());
    assert!("Now that the party is jumping\n" == String::from_utf8(analysis.message).unwrap().as_slice());
}

fn ch5() {
    println!("------- 5 ---------");
    let key = "ICE".as_bytes();
    let m = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal".as_bytes();
    let c = block_encrypt(key, m).as_slice().to_hex();
    println!("c: {}", c);
    assert!("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f" == c.as_slice());
}

fn main() {
    ch1();
    ch2();
    ch3();
    ch4();
    ch5();
}
