extern crate serialize;
extern crate openssl;
use serialize::hex::{FromHex, ToHex};
use serialize::base64::{ToBase64, FromBase64, STANDARD};
use std::io::BufferedReader;
use std::io::File;
use std::iter::AdditiveIterator;
use openssl::crypto::symm::{decrypt, AES_128_ECB};

static LETTER_FREQUENCY: &'static [f32] = & [0.0855, 0.0160, 0.0316, 0.0387, 0.1210, 0.0218, 0.0209, 0.0496, 0.0733, 0.0022, 0.0081, 0.0421, 0.0253, 0.0717, 0.0747, 0.0207, 0.0010, 0.0633, 0.0673, 0.0894, 0.0268, 0.0106, 0.0183, 0.0019, 0.0172, 0.0011];

#[deriving(Clone)]
struct ByteAnalysisResult {
    key : u8,
    score : f32,
    message : Vec<u8>
}

struct BlockAnalysisResult {
    key : Vec<u8>,
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

fn hamming_distance(m1 : &[u8], m2 : &[u8]) -> uint {
    let d = m1.iter().zip(m2.iter()).map(|(&b1, &b2)| {
        (b1 ^ b2).count_ones() as uint
    }).sum();

    return d;
}

fn guess_keysize(c : &Vec<u8>) -> Vec<(uint, f32)> {
    let keysize_distance = range(2, 40).map(|n| {
        let ds = range(0, c.len()/n - 1).map(|i| hamming_distance(c.slice(i*n,(i+1)*n), c.slice((i+1)*n, (i+2)*n)) as uint).collect::<Vec<uint>>();
        let l = ds.len();
        ds.move_iter().sum() as f32 / (l*n) as f32
    });

    let mut keysize_pair : Vec<(uint, f32)> = range(2u, 40u).zip(keysize_distance).collect();
    keysize_pair.sort_by(|&(_,a),&(_,b)| a.partial_cmp(&b).unwrap_or(Equal));
    keysize_pair
}

fn guess_block_key(c : &Vec<u8>, keysize : uint) -> BlockAnalysisResult {
    let block_count = c.len() / keysize;

    let key : Vec<u8> = range(0, keysize).map(|i| {
        let partial_c = range(0, block_count-1).map(|n| c[n*keysize + i]).collect::<Vec<u8>>();
        let analysis = best_key(partial_c.as_slice());
        analysis.key
    }).collect();

    let message = block_encrypt(key.as_slice(), c.as_slice());

    BlockAnalysisResult { key: key, message: message }
}

fn has_similar_block(data : Vec<u8>) -> bool {
    let n = data.len()/16;
    let blocks = range(0, n).map(|i| data.slice(i*16, (i+1)*16) ).collect::<Vec<&[u8]>>();

    range(0, n).zip(blocks.iter()).any(|(i, block)| {
        let mut it = blocks.iter();
        it.nth(i+1);
        it.any(|oth| block == oth)
    })
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

fn ch6() {
    println!("------- 6 ---------");
    let m1 = "this is a test".as_bytes();
    let m2 = "wokka wokka!!!".as_bytes();
    let h_test = hamming_distance(m1, m2);
    println!("h_test: {}", h_test);
    assert!(37 == h_test);

    let path = Path::new("./6.txt");
    let mut file = BufferedReader::new(File::open(&path));
    let c = file.read_to_string().unwrap().as_slice().from_base64().unwrap();
    let keysizes = guess_keysize(&c);

    for &(ks, score) in keysizes.iter() {
        println!("{}->{}", ks, score);
    }
    let (keysize, _) = keysizes[0];
    let analysis = guess_block_key(&c, keysize);
    let key = String::from_utf8(analysis.key).unwrap();
    println!("key: {}", key);
    print_message(analysis.message);

    assert!("Terminator X: Bring the noise" == key.as_slice());
}

fn ch7() {
    println!("------- 7 ---------");
    let path = Path::new("./7.txt");
    let mut file = BufferedReader::new(File::open(&path));
    let c = file.read_to_string().unwrap().as_slice().from_base64().unwrap();
    let k = "YELLOW SUBMARINE".as_bytes();

    let m = decrypt(AES_128_ECB, k, Vec::new(), c.as_slice());
    print_message(m);
}

fn ch8() {
    println!("------- 8 ---------");
    let path = Path::new("./8.txt");
    let mut file = BufferedReader::new(File::open(&path));
    let potentials_ecb = file.lines()
        .map(|l| l.unwrap())
        .filter(|l| has_similar_block(l.as_slice().trim().from_hex().unwrap()))
        .collect::<Vec<String>>();
    println!("Potential ecb ({}): {}", potentials_ecb.len(), potentials_ecb[0]);
}

fn main() {
    ch1();
    ch2();
    ch3();
    ch4();
    ch5();
    ch6();
    ch7();
    ch8();
}
