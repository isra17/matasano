fn bytes_to_string(bytes : Vec<u8>) -> String {
    String::from_utf8(bytes).unwrap()
}

fn pkcs7_pad(data : &mut Vec<u8>, block_size : uint) {
    let n = block_size - (data.len() % block_size);
    data.grow(n, &(n as u8));
}

fn ch1() {
    let mut data = Vec::from_slice("YELLOW SUBMARINE".as_bytes());
    pkcs7_pad(&mut data, 20);
    println!("Padded data: {}", data);
    println!("Padded message: {}", bytes_to_string(data.clone()));
    assert!("YELLOW SUBMARINE\x04\x04\x04\x04".as_bytes() == data.as_slice());
}

fn main() {
    ch1();
}
