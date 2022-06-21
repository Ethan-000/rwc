

use openssl::hash::{hash, MessageDigest};
use hex;
use rand::{thread_rng, Rng};
use rand::distributions::Alphanumeric;

pub fn ex1(){
    println!("\n");
    println!("Q1: MD5 is said to be ‘insecure/broken’. Which security properties are vulnerable? Prove it. \n");
    println!("The collision resistance property is broken in 2004 cause a collision was found. \n");

    let hex1 = "d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f8955ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5bd8823e3156348f5bae6dacd436c919c6dd53e2b487da03fd02396306d248cda0e99f33420f577ee8ce54b67080a80d1ec69821bcb6a8839396f9652b6ff72a70";
    let hex2 = "d131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8fb7f8955ad340609f4b30283e4888325f1415a085125e8f7cdc99fd91dbd7280373c5bd8823e3156348f5bae6dacd436c919c6dd53e23487da03fd02396306d248cda0e99f33420f577ee8ce54b67080280d1ec69821bcb6a8839396f965ab6ff72a70";
    let msg1 = hex::decode(hex1).unwrap();
    let msg2 = hex::decode(hex2).unwrap();
    let hash1 = hash(MessageDigest::md5(), &msg1).unwrap().to_vec();
    let hash2 = hash(MessageDigest::md5(), &msg2).unwrap().to_vec();

    println!("Block: {:?} \n", hex1);
    println!("and Block: {:?} \n", hex1);
    println!("has the same hash {:?}", hash1);
    assert_eq!(hash1, hash2);
}

pub fn ex2() {
    println!("\n");
    println!("Q2: Calculate the total theoretical number of attempts it would take to brute force various hashes digests (MD5, SHA-1, SHA256). \n");
    println!("Guess its 2^128 attempts for sha1/md5 and 2^256 for sha256,\n" );
    println!("but due to the birthday paradox it is possible to find one in 2^(N/2). \n")
}

pub fn ex3() {
    println!("\n");
    println!("Q3: Find a digest collision of the first 4/6 bits of any two input string MD5 hash digests. \n");
    let input_str = "A".as_bytes();

    let hash_str = hash(MessageDigest::md5(), &input_str).unwrap().to_vec();

    let mut hash_rand: Vec<_>;
    let now = std::time::Instant::now();
    let mut counter = 1;
    loop {
        let rand_string: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(counter)
        .map(char::from)
        .collect();
        hash_rand = hash(MessageDigest::md5(), &rand_string.as_bytes()).unwrap().to_vec();

        if hash_str[0] == hash_rand[0] {
            break;
        }
        counter += 1;
    }
    let elapsed = now.elapsed();
    println!("Time to find a 8 bit collision: {:?}", elapsed);
    assert_eq!(hash_str[0], hash_rand[0]);
}

pub fn ex4(x: &[u8], y: &[u8]) -> u64 {
    println!("\n");
    println!("Q4: Explain and demonstrate how to calculates the Hamming Distance between two strings. \n");
    println!("The Hamming distance between two equal-length strings of symbols is \n the number of positions at which the corresponding symbols are different (wikipedia) \n");
    println!("which can be calculated through fold and bitwise xor to check the difference. \n");
    hamming_distance(x, y)
}

pub fn ex5()  {
    println!("\n");
    println!("Q5: What is the Hamming Distance between any bytestring hashes where i1 (unmodified) and i2 has 1 bit flipped. \n");
    
    let i1 = "i1";
    let i2 = "i2";

    let hash_i1 = hash(MessageDigest::md5(), &i1.as_bytes()).unwrap().to_vec();
    let hash_i2 = hash(MessageDigest::md5(), &i2.as_bytes()).unwrap().to_vec();
    let distance = hamming_distance(&hash_i1, &hash_i2);
    println!("The hamming distance is {:?}", distance);
}

pub fn ex6() {
    println!("\n");
    println!("Q6: Explain and demonstrate the difference b/w Second Pre-Image Resistance and Collision Resistance. \n");

    println!("Second Pre-Image resistance means given a hash h and its image i it is difficult to find another i' that has hash h. \n");
    println!("Collision resistance means it is difficult to find i and i' such that they have the same hash. \n");
    println!("Collision resistance is a stronger assumption (I think) but sometimes the property is broken without Second Pre-Image resistance being broken.\n");
    println!("(See papers in the paper folder.)")
}

pub fn ex7() {
    println!("\n");
    println!("Q7: Explain and demonstrate the calculation of 'The Birthday Bound' Paradox. \n");

    println!("Given approximately by the equation n = sqrt(2*H*p(n))\n")
}

pub fn ex8() {
    println!("\n");
    println!("Q8: Find an input string which results in a SHA256 hash with 1/2/X 0's (zero) \n");

    let mut counter = 1;
    loop {
        let rand_string: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(counter)
        .map(char::from)
        .collect();
        let hash_rand = hash(MessageDigest::sha1(), &rand_string.as_bytes()).unwrap().to_vec();

        if hash_rand[0] == 0{
            println!("{:?} sha1 hash starts with 8 zeros \nhash: {:?}. ", rand_string, hash_rand);
            break;
        }
        counter += 1;
    }
}

pub fn ex9() {
    println!("\n");
    println!("Q9: Find X (look up, don't over think it): md5(X).digest() > d41d8cd98f00b204e9800998ecf8427e \n");

    let input_str = "".as_bytes();
    let hash_str = hash(MessageDigest::md5(), &input_str).unwrap().to_vec();
    let expected_hash = hex::decode("d41d8cd98f00b204e9800998ecf8427e").unwrap();

    assert_eq!(hash_str, expected_hash);
    println!("The image of d41d8cd98f00b204e9800998ecf8427e is the empty string. ")
}

pub fn ex12() {
    println!("\n");
    println!("Q12: Explain and demonstrate the difference between cryptographic hash functions and checksum functions (CRC32) \n");

    println!("Simple answer: \n");
    println!("checksum functions are used to check accidental changes. \n");
    println!("cryptographic hash functions are used for verification. \n");
}

fn hamming_distance(x: &[u8], y: &[u8]) -> u64 {
    x.iter().zip(y).fold(0, |a, (b, c)| a + (*b ^ *c).count_ones() as u64)
}










// Some materials that may be helpful: 
// http://merlot.usc.edu/csac-f06/papers/Wang05a.pdf
// https://www.mscs.dal.ca/~selinger/md5collision/
// https://crypto.stackexchange.com/questions/1434/are-there-two-known-strings-which-have-the-same-md5-hash-value


