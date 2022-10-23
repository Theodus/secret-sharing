use anyhow::{ensure, Result};
use chacha20poly1305::{
    aead::{Aead as _, KeyInit as _},
    ChaCha20Poly1305,
};
use clap::{self, Parser as _};
use rand::rngs::OsRng;
use std::{
    env::args_os,
    io::{stdin, Read},
};

#[derive(clap::Parser)]
#[command(author, version, about, long_about = None, propagate_version = true)]
struct Opt {
    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand)]
enum Commands {
    #[command(about = "Create n shares, k of which can restore the data from stdin")]
    Create {
        #[arg(help = "total count of shares")]
        n: u8,
        #[arg(help = "count of shares required to restore the secret")]
        k: u8,
    },
    #[command(about = "Combine shares given from stdin")]
    Combine,
}

fn main() -> Result<()> {
    let mut input = String::new();
    let opt = Opt::parse_from(args_os());
    stdin().read_to_string(&mut input)?;
    let output = run(opt, input)?;
    println!("{}", output);
    Ok(())
}

fn run(opt: Opt, input: String) -> Result<String> {
    match &opt.command {
        &Commands::Create { n, k } => Ok(create_shares(n, k, input.as_bytes())?
            .into_iter()
            .map(hex::encode)
            .collect::<Vec<String>>()
            .join("\n")),
        Commands::Combine => {
            let shares = input
                .split_terminator('\n')
                .map(|s| Ok(hex::decode(s)?))
                .collect::<Result<Vec<Vec<u8>>>>()?;
            Ok(String::from_utf8_lossy(&combine_shares(&shares)?).into())
        }
    }
}

fn create_shares(n: u8, k: u8, data: &[u8]) -> Result<Vec<Vec<u8>>> {
    let key = ChaCha20Poly1305::generate_key(&mut OsRng);

    let mut share_data = [0u8; shamirsecretsharing::DATA_SIZE];
    share_data[..32].copy_from_slice(&key);
    let mut shares = shamirsecretsharing::create_shares(&share_data, n, k)?;

    let compressed = zstd::stream::encode_all(data, 0).unwrap();
    let cipher = ChaCha20Poly1305::new(&key);
    let nonce = [0u8; 12];
    let ciphertext = cipher.encrypt(&nonce.into(), &*compressed).unwrap();

    for share in &mut shares {
        share.extend_from_slice(&ciphertext);
    }

    Ok(shares)
}

fn combine_shares(shares: &[Vec<u8>]) -> Result<Vec<u8>> {
    let share_data = shares
        .iter()
        .map(|s| s[..shamirsecretsharing::SHARE_SIZE].to_vec())
        .collect::<Vec<Vec<u8>>>();
    let key = shamirsecretsharing::combine_shares(&share_data)?.unwrap();

    let ciphertext = &shares[0][shamirsecretsharing::SHARE_SIZE..];
    ensure!(shares
        .iter()
        .all(|s| &s[shamirsecretsharing::SHARE_SIZE..] == ciphertext));

    let cipher = ChaCha20Poly1305::new(key[..32].into());
    let nonce = [0u8; 12];
    let plaintext = cipher.decrypt(&nonce.into(), ciphertext).unwrap();
    let decompressed = zstd::stream::decode_all(&*plaintext).unwrap();

    Ok(decompressed)
}

#[test]
fn test() {
    use rand::{seq::SliceRandom as _, thread_rng};
    use std::ops::Deref;

    let plaintext = "yup";
    let shares = run(
        Opt::parse_from(["self", "create", "3", "2"]),
        plaintext.into(),
    )
    .unwrap();
    let shares = shares.split_terminator('\n').collect::<Vec<&str>>();
    let subset = shares
        .choose_multiple(&mut thread_rng(), 2)
        .map(Deref::deref)
        .collect::<Vec<&str>>()
        .join("\n");
    let result = run(Opt::parse_from(["self", "combine"]), subset).unwrap();
    assert_eq!(result, plaintext);
}
