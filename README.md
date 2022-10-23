# secret-sharing

A CLI tool for creating `n` secret shares of data and combining exactly `k` of those shares to
recover the data. The process for creating shares is as follows:

1. Compress the secret data using [Zstandard](https://en.wikipedia.org/wiki/Zstd)
2. Create a 32-byte secret key using
   [OsRng](https://docs.rs/rand/latest/rand/rngs/struct.OsRng.html)
3. Encrypt the compressed secret using the
   [ChaCha20-Poly1305](https://en.wikipedia.org/wiki/ChaCha20-Poly1305) algorithm, with the secret
   key and a nonce of zero
4. Create `n` 113-byte shares of the secret key (followed by 32 bytes of zeroes to pad it up to 64
   bytes) using [Shamir Secret Sharing](https://dsprenkels.github.io/sss/#introduction)
5. Each secret key share is prepended to the encrypted payload

## Installation

```bash
cargo install --git https://github.com/theodus/secret-sharing
```

## Example Usage

- `secret-sharing create 3 2 <data.txt` produces 3 secret shares of the content of `data.txt`,
  where 2 of the shares are required to recover the content of `data.txt`
- `secret-sharing combine <share1.hex <share2.hex` recovers 2 shares into the secret data, assuming
  the shares were created with `k=2`
