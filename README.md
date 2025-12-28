# File Entropy Analyzer

A Rust CLI tool to analyze file entropy for detecting encrypted, compressed, or packed files.

## What is Shannon Entropy?

Shannon entropy measures the "randomness" or "information content" of data. The formula is:

```
H = -Σ p(x) * log₂(p(x))
```

Where:

- **H** = entropy in bits per byte (0.0 to 8.0)
- **p(x)** = probability of byte value x occurring
- The sum is over all 256 possible byte values (0-255)

### Entropy Interpretation

| Entropy Range | Interpretation | Examples |
|---------------|----------------|----------|
| 0.0 - 1.0 | Very low (repetitive) | Files of repeated bytes |
| 1.0 - 4.0 | Low (structured) | Simple text, code |
| 4.0 - 5.5 | Normal text | English text, source code |
| 5.5 - 6.5 | Binary data | Executables, libraries |
| 6.5 - 7.5 | Compressed | ZIP, gzip, images |
| 7.5 - 7.9 | Highly compressed | Efficient compression |
| 7.9 - 8.0 | Encrypted/random | AES-encrypted files |

## Usage

```bash
# Analyze a single file
file-entropy-analyzer /path/to/file

# Analyze directory (non-recursive)
file-entropy-analyzer /path/to/dir

# Analyze directory recursively
file-entropy-analyzer -r /path/to/dir

# Show detailed byte frequencies
file-entropy-analyzer -v /path/to/file

# Custom buffer size (default: 8192 bytes)
file-entropy-analyzer -b 65536 /path/to/file
```

## Building

```bash
cargo build --release
```

## Security Applications

- **Ransomware detection**: Encrypted files show entropy > 7.9
- **Malware analysis**: Packed/encrypted payloads have high entropy
- **Data classification**: Identify sensitive encrypted data
- **Forensics**: Find hidden encrypted volumes

## References

- Shannon, C.E. (1948). "A Mathematical Theory of Communication"
- NIST FIPS guidelines on cryptographic randomness
- Ransomware detection research using entropy analysis
