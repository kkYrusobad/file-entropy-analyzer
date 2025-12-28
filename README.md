# 🔬 File Entropy Analyzer

<div align="center">

[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()

**A blazing-fast CLI tool to analyze file entropy for detecting encrypted, compressed, or packed files.**

*Built with Rust for maximum performance and safety.*

</div>

---

## ✨ Features

- 🔍 **Shannon Entropy Analysis** — Calculate information entropy to identify file characteristics
- 🎯 **Magic Bytes Detection** — Identify 25+ file formats (PDF, PNG, MP3, ELF, ZIP, and more)
- 📊 **Visual Entropy Bar** — Intuitive terminal visualization of entropy levels
- 🎨 **Modern Terminal UI** — Color-coded output with emoji icons
- 📁 **Directory Scanning** — Recursive analysis with progress tracking
- ⚡ **Blazing Fast** — Optimized buffered reading for large files
- 🔬 **Detailed Analysis** — Verbose mode shows byte frequency distribution

## 📸 Screenshot

```
  📝 README.md
     Text file  1.79 KB
     🟡 █████████████░░░░░░░ 5.053 bits/byte
     Normal text file

  ⚙️ binary-executable
     ELF executable (64-bit)  1.38 MB
     🟠 ████████████████░░░░ 6.299 bits/byte
     Binary/executable

  🗜️ archive.tar.gz
     GZIP compressed  45.2 KB
     🔴 ███████████████████░ 7.892 bits/byte
     Highly compressed
```

## 🚀 Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/yourusername/file-entropy-analyzer.git
cd file-entropy-analyzer

# Build in release mode
cargo build --release

# The binary will be at ./target/release/file-entropy-analyzer
```

### Via Cargo (coming soon)

```bash
cargo install file-entropy-analyzer
```

## 📖 Usage

### Basic Usage

```bash
# Analyze a single file
file-entropy-analyzer /path/to/file

# Analyze all files in a directory
file-entropy-analyzer /path/to/directory

# Recursively scan directories
file-entropy-analyzer -r /path/to/directory

# Show detailed byte frequency distribution
file-entropy-analyzer -v /path/to/file
```

### Command Line Options

| Option | Short | Description |
|--------|-------|-------------|
| `--recursive` | `-r` | Recursively scan directories |
| `--verbose` | `-v` | Show byte frequency distribution |
| `--buffer-size` | `-b` | Custom buffer size in bytes (default: 8192) |
| `--help` | `-h` | Show help message |
| `--version` | `-V` | Show version |

### Examples

```bash
# Find potentially encrypted files in a directory
file-entropy-analyzer -r ~/Documents | grep "Encrypted"

# Analyze a suspicious binary
file-entropy-analyzer -v suspicious.exe

# Quick scan of current directory
file-entropy-analyzer .
```

## 📊 Understanding Entropy

Shannon entropy measures the "randomness" or "information content" of data:

```
H = -Σ p(x) × log₂(p(x))
```

| Entropy Range | Interpretation | Examples |
|---------------|----------------|----------|
| 🟢 0.0 - 1.0 | Very low (repetitive) | Sparse files, null bytes |
| 🟢 1.0 - 4.0 | Low (structured) | Simple text, code |
| 🟡 4.0 - 5.5 | Normal text | English prose, source code |
| 🟠 5.5 - 6.5 | Binary data | Executables, libraries |
| 🔶 6.5 - 7.5 | Compressed | ZIP, JPEG, gzip |
| 🔴 7.5 - 7.9 | Highly compressed | Efficient compression |
| ⛔ 7.9 - 8.0 | Encrypted/random | AES-encrypted, CSPRNG output |

## 🔐 Security Applications

| Use Case | Description |
|----------|-------------|
| **Ransomware Detection** | Encrypted files show entropy > 7.9 |
| **Malware Analysis** | Identify packed/encrypted payloads |
| **Data Classification** | Find sensitive encrypted data |
| **Digital Forensics** | Detect hidden encrypted volumes |
| **Incident Response** | Quick triage of suspicious files |

## 🎯 Supported File Types

The tool detects file types via magic bytes (more reliable than extensions):

| Category | Formats |
|----------|---------|
| **Images** | PNG, JPEG, GIF |
| **Audio** | MP3, FLAC, WAV, OGG |
| **Video** | MP4, M4A, MOV, WebM, MKV |
| **Archives** | ZIP, GZIP, BZIP2, XZ, 7-Zip, RAR |
| **Executables** | ELF (32/64-bit), Windows PE, Mach-O |
| **Documents** | PDF, XML, HTML |
| **Data** | SQLite, Text files, Shell scripts |

## 🏗️ Architecture

```
src/
└── main.rs          # Single-file implementation with:
    ├── CLI parsing  # clap derive macros
    ├── Entropy      # Shannon entropy calculation
    ├── Magic bytes  # File type detection
    ├── UI           # Colored output, progress bars
    └── Tests        # Unit tests for entropy math
```

## 📚 Theory & References

- **Shannon, C.E. (1948)** — "A Mathematical Theory of Communication"
- **NIST SP 800-22** — Randomness testing for cryptographic applications
- **File Signatures (Magic Bytes)** — [Wikipedia](https://en.wikipedia.org/wiki/List_of_file_signatures)

## 🧪 Testing

```bash
# Run unit tests
cargo test

# Run with verbose output
cargo test -- --nocapture
```

## 📝 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

<div align="center">

**Made with ❤️ and 🦀**

*If this tool helped you, consider giving it a ⭐!*

</div>
