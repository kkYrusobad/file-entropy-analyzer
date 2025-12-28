//! # File Entropy Analyzer
//!
//! This tool calculates Shannon entropy of files to detect:
//! - Encrypted files (high entropy, ~7.9-8.0 bits/byte)
//! - Compressed files (high entropy, ~7.5-7.9 bits/byte)
//! - Normal text files (low entropy, ~4.0-5.0 bits/byte)
//! - Binary executables (medium entropy, ~5.5-6.5 bits/byte)
//!
//! ## What is Shannon Entropy?
//!
//! Shannon entropy measures the "randomness" or "information content" of data.
//! The formula is: H = -Σ p(x) * log₂(p(x))
//!
//! Where:
//! - H is the entropy in bits per byte (0.0 to 8.0)
//! - p(x) is the probability of byte value x occurring
//! - The sum is over all possible byte values (0-255)
//!
//! ## Why does this work?
//!
//! - Random/encrypted data: Each byte value appears with equal probability (~1/256)
//!   This gives maximum entropy of log₂(256) = 8 bits/byte
//! - Repetitive/text data: Some bytes appear more often (e.g., 'e', ' ', 'a')
//!   This reduces entropy because the data is more predictable

use clap::Parser;
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::PathBuf;
use walkdir::WalkDir;

/// File Entropy Analyzer - Detect encrypted, compressed, or packed files
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to file or directory to analyze
    #[arg(required = true)]
    path: PathBuf,

    /// Recursively scan directories
    #[arg(short, long, default_value_t = false)]
    recursive: bool,

    /// Show detailed byte frequency distribution
    #[arg(short, long, default_value_t = false)]
    verbose: bool,

    /// Buffer size in bytes for reading files (default: 8KB)
    #[arg(short, long, default_value_t = 8192)]
    buffer_size: usize,
}

/// Holds the result of entropy analysis for a file
#[derive(Debug)]
struct EntropyResult {
    /// Path to the analyzed file
    path: PathBuf,
    /// Calculated Shannon entropy (0.0 to 8.0 bits/byte)
    entropy: f64,
    /// Total bytes analyzed
    total_bytes: u64,
    /// Frequency of each byte value (0-255)
    byte_frequencies: [u64; 256],
}

impl EntropyResult {
    /// Classify the file based on entropy value
    ///
    /// These thresholds are based on empirical observations:
    /// - Text files typically have entropy 4.0-5.5
    /// - Executables typically have entropy 5.5-6.5
    /// - Compressed files typically have entropy 7.5-7.9
    /// - Encrypted files typically have entropy 7.9-8.0
    fn classify(&self) -> &'static str {
        match self.entropy {
            e if e < 1.0 => "Very low entropy (repetitive data)",
            e if e < 4.0 => "Low entropy (structured data/text)",
            e if e < 5.5 => "Normal text file",
            e if e < 6.5 => "Binary/executable",
            e if e < 7.5 => "Compressed or semi-random",
            e if e < 7.9 => "Highly compressed",
            _ => "Encrypted or maximum entropy",
        }
    }

    /// Get a color for the entropy level for terminal display
    fn entropy_color(&self) -> colored::Color {
        match self.entropy {
            e if e < 4.0 => colored::Color::Green,
            e if e < 6.5 => colored::Color::Yellow,
            e if e < 7.5 => colored::Color::TrueColor { r: 255, g: 165, b: 0 }, // Orange
            _ => colored::Color::Red,
        }
    }
}

/// Calculate Shannon entropy from byte frequency counts
///
/// # The Math Behind This
///
/// Shannon entropy formula: H = -Σ p(x) * log₂(p(x))
///
/// For each byte value (0-255):
/// 1. Calculate probability: p(x) = count(x) / total_bytes
/// 2. If p(x) > 0, add: -p(x) * log₂(p(x)) to the sum
///
/// # Why use log₂?
///
/// We measure in bits. log₂(256) = 8, so maximum entropy is 8 bits/byte.
/// This makes intuitive sense: each byte has 8 bits of information.
///
/// # Arguments
///
/// * `frequencies` - Array of 256 elements, each containing the count of that byte value
/// * `total_bytes` - Total number of bytes analyzed
///
/// # Returns
///
/// Entropy value between 0.0 (perfectly predictable) and 8.0 (perfectly random)
fn calculate_entropy(frequencies: &[u64; 256], total_bytes: u64) -> f64 {
    // Handle edge case: empty file has 0 entropy
    if total_bytes == 0 {
        return 0.0;
    }

    let total = total_bytes as f64;
    let mut entropy = 0.0;

    // Iterate over all 256 possible byte values
    for &count in frequencies.iter() {
        // Skip bytes that never appear (log(0) is undefined)
        if count == 0 {
            continue;
        }

        // Calculate probability of this byte value
        // p(x) = how often this byte appears / total bytes
        let probability = count as f64 / total;

        // Shannon entropy contribution: -p(x) * log₂(p(x))
        //
        // Why negative? Because log(p) is negative when p < 1,
        // and we want a positive entropy value.
        //
        // Note: probability.log2() computes log₂(probability)
        entropy -= probability * probability.log2();
    }

    entropy
}

/// Analyze a single file and calculate its entropy
///
/// # How file reading works
///
/// We use buffered reading to handle large files efficiently:
/// 1. Open the file
/// 2. Wrap in BufReader (adds internal buffering)
/// 3. Read in chunks of `buffer_size` bytes
/// 4. Count byte frequencies as we go
/// 5. Calculate entropy from final counts
///
/// # Arguments
///
/// * `path` - Path to the file to analyze
/// * `buffer_size` - Size of read buffer in bytes
/// * `show_progress` - Whether to display a progress bar
///
/// # Returns
///
/// `EntropyResult` containing entropy and statistics, or an error
fn analyze_file(
    path: &PathBuf,
    buffer_size: usize,
    show_progress: bool,
) -> Result<EntropyResult, std::io::Error> {
    // Open the file
    // File::open returns Result<File, io::Error>
    // The ? operator propagates errors up to the caller
    let file = File::open(path)?;

    // Get file size for progress bar
    // metadata() returns file information including size
    let file_size = file.metadata()?.len();

    // Create a buffered reader
    // BufReader adds an internal buffer to reduce system calls
    // Without it, each read() would be a separate syscall (slow!)
    let mut reader = BufReader::new(file);

    // Initialize byte frequency counter
    // Array of 256 u64 values, all starting at 0
    // Index = byte value (0-255), Value = count of occurrences
    let mut frequencies: [u64; 256] = [0; 256];

    // Track total bytes read
    let mut total_bytes: u64 = 0;

    // Create read buffer
    // Vec<u8> is a growable byte array
    // vec![0; size] creates a vector of `size` zeros
    let mut buffer = vec![0u8; buffer_size];

    // Optional progress bar for large files
    let progress = if show_progress && file_size > 1_000_000 {
        let pb = ProgressBar::new(file_size);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")
                .expect("Invalid progress bar template")
                .progress_chars("#>-"),
        );
        Some(pb)
    } else {
        None
    };

    // Read file in chunks
    loop {
        // reader.read() fills the buffer and returns bytes read
        // Returns 0 when we reach end of file
        let bytes_read = reader.read(&mut buffer)?;

        if bytes_read == 0 {
            break; // End of file
        }

        // Count frequency of each byte in this chunk
        // buffer[..bytes_read] is a slice of the actually-read bytes
        for &byte in &buffer[..bytes_read] {
            // byte is a u8 (0-255), which directly indexes our array
            frequencies[byte as usize] += 1;
        }

        total_bytes += bytes_read as u64;

        // Update progress bar if present
        if let Some(ref pb) = progress {
            pb.set_position(total_bytes);
        }
    }

    // Finish progress bar
    if let Some(pb) = progress {
        pb.finish_with_message("done");
    }

    // Calculate entropy from the collected frequencies
    let entropy = calculate_entropy(&frequencies, total_bytes);

    Ok(EntropyResult {
        path: path.clone(),
        entropy,
        total_bytes,
        byte_frequencies: frequencies,
    })
}

/// Print detailed byte frequency distribution
///
/// This shows which byte values appear most frequently,
/// which helps understand the file's structure.
fn print_frequency_distribution(result: &EntropyResult) {
    println!("\n{}", "Byte Frequency Distribution (top 20):".bold());

    // Create vector of (byte_value, count) pairs
    let mut freq_pairs: Vec<(usize, u64)> = result
        .byte_frequencies
        .iter()
        .enumerate()
        .filter(|(_, &count)| count > 0)
        .map(|(byte, &count)| (byte, count))
        .collect();

    // Sort by count (descending)
    freq_pairs.sort_by(|a, b| b.1.cmp(&a.1));

    // Show top 20
    for (byte, count) in freq_pairs.iter().take(20) {
        let percentage = (*count as f64 / result.total_bytes as f64) * 100.0;
        let char_repr = if *byte >= 32 && *byte <= 126 {
            format!("'{}'", *byte as u8 as char)
        } else {
            format!("0x{:02X}", byte)
        };
        println!(
            "  {:>6}: {:>10} ({:>5.2}%)",
            char_repr, count, percentage
        );
    }
}

/// Print the analysis result with colors and classification
fn print_result(result: &EntropyResult, verbose: bool) {
    let entropy_str = format!("{:.4}", result.entropy);
    let colored_entropy = entropy_str.color(result.entropy_color()).bold();

    println!(
        "{}: {} bits/byte - {}",
        result.path.display(),
        colored_entropy,
        result.classify()
    );
    println!(
        "  {} bytes analyzed",
        result.total_bytes.to_string().dimmed()
    );

    if verbose {
        print_frequency_distribution(result);
    }
}

fn main() {
    // Parse command-line arguments using clap
    // The derive macro generates argument parsing from our Args struct
    let args = Args::parse();

    // Check if path exists
    if !args.path.exists() {
        eprintln!(
            "{}: Path does not exist: {}",
            "Error".red().bold(),
            args.path.display()
        );
        std::process::exit(1);
    }

    // Handle single file
    if args.path.is_file() {
        match analyze_file(&args.path, args.buffer_size, true) {
            Ok(result) => print_result(&result, args.verbose),
            Err(e) => eprintln!(
                "{}: Failed to analyze {}: {}",
                "Error".red().bold(),
                args.path.display(),
                e
            ),
        }
        return;
    }

    // Handle directory
    if args.path.is_dir() {
        let walker = if args.recursive {
            WalkDir::new(&args.path)
        } else {
            WalkDir::new(&args.path).max_depth(1)
        };

        let mut file_count = 0;
        let mut error_count = 0;

        for entry in walker.into_iter().filter_map(|e| e.ok()) {
            let path = entry.path().to_path_buf();

            // Skip directories, only analyze files
            if path.is_file() {
                match analyze_file(&path, args.buffer_size, false) {
                    Ok(result) => {
                        print_result(&result, args.verbose);
                        file_count += 1;
                    }
                    Err(e) => {
                        eprintln!(
                            "{}: Failed to analyze {}: {}",
                            "Warning".yellow().bold(),
                            path.display(),
                            e
                        );
                        error_count += 1;
                    }
                }
            }
        }

        println!(
            "\n{} files analyzed, {} errors",
            file_count.to_string().green().bold(),
            error_count.to_string().red().bold()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_calculation_uniform() {
        // Uniform distribution: each byte appears once
        // This should give maximum entropy ≈ 8.0
        let mut frequencies = [0u64; 256];
        for i in 0..256 {
            frequencies[i] = 1;
        }
        let entropy = calculate_entropy(&frequencies, 256);
        assert!((entropy - 8.0).abs() < 0.0001, "Expected entropy ≈ 8.0, got {}", entropy);
    }

    #[test]
    fn test_entropy_calculation_single_byte() {
        // All same byte: minimum entropy = 0.0
        let mut frequencies = [0u64; 256];
        frequencies[65] = 1000; // All 'A's
        let entropy = calculate_entropy(&frequencies, 1000);
        assert!((entropy - 0.0).abs() < 0.0001, "Expected entropy = 0.0, got {}", entropy);
    }

    #[test]
    fn test_entropy_calculation_two_bytes_equal() {
        // Two bytes with equal frequency: entropy = 1.0
        let mut frequencies = [0u64; 256];
        frequencies[0] = 500;
        frequencies[1] = 500;
        let entropy = calculate_entropy(&frequencies, 1000);
        assert!((entropy - 1.0).abs() < 0.0001, "Expected entropy = 1.0, got {}", entropy);
    }

    #[test]
    fn test_empty_file() {
        let frequencies = [0u64; 256];
        let entropy = calculate_entropy(&frequencies, 0);
        assert!((entropy - 0.0).abs() < 0.0001, "Expected entropy = 0.0 for empty file");
    }
}
