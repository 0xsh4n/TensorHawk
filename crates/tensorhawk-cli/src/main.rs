//! `tensorhawk` — command-line interface.

use anyhow::Result;
use clap::{Parser, ValueEnum};
use std::io::Write;
use std::path::PathBuf;
use tensorhawk_core::report::{merged_sarif, render_html_document};
use tensorhawk_core::{analyze_paths, Baseline, Report, ScanConfig, Severity};

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum OutputFormat {
    Human,
    Json,
    Sarif,
    Html,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum SevArg {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl From<SevArg> for Severity {
    fn from(s: SevArg) -> Self {
        match s {
            SevArg::Info => Severity::Info,
            SevArg::Low => Severity::Low,
            SevArg::Medium => Severity::Medium,
            SevArg::High => Severity::High,
            SevArg::Critical => Severity::Critical,
        }
    }
}

/// Static security analysis for LLM model artifacts.
#[derive(Parser, Debug)]
#[command(name = "tensorhawk", version, about, long_about = None)]
struct Cli {
    /// Model file or directory to scan.
    #[arg(value_name = "PATH")]
    path: PathBuf,

    /// Output format.
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Human)]
    format: OutputFormat,

    /// Write output to a file instead of stdout.
    #[arg(short, long, value_name = "FILE")]
    output: Option<PathBuf>,

    /// Recurse into directories.
    #[arg(short, long)]
    recursive: bool,

    /// Only report findings at or above this severity.
    #[arg(long, value_enum, default_value_t = SevArg::Info)]
    min_severity: SevArg,

    /// Exit non-zero if any finding is at or above this severity (CI gate).
    #[arg(long, value_enum, default_value_t = SevArg::High)]
    fail_on: SevArg,

    /// Disable ANSI colour in human output.
    #[arg(long)]
    no_color: bool,

    /// Load additional declarative MODEL_RULE packs from this directory.
    #[arg(long, value_name = "DIR")]
    rules: Option<PathBuf>,

    /// Suppress findings listed in this baseline file (JSON).
    #[arg(long, value_name = "FILE")]
    baseline: Option<PathBuf>,

    /// Write a baseline capturing all current findings to this file and exit 0.
    #[arg(long, value_name = "FILE")]
    write_baseline: Option<PathBuf>,

    /// Enable experimental, heuristic research detectors (probabilistic).
    #[arg(long)]
    experimental: bool,
}

fn is_candidate(p: &std::path::Path) -> bool {
    let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("");
    let name = p.file_name().and_then(|e| e.to_str()).unwrap_or("");
    matches!(
        ext,
        "gguf"
            | "ggml"
            | "safetensors"
            | "bin"
            | "pt"
            | "pth"
            | "ckpt"
            | "onnx"
            | "pkl"
            | "pb"
            | "npz"
    ) || name == "saved_model.pb"
}

fn collect_targets(cli: &Cli) -> Vec<PathBuf> {
    if cli.path.is_file() {
        return vec![cli.path.clone()];
    }
    if cli.path.is_dir() {
        let walker =
            walkdir::WalkDir::new(&cli.path).max_depth(if cli.recursive { usize::MAX } else { 1 });
        return walker
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .map(|e| e.into_path())
            .filter(|p| is_candidate(p))
            .collect();
    }
    Vec::new()
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let color = !cli.no_color && cli.output.is_none() && atty_stdout();
    let min: Severity = cli.min_severity.into();
    let fail_on: Severity = cli.fail_on.into();

    let targets = collect_targets(&cli);
    if targets.is_empty() {
        eprintln!(
            "tensorhawk: no scannable model files at {}",
            cli.path.display()
        );
        std::process::exit(2);
    }

    let config = ScanConfig {
        user_rules: cli.rules.clone(),
        experimental: cli.experimental,
    };

    // Scan every target (in parallel), preserving order.
    let mut reports: Vec<Report> = Vec::new();
    for (path, res) in analyze_paths(&targets, &config) {
        match res {
            Ok(report) => reports.push(report),
            Err(e) => eprintln!("tensorhawk: error scanning {}: {e}", path.display()),
        }
    }

    // --write-baseline captures current findings and exits before filtering.
    if let Some(path) = &cli.write_baseline {
        let baseline = Baseline::from_reports(&reports);
        std::fs::File::create(path)?.write_all(baseline.to_json().as_bytes())?;
        eprintln!(
            "tensorhawk: wrote baseline with {} fingerprint(s) to {}",
            baseline.fingerprints.len(),
            path.display()
        );
        return Ok(());
    }

    // Baseline suppression, then min-severity filtering.
    let baseline = match &cli.baseline {
        Some(path) => Some(Baseline::load(path)?),
        None => None,
    };
    let mut suppressed = 0usize;
    for report in &mut reports {
        if let Some(b) = &baseline {
            suppressed += b.apply(report);
        }
        report.findings.retain(|f| f.severity >= min);
    }
    if suppressed > 0 {
        eprintln!("tensorhawk: suppressed {suppressed} baselined finding(s)");
    }

    let rendered = match cli.format {
        OutputFormat::Human => reports
            .iter()
            .map(|r| r.to_human(color))
            .collect::<Vec<_>>()
            .join("\n"),
        OutputFormat::Json => {
            if reports.len() == 1 {
                reports[0].to_json()
            } else {
                serde_json::to_string_pretty(&reports)?
            }
        }
        OutputFormat::Sarif => merged_sarif(&reports),
        OutputFormat::Html => render_html_document(&reports),
    };

    match &cli.output {
        Some(path) => {
            let mut f = std::fs::File::create(path)?;
            f.write_all(rendered.as_bytes())?;
            eprintln!("tensorhawk: wrote {}", path.display());
        }
        None => println!("{rendered}"),
    }

    // CI gate: fail if any report has a finding at/above --fail-on.
    let worst = reports
        .iter()
        .filter_map(|r| r.worst())
        .max()
        .unwrap_or(Severity::Info);
    if worst >= fail_on {
        std::process::exit(1);
    }
    Ok(())
}

/// Cheap stdout tty check without pulling in a crate.
fn atty_stdout() -> bool {
    #[cfg(unix)]
    {
        // SAFETY: isatty on fd 1 has no memory-safety concerns.
        unsafe { libc_isatty(1) }
    }
    #[cfg(not(unix))]
    {
        true
    }
}

#[cfg(unix)]
unsafe fn libc_isatty(fd: i32) -> bool {
    extern "C" {
        fn isatty(fd: i32) -> i32;
    }
    isatty(fd) == 1
}
