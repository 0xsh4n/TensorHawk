//! `tensorhawk` — command-line interface.

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use std::io::Write;
use std::path::{Path, PathBuf};
use tensorhawk_core::report::{merged_sarif, render_html_report, HtmlReportOptions};
use tensorhawk_core::{analyze_paths, Baseline, Report, ScanConfig, Severity};

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum OutputFormat {
    Human,
    Json,
    Sarif,
    Html,
    /// Branded PDF report (requires `--output` and a local HTML→PDF converter:
    /// WeasyPrint, wkhtmltopdf, or headless Chromium/Chrome).
    Pdf,
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

    /// Author name shown in the HTML/PDF report header and footer. Pass an empty
    /// string to omit.
    #[arg(long, value_name = "NAME", default_value = "0xsh4n")]
    author: String,
}

fn is_candidate(p: &std::path::Path) -> bool {
    let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("");
    let name = p.file_name().and_then(|e| e.to_str()).unwrap_or("");
    let ext_match = matches!(
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
            | "json"
            | "csv"
            | "tsv"
            | "jsonl"
            | "ndjson"
    ) || name == "saved_model.pb";
    // Fast path: a recognized extension. Otherwise sniff the leading bytes for a
    // strong container magic, so extensionless model files are still discovered
    // during a directory scan — notably Ollama's `sha256-<hash>` blobs.
    ext_match || has_model_magic_at(p)
}

/// Peek at a file's first bytes and report whether they carry a strong model
/// container magic (GGUF/GGML/ZIP/safetensors). Any I/O error means "not a
/// candidate" — discovery must never fail the run on an unreadable entry.
fn has_model_magic_at(p: &std::path::Path) -> bool {
    use std::io::Read;
    let mut buf = [0u8; 16];
    match std::fs::File::open(p).and_then(|mut f| f.read(&mut buf)) {
        Ok(n) => tensorhawk_core::format::has_model_magic(&buf[..n]),
        Err(_) => false,
    }
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

    // Branding/options shared by the HTML and PDF reports.
    let author = cli.author.trim();
    let html_opts = HtmlReportOptions {
        author: (!author.is_empty()).then(|| author.to_string()),
        generated_at: Some(now_utc_string()),
    };

    match cli.format {
        OutputFormat::Pdf => {
            let out = cli
                .output
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("--format pdf requires --output <FILE.pdf>"))?;
            let html = render_html_report(&reports, &html_opts);
            render_pdf(&html, out)?;
            eprintln!("tensorhawk: wrote {}", out.display());
        }
        other => {
            let rendered = match other {
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
                OutputFormat::Html => render_html_report(&reports, &html_opts),
                OutputFormat::Pdf => unreachable!("handled above"),
            };
            match &cli.output {
                Some(path) => {
                    let mut f = std::fs::File::create(path)?;
                    f.write_all(rendered.as_bytes())?;
                    eprintln!("tensorhawk: wrote {}", path.display());
                }
                None => println!("{rendered}"),
            }
        }
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

/// Convert a rendered HTML report to a PDF at `out`, using the first available
/// local converter. WeasyPrint is preferred (it honours our `@page` running
/// header/footer and page numbers); wkhtmltopdf and headless Chromium/Chrome
/// are fallbacks. External converters are an optional integration: if none is
/// installed we fail with actionable guidance rather than a mandatory dep.
fn render_pdf(html: &str, out: &Path) -> Result<()> {
    use std::process::Command;

    let tmp = std::env::temp_dir().join(format!("tensorhawk-report-{}.html", std::process::id()));
    std::fs::write(&tmp, html).with_context(|| format!("writing temp HTML {}", tmp.display()))?;
    let tmp_in = tmp.display().to_string();
    let out_s = out.display().to_string();
    let tmp_url = format!("file://{tmp_in}");

    let attempts: &[(&str, Vec<String>)] = &[
        ("weasyprint", vec![tmp_in.clone(), out_s.clone()]),
        (
            "wkhtmltopdf",
            vec![
                "--enable-local-file-access".into(),
                tmp_in.clone(),
                out_s.clone(),
            ],
        ),
        ("chromium", chromium_args(&tmp_url, &out_s)),
        ("chromium-browser", chromium_args(&tmp_url, &out_s)),
        ("google-chrome", chromium_args(&tmp_url, &out_s)),
        ("google-chrome-stable", chromium_args(&tmp_url, &out_s)),
    ];

    let mut tried: Vec<&str> = Vec::new();
    for (bin, args) in attempts {
        if which(bin).is_none() {
            continue;
        }
        tried.push(bin);
        match Command::new(bin).args(args).output() {
            Ok(o) if o.status.success() && out.exists() => {
                let _ = std::fs::remove_file(&tmp);
                return Ok(());
            }
            Ok(o) => eprintln!(
                "tensorhawk: {bin} could not produce the PDF: {}",
                String::from_utf8_lossy(&o.stderr).trim()
            ),
            Err(e) => eprintln!("tensorhawk: failed to run {bin}: {e}"),
        }
    }
    let _ = std::fs::remove_file(&tmp);

    if tried.is_empty() {
        anyhow::bail!(
            "no HTML→PDF converter found (looked for weasyprint, wkhtmltopdf, \
             chromium/chrome on PATH). Install one, or use `--format html` and print to \
             PDF from a browser."
        );
    }
    anyhow::bail!(
        "the available converter(s) [{}] failed to produce the PDF (see messages above)",
        tried.join(", ")
    );
}

/// Headless-Chromium argv for printing a local HTML URL to a PDF. `--no-pdf-
/// header-footer` suppresses Chrome's own date/URL banner (the document carries
/// its own branded header/footer).
fn chromium_args(url: &str, out: &str) -> Vec<String> {
    vec![
        "--headless".into(),
        "--disable-gpu".into(),
        "--no-sandbox".into(),
        "--no-pdf-header-footer".into(),
        format!("--print-to-pdf={out}"),
        url.to_string(),
    ]
}

/// Locate an executable on `PATH` (no external crate).
fn which(bin: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths).find_map(|dir| {
            let p = dir.join(bin);
            p.is_file().then_some(p)
        })
    })
}

/// Current UTC time as `YYYY-MM-DD HH:MM:SS UTC`, computed from the Unix epoch
/// without a date-handling dependency.
fn now_utc_string() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02} {h:02}:{mi:02}:{s:02} UTC")
}

/// Convert a count of days since the Unix epoch to a `(year, month, day)` civil
/// date (Howard Hinnant's `civil_from_days`, proleptic Gregorian).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32; // [1, 12]
    (y + if m <= 2 { 1 } else { 0 }, m, d)
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
