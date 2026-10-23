//! The declarative `MODEL_RULE` engine.
//!
//! Detections ship as *data*, not code: a rule pack is parsed into [`Rule`]s,
//! compiled into a [`RuleScanner`] that implements the same [`Scanner`] trait as
//! the built-ins, and evaluated as a pure function of the artifact. A bundled
//! reference pack ([`builtin_rules`]) is embedded in the binary; users can layer
//! additional packs from disk with [`load_dir`].

mod parse;

pub use parse::parse_rules;

use crate::artifact::Artifact;
use crate::finding::{redact, Finding, Location, Severity};
use crate::scanners::{pickle, Scanner};
use regex::bytes::Regex;
use std::path::Path;

/// Where a rule looks for evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// Container metadata key/value strings.
    Metadata,
    /// The raw mapped bytes of the whole artifact.
    Raw,
    /// Imports/opcodes of embedded pickle streams.
    Pickle,
    /// ONNX / TensorFlow graph operator names.
    Operators,
}

/// A named regular expression usable from a rule condition as `$name`.
pub struct StringDef {
    pub name: String,
    pub re: Regex,
}

/// A boolean condition over an artifact.
pub enum Expr {
    Bool(bool),
    /// `$name` — the named string matched somewhere in a targeted scope.
    Var(String),
    /// `import("module.name")` — a pickle import whose `module.name` starts with
    /// the argument (trailing-dot / prefix semantics like the built-in scanner).
    Import(String),
    /// `opcode(REDUCE)` — the pickle stream contains a REDUCE/build opcode.
    Opcode(String),
    /// `op("OpType")` — a graph operator matches (supports a trailing `*`).
    Op(String),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
}

/// One compiled rule.
pub struct Rule {
    pub id: String,
    pub name: String,
    pub severity: Severity,
    pub confidence: f32,
    pub title: Option<String>,
    pub references: Vec<String>,
    pub remediation: Option<String>,
    pub targets: Vec<Target>,
    pub strings: Vec<StringDef>,
    pub condition: Expr,
}

/// A scanner backed by a set of declarative rules.
pub struct RuleScanner {
    rules: Vec<Rule>,
    source: &'static str,
}

impl RuleScanner {
    /// Build a scanner from already-parsed rules with a source label.
    pub fn new(rules: Vec<Rule>, source: &'static str) -> Self {
        RuleScanner { rules, source }
    }

    /// Parse a rule pack from source text.
    pub fn from_source(src: &str, source: &'static str) -> Result<Self, String> {
        Ok(RuleScanner::new(parse_rules(src)?, source))
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

/// The bundled reference rule pack, compiled into the binary.
pub fn builtin_rules() -> RuleScanner {
    let src = include_str!("../../../../rules/builtin.model_rule");
    RuleScanner::from_source(src, "builtin-rules").expect("bundled rule pack must parse")
}

/// Load and merge every `*.model_rule` / `*.rule` file in a directory.
pub fn load_dir(dir: &Path) -> Result<Vec<Rule>, String> {
    let mut rules = Vec::new();
    let entries = std::fs::read_dir(dir).map_err(|e| format!("reading {}: {e}", dir.display()))?;
    let mut files: Vec<_> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            matches!(
                p.extension().and_then(|x| x.to_str()),
                Some("model_rule") | Some("rule")
            )
        })
        .collect();
    files.sort();
    for path in files {
        let src = std::fs::read_to_string(&path)
            .map_err(|e| format!("reading {}: {e}", path.display()))?;
        let parsed = parse_rules(&src).map_err(|e| format!("{}: {e}", path.display()))?;
        rules.extend(parsed);
    }
    Ok(rules)
}

impl Scanner for RuleScanner {
    fn id(&self) -> &'static str {
        self.source
    }
    fn description(&self) -> &'static str {
        "Evaluates declarative MODEL_RULE detections"
    }
    fn scan(&self, artifact: &Artifact) -> Vec<Finding> {
        let ctx = EvalContext::new(artifact);
        let mut findings = Vec::new();
        for rule in &self.rules {
            findings.extend(ctx.eval_rule(rule));
        }
        // A rule targeting both metadata and raw can hit the same value twice;
        // collapse identical (rule_id, evidence) findings.
        let mut seen = std::collections::HashSet::new();
        findings.retain(|f| seen.insert((f.rule_id.clone(), f.evidence.clone())));
        findings
    }
}

/// Per-artifact evaluation context: precomputes the pickle imports/opcodes once
/// so a pack with many pickle rules doesn't re-disassemble per rule.
struct EvalContext<'a> {
    artifact: &'a Artifact,
    pickle_imports: Vec<(String, String, String)>, // (component, module, name)
    has_reduce: bool,
    raw: &'a [u8],
}

const RAW_SCAN_CAP: usize = 256 * 1024 * 1024;

impl<'a> EvalContext<'a> {
    fn new(artifact: &'a Artifact) -> Self {
        let mut pickle_imports = Vec::new();
        let mut has_reduce = false;
        for stream in &artifact.pickles {
            let a = pickle::imported_globals(&stream.bytes);
            has_reduce |= a.has_reduce;
            for (m, n) in a.imports {
                pickle_imports.push((stream.name.clone(), m, n));
            }
        }
        let data = artifact.data();
        let raw = &data[..data.len().min(RAW_SCAN_CAP)];
        EvalContext {
            artifact,
            pickle_imports,
            has_reduce,
            raw,
        }
    }

    fn eval_rule(&self, rule: &Rule) -> Vec<Finding> {
        // For a single-atom top-level condition we emit one finding per concrete
        // match (nice granularity for string/operator rules). For any composite
        // boolean, we emit a single finding when the whole condition holds.
        let matches: Vec<Match> = match &rule.condition {
            Expr::Var(name) => self.var_matches(rule, name),
            Expr::Import(pat) => self.import_matches(pat),
            Expr::Op(pat) => self.op_matches(pat),
            other => {
                if self.eval_bool(rule, other) {
                    vec![Match {
                        component: "condition".into(),
                        evidence: None,
                    }]
                } else {
                    Vec::new()
                }
            }
        };
        matches.into_iter().map(|m| self.finding(rule, m)).collect()
    }

    fn eval_bool(&self, rule: &Rule, e: &Expr) -> bool {
        match e {
            Expr::Bool(b) => *b,
            Expr::Var(name) => !self.var_matches(rule, name).is_empty(),
            Expr::Import(pat) => !self.import_matches(pat).is_empty(),
            Expr::Op(pat) => !self.op_matches(pat).is_empty(),
            Expr::Opcode(op) => op == "REDUCE" && self.has_reduce,
            Expr::And(a, b) => self.eval_bool(rule, a) && self.eval_bool(rule, b),
            Expr::Or(a, b) => self.eval_bool(rule, a) || self.eval_bool(rule, b),
            Expr::Not(a) => !self.eval_bool(rule, a),
        }
    }

    fn var_matches(&self, rule: &Rule, name: &str) -> Vec<Match> {
        let def = match rule.strings.iter().find(|s| s.name == name) {
            Some(d) => d,
            None => return Vec::new(),
        };
        let mut out = Vec::new();
        for target in &rule.targets {
            match target {
                // Metadata/raw/pickle matches may be credentials, so evidence is
                // redacted — a rule pack must never be able to exfiltrate a full
                // secret through a report.
                Target::Metadata => {
                    for (k, v) in &self.artifact.metadata {
                        if let Some(m) = def.re.find(v.as_bytes()) {
                            out.push(Match {
                                component: format!("metadata:{k}"),
                                evidence: Some(redact_match(m.as_bytes())),
                            });
                        }
                    }
                }
                Target::Raw => {
                    for m in def.re.find_iter(self.raw).take(50) {
                        out.push(Match {
                            component: "raw".into(),
                            evidence: Some(redact_match(m.as_bytes())),
                        });
                    }
                }
                Target::Pickle => {
                    for stream in &self.artifact.pickles {
                        if let Some(m) = def.re.find(&stream.bytes) {
                            out.push(Match {
                                component: stream.name.clone(),
                                evidence: Some(redact_match(m.as_bytes())),
                            });
                        }
                    }
                }
                Target::Operators => {
                    for op in &self.artifact.graph_ops {
                        if def.re.is_match(op.as_bytes()) {
                            out.push(Match {
                                component: "operators".into(),
                                evidence: Some(op.clone()),
                            });
                        }
                    }
                }
            }
        }
        out
    }

    fn import_matches(&self, pat: &str) -> Vec<Match> {
        self.pickle_imports
            .iter()
            .filter(|(_, module, name)| import_hit(module, name, pat))
            .map(|(component, module, name)| Match {
                component: component.clone(),
                evidence: Some(format!("GLOBAL {module}.{name}")),
            })
            .collect()
    }

    fn op_matches(&self, pat: &str) -> Vec<Match> {
        self.artifact
            .graph_ops
            .iter()
            .filter(|op| op_hit(op, pat))
            .map(|op| Match {
                component: "operators".into(),
                evidence: Some(op.clone()),
            })
            .collect()
    }

    fn finding(&self, rule: &Rule, m: Match) -> Finding {
        let title = rule
            .title
            .clone()
            .unwrap_or_else(|| format!("Rule `{}` matched", rule.name));
        let mut b = Finding::builder(&rule.id, "rules", rule.severity)
            .title(title)
            .detail(format!(
                "Declarative rule `{}` matched in {}.",
                rule.name, m.component
            ))
            .confidence(rule.confidence)
            .location(Location::new(m.component));
        for r in &rule.references {
            b = b.reference(r.clone());
        }
        if let Some(rem) = &rule.remediation {
            b = b.remediation(rem.clone());
        }
        if let Some(ev) = m.evidence {
            b = b.evidence(ev);
        }
        b.build()
    }
}

struct Match {
    component: String,
    evidence: Option<String>,
}

/// Prefix/trailing-dot import matching, matching the built-in pickle scanner.
fn import_hit(module: &str, name: &str, pat: &str) -> bool {
    let full = format!("{module}.{name}");
    if let Some(prefix) = pat.strip_suffix('.') {
        module == prefix || module.starts_with(&format!("{prefix}."))
    } else if pat.contains('.') {
        full == pat || module == pat
    } else {
        module == pat
    }
}

/// Operator matching with an optional trailing `*` wildcard.
fn op_hit(op: &str, pat: &str) -> bool {
    match pat.strip_suffix('*') {
        Some(prefix) => op.starts_with(prefix),
        None => op == pat,
    }
}

/// Redact a matched byte span before it reaches a report (it may be a secret).
fn redact_match(b: &[u8]) -> String {
    redact(&String::from_utf8_lossy(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn import_matching_semantics() {
        assert!(import_hit("os", "system", "os."));
        assert!(import_hit("os", "system", "os.system"));
        assert!(import_hit("subprocess", "Popen", "subprocess."));
        assert!(!import_hit("torch", "load", "os."));
    }

    #[test]
    fn op_matching_wildcard() {
        assert!(op_hit("PyFunc", "PyFunc"));
        assert!(op_hit("com.microsoft.CustomOp", "com.microsoft.*"));
        assert!(!op_hit("Conv", "PyFunc"));
    }

    #[test]
    fn builtin_pack_parses() {
        let s = builtin_rules();
        assert!(!s.is_empty());
    }
}
