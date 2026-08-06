//! Hand-written lexer + recursive-descent / Pratt parser for the `MODEL_RULE`
//! declarative rule language (see `docs/ARCHITECTURE.md`).
//!
//! The grammar (abbreviated EBNF):
//! ```text
//! rule      = "MODEL_RULE" ident "{" meta target (strings)? condition "}" ;
//! meta      = "meta:" (ident "=" literal)+ ;
//! target    = "target:" ident ("," ident)* ;
//! strings   = "strings:" (var "=" (regex | string))+ ;
//! condition = "condition:" expr ;
//! expr      = term (("and"|"or") term)* ;
//! term      = var | "import" "(" string ")" | "opcode" "(" ident ")"
//!           | "op" "(" string ")" | "(" expr ")" | "not" term ;
//! ```

use super::{Expr, Rule, StringDef, Target};
use crate::finding::Severity;
use regex::bytes::Regex;

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Ident(String),
    Var(String),   // $name
    Str(String),   // "..."
    Regex(String), // /.../
    Num(f32),
    LBrace,
    RBrace,
    LParen,
    RParen,
    Colon,
    Comma,
    Eq,
}

struct Lexer<'a> {
    s: &'a [u8],
    i: usize,
}

impl<'a> Lexer<'a> {
    fn new(s: &'a str) -> Self {
        Lexer { s: s.as_bytes(), i: 0 }
    }

    fn tokenize(mut self) -> Result<Vec<Tok>, String> {
        let mut out = Vec::new();
        while self.i < self.s.len() {
            let c = self.s[self.i];
            match c {
                b' ' | b'\t' | b'\r' | b'\n' => self.i += 1,
                b'#' => {
                    // comment to end of line
                    while self.i < self.s.len() && self.s[self.i] != b'\n' {
                        self.i += 1;
                    }
                }
                b'{' => self.push(&mut out, Tok::LBrace),
                b'}' => self.push(&mut out, Tok::RBrace),
                b'(' => self.push(&mut out, Tok::LParen),
                b')' => self.push(&mut out, Tok::RParen),
                b':' => self.push(&mut out, Tok::Colon),
                b',' => self.push(&mut out, Tok::Comma),
                b'=' => self.push(&mut out, Tok::Eq),
                b'"' => out.push(self.string()?),
                b'/' => out.push(self.regex()?),
                b'$' => out.push(self.var()),
                _ if c.is_ascii_digit() || (c == b'-' && self.peek_digit()) => {
                    out.push(self.number()?)
                }
                _ if is_ident_start(c) => out.push(self.ident()),
                _ => return Err(format!("unexpected character {:?}", c as char)),
            }
        }
        Ok(out)
    }

    fn push(&mut self, out: &mut Vec<Tok>, t: Tok) {
        out.push(t);
        self.i += 1;
    }

    fn peek_digit(&self) -> bool {
        self.s.get(self.i + 1).is_some_and(|c| c.is_ascii_digit())
    }

    fn string(&mut self) -> Result<Tok, String> {
        self.i += 1; // opening quote
        let mut buf = String::new();
        while self.i < self.s.len() {
            let c = self.s[self.i];
            if c == b'\\' && self.i + 1 < self.s.len() {
                buf.push(self.s[self.i + 1] as char);
                self.i += 2;
            } else if c == b'"' {
                self.i += 1;
                return Ok(Tok::Str(buf));
            } else {
                buf.push(c as char);
                self.i += 1;
            }
        }
        Err("unterminated string literal".into())
    }

    fn regex(&mut self) -> Result<Tok, String> {
        self.i += 1; // opening slash
        let mut buf = String::new();
        while self.i < self.s.len() {
            let c = self.s[self.i];
            if c == b'\\' && self.i + 1 < self.s.len() {
                // keep the escape so the regex engine sees it
                buf.push('\\');
                buf.push(self.s[self.i + 1] as char);
                self.i += 2;
            } else if c == b'/' {
                self.i += 1;
                return Ok(Tok::Regex(buf));
            } else {
                buf.push(c as char);
                self.i += 1;
            }
        }
        Err("unterminated regex literal".into())
    }

    fn var(&mut self) -> Tok {
        self.i += 1; // $
        let start = self.i;
        while self.i < self.s.len() && is_ident_char(self.s[self.i]) {
            self.i += 1;
        }
        Tok::Var(String::from_utf8_lossy(&self.s[start..self.i]).into_owned())
    }

    fn ident(&mut self) -> Tok {
        let start = self.i;
        while self.i < self.s.len() && is_ident_char(self.s[self.i]) {
            self.i += 1;
        }
        Tok::Ident(String::from_utf8_lossy(&self.s[start..self.i]).into_owned())
    }

    fn number(&mut self) -> Result<Tok, String> {
        let start = self.i;
        if self.s[self.i] == b'-' {
            self.i += 1;
        }
        while self.i < self.s.len() && (self.s[self.i].is_ascii_digit() || self.s[self.i] == b'.') {
            self.i += 1;
        }
        let txt = String::from_utf8_lossy(&self.s[start..self.i]);
        txt.parse::<f32>()
            .map(Tok::Num)
            .map_err(|_| format!("invalid number {txt}"))
    }
}

fn is_ident_start(c: u8) -> bool {
    c.is_ascii_alphabetic() || c == b'_'
}
fn is_ident_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_' || c == b'.' || c == b'-'
}

struct Parser {
    toks: Vec<Tok>,
    i: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.i)
    }
    fn bump(&mut self) -> Option<Tok> {
        let t = self.toks.get(self.i).cloned();
        self.i += 1;
        t
    }
    fn expect(&mut self, want: &Tok) -> Result<(), String> {
        match self.bump() {
            Some(ref t) if t == want => Ok(()),
            other => Err(format!("expected {want:?}, found {other:?}")),
        }
    }
    fn ident(&mut self) -> Result<String, String> {
        match self.bump() {
            Some(Tok::Ident(s)) => Ok(s),
            other => Err(format!("expected identifier, found {other:?}")),
        }
    }

    fn parse_ruleset(&mut self) -> Result<Vec<Rule>, String> {
        let mut rules = Vec::new();
        while self.peek().is_some() {
            rules.push(self.parse_rule()?);
        }
        Ok(rules)
    }

    fn parse_rule(&mut self) -> Result<Rule, String> {
        match self.bump() {
            Some(Tok::Ident(k)) if k == "MODEL_RULE" => {}
            other => return Err(format!("expected MODEL_RULE, found {other:?}")),
        }
        let name = self.ident()?;
        self.expect(&Tok::LBrace)?;

        let mut rule = Rule {
            id: name.clone(),
            name,
            severity: Severity::Medium,
            confidence: 0.8,
            title: None,
            references: Vec::new(),
            remediation: None,
            targets: Vec::new(),
            strings: Vec::new(),
            condition: Expr::Bool(false),
        };
        let mut have_condition = false;

        while self.peek() != Some(&Tok::RBrace) {
            let section = self.ident()?;
            self.expect(&Tok::Colon)?;
            match section.as_str() {
                "meta" => self.parse_meta(&mut rule)?,
                "target" => rule.targets = self.parse_targets()?,
                "strings" => rule.strings = self.parse_strings()?,
                "condition" => {
                    rule.condition = self.parse_expr(0)?;
                    have_condition = true;
                }
                other => return Err(format!("unknown section `{other}`")),
            }
        }
        self.expect(&Tok::RBrace)?;

        if rule.targets.is_empty() {
            return Err(format!("rule `{}` has no target", rule.name));
        }
        if !have_condition {
            return Err(format!("rule `{}` has no condition", rule.name));
        }
        Ok(rule)
    }

    fn parse_meta(&mut self, rule: &mut Rule) -> Result<(), String> {
        // key = literal, repeated until the next section keyword or `}`.
        while let Some(Tok::Ident(_)) = self.peek() {
            if self.is_section_ahead() {
                break;
            }
            let key = self.ident()?;
            self.expect(&Tok::Eq)?;
            match key.as_str() {
                "id" => rule.id = self.literal_string()?,
                "title" => rule.title = Some(self.literal_string()?),
                "severity" => rule.severity = parse_severity(&self.literal_string()?)?,
                "confidence" => rule.confidence = self.literal_num()?.clamp(0.0, 1.0),
                "reference" => rule.references.push(self.literal_string()?),
                "remediation" => rule.remediation = Some(self.literal_string()?),
                _ => {
                    // tolerate unknown meta keys (forward-compat)
                    let _ = self.bump();
                }
            }
        }
        Ok(())
    }

    /// True if the upcoming `ident :` is a section header, so `meta` stops.
    fn is_section_ahead(&self) -> bool {
        matches!(self.toks.get(self.i), Some(Tok::Ident(k))
            if matches!(k.as_str(), "meta" | "target" | "strings" | "condition"))
            && self.toks.get(self.i + 1) == Some(&Tok::Colon)
    }

    fn literal_string(&mut self) -> Result<String, String> {
        match self.bump() {
            Some(Tok::Str(s)) => Ok(s),
            Some(Tok::Ident(s)) => Ok(s),
            other => Err(format!("expected string literal, found {other:?}")),
        }
    }
    fn literal_num(&mut self) -> Result<f32, String> {
        match self.bump() {
            Some(Tok::Num(n)) => Ok(n),
            other => Err(format!("expected number, found {other:?}")),
        }
    }

    fn parse_targets(&mut self) -> Result<Vec<Target>, String> {
        let mut targets = vec![parse_target(&self.ident()?)?];
        while self.peek() == Some(&Tok::Comma) {
            self.bump();
            targets.push(parse_target(&self.ident()?)?);
        }
        Ok(targets)
    }

    fn parse_strings(&mut self) -> Result<Vec<StringDef>, String> {
        let mut defs = Vec::new();
        while let Some(Tok::Var(_)) = self.peek() {
            let name = match self.bump() {
                Some(Tok::Var(n)) => n,
                _ => unreachable!(),
            };
            self.expect(&Tok::Eq)?;
            // A regex literal is used verbatim; a plain string is matched
            // literally (escaped into an equivalent regex).
            let pattern = match self.bump() {
                Some(Tok::Regex(r)) => r,
                Some(Tok::Str(s)) => regex::escape(&s),
                other => return Err(format!("expected regex or string, found {other:?}")),
            };
            let re =
                Regex::new(&pattern).map_err(|e| format!("invalid regex for ${name}: {e}"))?;
            defs.push(StringDef { name, re });
        }
        Ok(defs)
    }

    /// Pratt-style expression parser. `and` binds tighter than `or`.
    fn parse_expr(&mut self, min_bp: u8) -> Result<Expr, String> {
        let mut lhs = self.parse_term()?;
        while let Some(Tok::Ident(op)) = self.peek() {
            let (lbp, rbp) = match op.as_str() {
                "or" => (1, 2),
                "and" => (3, 4),
                _ => break,
            };
            if lbp < min_bp {
                break;
            }
            let op = op.clone();
            self.bump();
            let rhs = self.parse_expr(rbp)?;
            lhs = match op.as_str() {
                "or" => Expr::Or(Box::new(lhs), Box::new(rhs)),
                _ => Expr::And(Box::new(lhs), Box::new(rhs)),
            };
        }
        Ok(lhs)
    }

    fn parse_term(&mut self) -> Result<Expr, String> {
        match self.bump() {
            Some(Tok::Var(v)) => Ok(Expr::Var(v)),
            Some(Tok::LParen) => {
                let e = self.parse_expr(0)?;
                self.expect(&Tok::RParen)?;
                Ok(e)
            }
            Some(Tok::Ident(k)) => match k.as_str() {
                "not" => Ok(Expr::Not(Box::new(self.parse_term()?))),
                "true" => Ok(Expr::Bool(true)),
                "false" => Ok(Expr::Bool(false)),
                "import" | "opcode" | "op" => {
                    self.expect(&Tok::LParen)?;
                    let arg = self.literal_string()?;
                    self.expect(&Tok::RParen)?;
                    Ok(match k.as_str() {
                        "import" => Expr::Import(arg),
                        "opcode" => Expr::Opcode(arg.to_ascii_uppercase()),
                        _ => Expr::Op(arg),
                    })
                }
                other => Err(format!("unexpected identifier `{other}` in condition")),
            },
            other => Err(format!("unexpected token {other:?} in condition")),
        }
    }
}

fn parse_severity(s: &str) -> Result<Severity, String> {
    Ok(match s.to_ascii_lowercase().as_str() {
        "info" => Severity::Info,
        "low" => Severity::Low,
        "medium" => Severity::Medium,
        "high" => Severity::High,
        "critical" => Severity::Critical,
        other => return Err(format!("unknown severity `{other}`")),
    })
}

fn parse_target(s: &str) -> Result<Target, String> {
    Ok(match s.to_ascii_lowercase().as_str() {
        "metadata" => Target::Metadata,
        "raw" => Target::Raw,
        "pickle" => Target::Pickle,
        "operators" | "operator" | "ops" => Target::Operators,
        other => return Err(format!("unknown target `{other}`")),
    })
}

/// Parse a full rule pack from source text.
pub fn parse_rules(src: &str) -> Result<Vec<Rule>, String> {
    let toks = Lexer::new(src).tokenize()?;
    let mut p = Parser { toks, i: 0 };
    p.parse_ruleset()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_secret_rule() {
        let src = r#"
            MODEL_RULE aws_key {
                meta:
                    id = "THK-SEC-001"
                    severity = critical
                    confidence = 0.95
                target:
                    metadata, raw
                strings:
                    $k = /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/
                condition:
                    $k
            }
        "#;
        let rules = parse_rules(src).expect("parse");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "THK-SEC-001");
        assert_eq!(rules[0].severity, Severity::Critical);
        assert_eq!(rules[0].targets.len(), 2);
    }

    #[test]
    fn parses_boolean_pickle_condition() {
        let src = r#"
            MODEL_RULE pickle_rce {
                meta: id = "THK-PKL-001" severity = critical
                target: pickle
                condition: import("os.system") or (import("subprocess") and opcode(REDUCE))
            }
        "#;
        let rules = parse_rules(src).expect("parse");
        assert!(matches!(rules[0].condition, Expr::Or(_, _)));
    }

    #[test]
    fn rejects_missing_condition() {
        let src = "MODEL_RULE bad { target: raw }";
        assert!(parse_rules(src).is_err());
    }

    /// The rule parser consumes untrusted rule packs, so it must return an error
    /// rather than panic on arbitrary text. Fuzz it with random ASCII.
    #[test]
    fn parser_never_panics_on_random_input() {
        let mut state = 0x0bad_c0de_dead_beefu64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let alphabet = b"MODEL_RULE {}()=/:,$\"abc123 \nand or not import op opcode metadata raw pickle";
        for _ in 0..2000 {
            let len = (next() % 200) as usize;
            let s: String = (0..len)
                .map(|_| alphabet[(next() as usize) % alphabet.len()] as char)
                .collect();
            let _ = parse_rules(&s); // may Ok or Err, must not panic
        }
    }
}
