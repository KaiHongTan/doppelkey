//! Minimal .env parser that records byte offsets, so values can be replaced (and restored by
//! `eject`) without touching any other byte of the file.

#[derive(Debug, Clone, PartialEq)]
pub struct Var {
    pub name: String,
    /// The value text exactly as written between any quotes.
    pub value: String,
    /// Byte range of `value` within the file.
    pub start: usize,
    pub end: usize,
    pub quote: Option<char>,
    pub line: usize,
}

pub fn parse(text: &str) -> Vec<Var> {
    let mut out = Vec::new();
    let mut offset = 0;
    for (lineno, raw) in text.split_inclusive('\n').enumerate() {
        let line_start = offset;
        offset += raw.len();
        let line = raw.trim_end_matches(['\n', '\r']);
        let mut i = line.len() - line.trim_start().len();
        let rest = &line[i..];
        if rest.is_empty() || rest.starts_with('#') {
            continue;
        }
        if let Some(r) = rest.strip_prefix("export ") {
            i += rest.len() - r.len();
            i += r.len() - r.trim_start().len();
        }
        let name_len = line[i..]
            .bytes()
            .take_while(|b| b.is_ascii_alphanumeric() || *b == b'_' || *b == b'.' || *b == b'-')
            .count();
        if name_len == 0 || line.as_bytes()[i].is_ascii_digit() {
            continue;
        }
        let name = &line[i..i + name_len];
        i += name_len;
        while line[i..].starts_with([' ', '\t']) {
            i += 1;
        }
        if !line[i..].starts_with('=') {
            continue;
        }
        i += 1;
        while line[i..].starts_with([' ', '\t']) {
            i += 1;
        }
        let (vs, ve, quote) = match line[i..].chars().next() {
            Some(q @ ('"' | '\'' | '`')) => {
                let body = &line[i + 1..];
                let mut close = None;
                let mut esc = false;
                for (j, c) in body.char_indices() {
                    if esc {
                        esc = false;
                        continue;
                    }
                    if c == '\\' && q == '"' {
                        esc = true;
                        continue;
                    }
                    if c == q {
                        close = Some(j);
                        break;
                    }
                }
                match close {
                    Some(j) => (i + 1, i + 1 + j, Some(q)),
                    None => continue, // multi-line or unterminated: not supported, leave alone
                }
            }
            _ => {
                let v = &line[i..];
                let cut = v.find(" #").or_else(|| v.find("\t#")).unwrap_or(v.len());
                let trimmed = v[..cut].trim_end();
                (i, i + trimmed.len(), None)
            }
        };
        out.push(Var {
            name: name.to_string(),
            value: line[vs..ve].to_string(),
            start: line_start + vs,
            end: line_start + ve,
            quote,
            line: lineno + 1,
        });
    }
    out
}

/// Replace byte ranges (non-overlapping) with new text.
pub fn splice(text: &str, mut edits: Vec<(usize, usize, String)>) -> String {
    edits.sort_by_key(|e| std::cmp::Reverse(e.0));
    let mut s = text.to_string();
    for (a, b, t) in edits {
        s.replace_range(a..b, &t);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_common_shapes() {
        let t = "# c\nA=1\nexport B = \"two words\" # note\nC='x y'\nD=plain # comment\n  E=\nF=\"unterminated\nG=x=y\n";
        let v = parse(t);
        let names: Vec<_> = v
            .iter()
            .map(|x| (x.name.as_str(), x.value.as_str()))
            .collect();
        assert_eq!(
            names,
            vec![
                ("A", "1"),
                ("B", "two words"),
                ("C", "x y"),
                ("D", "plain"),
                ("E", ""),
                ("G", "x=y")
            ]
        );
        for x in &v {
            assert_eq!(&t[x.start..x.end], x.value);
        }
        let edited = splice(t, vec![(v[1].start, v[1].end, "Z".into())]);
        assert!(edited.contains("export B = \"Z\" # note"));
    }
}
