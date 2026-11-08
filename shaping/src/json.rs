//! Strict JSON: duplicate member names anywhere are an error, and integers keep their
//! exact value, so that the configuration's error classes do not depend on a float.

use std::collections::HashSet;

use crate::error::{Error, err};

/// A parsed JSON value.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Json {
    Null,
    Bool(bool),
    /// An integer, saturated to the bounds of `i128`.
    Int(i128),
    /// A number with a fraction or an exponent: never an integer.
    Float,
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Json {
    pub(crate) fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(m) => m
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v)
                .filter(|v| !matches!(v, Json::Null)),
            _ => None,
        }
    }
}

/// The nesting a document may have, which bounds the parser's stack.
const MAX_DEPTH: usize = 512;

pub(crate) fn parse(b: &[u8]) -> Result<Json, Error> {
    let text = std::str::from_utf8(b).map_err(|_| syntax("not UTF-8"))?;
    let mut p = Parser {
        b: text.as_bytes(),
        i: 0,
    };
    p.ws();
    let v = p.value(0)?;
    p.ws();
    if p.i != p.b.len() {
        return Err(syntax("bytes after the document"));
    }
    Ok(v)
}

fn syntax(m: &str) -> Error {
    err("syntax", m)
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}

impl Parser<'_> {
    fn ws(&mut self) {
        while matches!(self.b.get(self.i), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }

    fn eat(&mut self, c: u8) -> bool {
        let hit = self.b.get(self.i) == Some(&c);
        self.i += usize::from(hit);
        hit
    }

    fn word(&mut self, w: &str, v: Json) -> Result<Json, Error> {
        if self.b[self.i..].starts_with(w.as_bytes()) {
            self.i += w.len();
            Ok(v)
        } else {
            Err(syntax("unknown token"))
        }
    }

    fn value(&mut self, depth: usize) -> Result<Json, Error> {
        if depth > MAX_DEPTH {
            return Err(syntax("nested too deep"));
        }
        match self.b.get(self.i) {
            Some(b'{') => self.object(depth),
            Some(b'[') => self.array(depth),
            Some(b'"') => self.string().map(Json::Str),
            Some(b't') => self.word("true", Json::Bool(true)),
            Some(b'f') => self.word("false", Json::Bool(false)),
            Some(b'n') => self.word("null", Json::Null),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err(syntax("expected a value")),
        }
    }

    fn object(&mut self, depth: usize) -> Result<Json, Error> {
        self.i += 1;
        let mut members: Vec<(String, Json)> = Vec::new();
        let mut names = HashSet::new();
        self.ws();
        if self.eat(b'}') {
            return Ok(Json::Obj(members));
        }
        loop {
            self.ws();
            let key = self.string()?;
            self.ws();
            if !self.eat(b':') {
                return Err(syntax("expected a colon"));
            }
            self.ws();
            let v = self.value(depth + 1)?;
            if !names.insert(key.clone()) {
                return Err(err("duplicate_key", key));
            }
            members.push((key, v));
            self.ws();
            if self.eat(b',') {
                continue;
            }
            if self.eat(b'}') {
                return Ok(Json::Obj(members));
            }
            return Err(syntax("expected a comma or a brace"));
        }
    }

    fn array(&mut self, depth: usize) -> Result<Json, Error> {
        self.i += 1;
        let mut items = Vec::new();
        self.ws();
        if self.eat(b']') {
            return Ok(Json::Arr(items));
        }
        loop {
            self.ws();
            items.push(self.value(depth + 1)?);
            self.ws();
            if self.eat(b',') {
                continue;
            }
            if self.eat(b']') {
                return Ok(Json::Arr(items));
            }
            return Err(syntax("expected a comma or a bracket"));
        }
    }

    fn hex4(&mut self) -> Result<u32, Error> {
        let h = self.b.get(self.i..self.i + 4).ok_or(syntax("cut escape"))?;
        let h = std::str::from_utf8(h).map_err(|_| syntax("bad escape"))?;
        if !h.bytes().all(|c| c.is_ascii_hexdigit()) {
            return Err(syntax("bad escape"));
        }
        self.i += 4;
        u32::from_str_radix(h, 16).map_err(|_| syntax("bad escape"))
    }

    fn string(&mut self) -> Result<String, Error> {
        if !self.eat(b'"') {
            return Err(syntax("expected a string"));
        }
        let mut out: Vec<u8> = Vec::new();
        loop {
            let c = *self.b.get(self.i).ok_or(syntax("cut string"))?;
            self.i += 1;
            match c {
                b'"' => return String::from_utf8(out).map_err(|_| syntax("bad string")),
                0..=0x1f => return Err(syntax("control character in a string")),
                b'\\' => {
                    let e = *self.b.get(self.i).ok_or(syntax("cut escape"))?;
                    self.i += 1;
                    let ch = match e {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => self.unicode()?,
                        _ => return Err(syntax("bad escape")),
                    };
                    let mut buf = [0; 4];
                    out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                }
                c => out.push(c),
            }
        }
    }

    /// A `\u` escape; a lone surrogate reads as U+FFFD, as no name holds one.
    fn unicode(&mut self) -> Result<char, Error> {
        let hi = self.hex4()?;
        if (0xd800..0xdc00).contains(&hi) && self.b[self.i..].starts_with(b"\\u") {
            let at = self.i;
            self.i += 2;
            let lo = self.hex4()?;
            if (0xdc00..0xe000).contains(&lo) {
                let c = 0x10000 + ((hi - 0xd800) << 10) + (lo - 0xdc00);
                return Ok(char::from_u32(c).unwrap_or('\u{fffd}'));
            }
            self.i = at;
        }
        Ok(char::from_u32(hi).unwrap_or('\u{fffd}'))
    }

    fn digits(&mut self) -> usize {
        let at = self.i;
        while matches!(self.b.get(self.i), Some(b'0'..=b'9')) {
            self.i += 1;
        }
        self.i - at
    }

    fn number(&mut self) -> Result<Json, Error> {
        let negative = self.eat(b'-');
        let start = self.i;
        let n = self.digits();
        if n == 0 || (n > 1 && self.b[start] == b'0') {
            return Err(syntax("bad number"));
        }
        let end = self.i;
        let mut float = false;
        if self.eat(b'.') {
            float = true;
            if self.digits() == 0 {
                return Err(syntax("bad number"));
            }
        }
        if matches!(self.b.get(self.i), Some(b'e' | b'E')) {
            self.i += 1;
            float = true;
            if !self.eat(b'+') {
                self.eat(b'-');
            }
            if self.digits() == 0 {
                return Err(syntax("bad number"));
            }
        }
        if float {
            return Ok(Json::Float);
        }
        let mut v: i128 = 0;
        for &d in &self.b[start..end] {
            v = v.saturating_mul(10).saturating_add(i128::from(d - b'0'));
        }
        Ok(Json::Int(if negative { -v } else { v }))
    }
}
