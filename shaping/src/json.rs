//! Strict JSON reading of configuration documents.
//!
//! A document is first read into a [`serde_json::Value`], rejecting
//! duplicate member names, numbers outside binary64 and anything that is
//! not JSON. It is then deserialized through [`Strict`], which treats a
//! `null` member as absent, accepts only JSON integers (no fraction or
//! exponent) for integer fields and only objects for structs.

use serde::de::{self, DeserializeOwned, IntoDeserializer, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Number, Value};

use crate::def::{Error, err};

/// Reads `b` strictly as a `T`; errors are prefixed with `what`.
pub(crate) fn from_slice<T: DeserializeOwned>(what: &str, b: &[u8]) -> Result<T, Error> {
    let v = parse(b).map_err(|e| err(format!("{what}: {e}")))?;
    T::deserialize(Strict(&v)).map_err(|e| err(format!("{what}: {e}")))
}

fn parse(b: &[u8]) -> Result<Value, String> {
    serde_json::from_slice::<Doc>(b).map(|d| d.0).map_err(|e| {
        let s = e.to_string();
        if s.contains("number out of range") {
            format!("number overflows binary64 ({s})")
        } else if e.is_data() {
            s
        } else {
            format!("parse error: {s}")
        }
    })
}

/// A JSON value read without duplicate member names.
struct Doc(Value);

impl<'de> Deserialize<'de> for Doc {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(DocVisitor).map(Doc)
    }
}

struct DocVisitor;

impl<'de> Visitor<'de> for DocVisitor {
    type Value = Value;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_bool<E>(self, x: bool) -> Result<Value, E> {
        Ok(Value::Bool(x))
    }

    fn visit_i64<E>(self, x: i64) -> Result<Value, E> {
        Ok(Value::Number(x.into()))
    }

    fn visit_u64<E>(self, x: u64) -> Result<Value, E> {
        Ok(Value::Number(x.into()))
    }

    fn visit_f64<E: de::Error>(self, x: f64) -> Result<Value, E> {
        Number::from_f64(x)
            .map(Value::Number)
            .ok_or_else(|| E::custom("number overflows binary64"))
    }

    fn visit_str<E>(self, s: &str) -> Result<Value, E> {
        Ok(Value::String(s.to_owned()))
    }

    fn visit_string<E>(self, s: String) -> Result<Value, E> {
        Ok(Value::String(s))
    }

    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_none<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A: de::SeqAccess<'de>>(self, mut a: A) -> Result<Value, A::Error> {
        let mut v = Vec::new();
        while let Some(Doc(x)) = a.next_element()? {
            v.push(x);
        }
        Ok(Value::Array(v))
    }

    fn visit_map<A: de::MapAccess<'de>>(self, mut a: A) -> Result<Value, A::Error> {
        let mut m = Map::new();
        while let Some(k) = a.next_key::<String>()? {
            if m.contains_key(&k) {
                return Err(de::Error::custom(format!("duplicate member `{k}`")));
            }
            let Doc(v) = a.next_value()?;
            m.insert(k, v);
        }
        Ok(Value::Object(m))
    }
}

/// A deserializer over a read document; see the module documentation.
struct Strict<'a>(&'a Value);

type E = serde_json::Error;

impl Strict<'_> {
    fn integer<'de, V: Visitor<'de>>(self, v: V) -> Result<V::Value, E> {
        match self.0 {
            Value::Number(n) if n.is_u64() => v.visit_u64(n.as_u64().unwrap_or_default()),
            Value::Number(n) if n.is_i64() => v.visit_i64(n.as_i64().unwrap_or_default()),
            Value::Number(n) => Err(de::Error::custom(format!(
                "{n}: expected a JSON integer (no fraction or exponent)"
            ))),
            _ => self.deserialize_any(v),
        }
    }

    fn unsigned<'de, V: Visitor<'de>>(self, v: V) -> Result<V::Value, E> {
        match self.0 {
            Value::Number(n) if n.as_i64().is_some_and(|x| x < 0) => Err(de::Error::custom(
                format!("{n}: negative, expected a non-negative integer"),
            )),
            _ => self.integer(v),
        }
    }
}

macro_rules! integers {
    ($how:ident: $($f:ident)*) => {$(
        fn $f<V: Visitor<'de>>(self, v: V) -> Result<V::Value, E> {
            self.$how(v)
        }
    )*};
}

impl<'de> Deserializer<'de> for Strict<'_> {
    type Error = E;

    fn deserialize_any<V: Visitor<'de>>(self, v: V) -> Result<V::Value, E> {
        match self.0 {
            Value::Null => v.visit_unit(),
            Value::Bool(b) => v.visit_bool(*b),
            Value::Number(n) => {
                if let Some(x) = n.as_u64() {
                    v.visit_u64(x)
                } else if let Some(x) = n.as_i64() {
                    v.visit_i64(x)
                } else {
                    v.visit_f64(n.as_f64().unwrap_or(f64::NAN))
                }
            }
            Value::String(s) => v.visit_str(s),
            Value::Array(a) => v.visit_seq(Seq(a.iter())),
            Value::Object(m) => v.visit_map(Members {
                it: m.iter(),
                value: None,
            }),
        }
    }

    integers!(unsigned: deserialize_u8 deserialize_u16 deserialize_u32 deserialize_u64 deserialize_u128);
    integers!(integer: deserialize_i8 deserialize_i16 deserialize_i32 deserialize_i64 deserialize_i128);

    fn deserialize_option<V: Visitor<'de>>(self, v: V) -> Result<V::Value, E> {
        match self.0 {
            Value::Null => v.visit_none(),
            _ => v.visit_some(self),
        }
    }

    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        _: &'static str,
        v: V,
    ) -> Result<V::Value, E> {
        v.visit_newtype_struct(self)
    }

    fn deserialize_struct<V: Visitor<'de>>(
        self,
        _: &'static str,
        _: &'static [&'static str],
        v: V,
    ) -> Result<V::Value, E> {
        self.deserialize_map(v)
    }

    fn deserialize_map<V: Visitor<'de>>(self, v: V) -> Result<V::Value, E> {
        match self.0 {
            Value::Object(_) => self.deserialize_any(v),
            x => Err(de::Error::custom(format!(
                "expected a JSON object, found {}",
                kind(x)
            ))),
        }
    }

    fn deserialize_enum<V: Visitor<'de>>(
        self,
        _: &'static str,
        _: &'static [&'static str],
        v: V,
    ) -> Result<V::Value, E> {
        match self.0 {
            Value::String(s) => v.visit_enum(s.as_str().into_deserializer()),
            x => Err(de::Error::custom(format!(
                "expected a string, found {}",
                kind(x)
            ))),
        }
    }

    serde::forward_to_deserialize_any! {
        bool f32 f64 char str string bytes byte_buf unit unit_struct seq tuple
        tuple_struct identifier ignored_any
    }
}

fn kind(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "an array",
        Value::Object(_) => "an object",
    }
}

struct Seq<'a>(std::slice::Iter<'a, Value>);

impl<'de> de::SeqAccess<'de> for Seq<'_> {
    type Error = E;

    fn next_element_seed<T: de::DeserializeSeed<'de>>(
        &mut self,
        seed: T,
    ) -> Result<Option<T::Value>, E> {
        self.0
            .next()
            .map(|x| seed.deserialize(Strict(x)))
            .transpose()
    }
}

/// The members of an object; a `null` member is skipped, as absent.
struct Members<'a> {
    it: serde_json::map::Iter<'a>,
    value: Option<&'a Value>,
}

impl<'de> de::MapAccess<'de> for Members<'_> {
    type Error = E;

    fn next_key_seed<K: de::DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> Result<Option<K::Value>, E> {
        for (k, v) in self.it.by_ref() {
            if !v.is_null() {
                self.value = Some(v);
                return seed.deserialize(k.as_str().into_deserializer()).map(Some);
            }
        }
        Ok(None)
    }

    fn next_value_seed<T: de::DeserializeSeed<'de>>(&mut self, seed: T) -> Result<T::Value, E> {
        seed.deserialize(Strict(self.value.take().unwrap_or(&Value::Null)))
    }
}
