//! Conformance tests against the zmux specification assets vendored in
//! `testdata/spec`, copied unchanged from the specification.

// Test helpers are shared between modules with plain `pub`.
#![allow(unreachable_pub)]

mod corpus;
mod examples;
mod manifest;
mod model;
mod registry;
mod robustness;
mod runner;
mod support;
mod traces;
mod wire;
