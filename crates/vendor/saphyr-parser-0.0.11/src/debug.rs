//! Broil modification: disable content-bearing debug output in the hardened source.
//! See docs/provenance/saphyr-parser-0.0.11.md for upstream and patch provenance.

/// Deliberately emits nothing, including when `debug_prints` is enabled.
macro_rules! debug_print {
    ($($arg:tt)*) => {{}};
}
