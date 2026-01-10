//! Script analysis for inline code execution (php -r, python -c, etc.)
//!
//! Each language has its own module that checks if inline scripts are read-only.

pub mod php;
pub mod python;
