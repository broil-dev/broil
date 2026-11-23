// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0
//! Alias-command tokenization.
//!
//! A hand-rolled POSIX-style lexical tokenizer that honors quotes and
//! backslash escaping and performs zero shell expansion. It is used by
//! config validation at load time and reused for alias expansion at
//! invocation time.

use std::fmt;

/// A tokenization failure. Config validation maps this to a config
/// validation error (exit `1`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenizeError {
    /// A single quote is never closed.
    UnterminatedSingleQuote,
    /// A double quote is never closed.
    UnterminatedDoubleQuote,
    /// The input ends immediately after an active backslash.
    TrailingBackslash,
}

impl fmt::Display for TokenizeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            TokenizeError::UnterminatedSingleQuote => "unterminated single quote",
            TokenizeError::UnterminatedDoubleQuote => "unterminated double quote",
            TokenizeError::TrailingBackslash => "trailing backslash",
        };
        f.write_str(text)
    }
}

impl std::error::Error for TokenizeError {}

/// Tokenize an alias command string.
///
/// * Separators outside quotes are space, tab, and newline only; carriage
///   return is an ordinary character.
/// * An unescaped backslash immediately followed by a newline, when
///   unquoted or inside double quotes, is removed as a line continuation.
///   Inside single quotes both characters are literal.
/// * A newline not consumed by line continuation separates tokens outside
///   quotes and is literal token content inside quotes; it never separates
///   commands.
/// * `#` and the characters `|`, `&`, `;`, `<`, `>`, `(`, and `)` are
///   ordinary literal characters.
/// * Single quotes preserve everything literally until the closing quote.
/// * Inside double quotes a backslash is special only before `$`, `` ` ``,
///   `"`, `\`, and newline.
/// * An unquoted backslash makes the next character literal.
/// * No expansion of any kind is performed.
///
/// Whitespace-only input yields an empty token list; rejecting empty token
/// lists is schema validation's job.
pub fn tokenize_alias_command(input: &str) -> Result<Vec<String>, TokenizeError> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut has_token = false;
    let mut chars = input.chars();

    while let Some(c) = chars.next() {
        match c {
            ' ' | '\t' | '\n' => {
                if has_token {
                    tokens.push(std::mem::take(&mut current));
                    has_token = false;
                }
            }
            '\'' => {
                has_token = true;
                loop {
                    match chars.next() {
                        Some('\'') => break,
                        Some(inner) => current.push(inner),
                        None => return Err(TokenizeError::UnterminatedSingleQuote),
                    }
                }
            }
            '"' => {
                has_token = true;
                loop {
                    match chars.next() {
                        Some('"') => break,
                        Some('\\') => match chars.next() {
                            Some('\n') => {}
                            Some(special @ ('$' | '`' | '"' | '\\')) => current.push(special),
                            Some(other) => {
                                current.push('\\');
                                current.push(other);
                            }
                            None => return Err(TokenizeError::TrailingBackslash),
                        },
                        Some(inner) => current.push(inner),
                        None => return Err(TokenizeError::UnterminatedDoubleQuote),
                    }
                }
            }
            '\\' => match chars.next() {
                Some('\n') => {}
                Some(escaped) => {
                    has_token = true;
                    current.push(escaped);
                }
                None => return Err(TokenizeError::TrailingBackslash),
            },
            other => {
                has_token = true;
                current.push(other);
            }
        }
    }

    if has_token {
        tokens.push(current);
    }
    Ok(tokens)
}
