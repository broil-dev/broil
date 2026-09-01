// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenizeError {
    UnterminatedSingleQuote,
    UnterminatedDoubleQuote,
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
