// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::Error;
use regex::{Regex, RegexBuilder};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Profile {
    Legacy,
    Current,
}
impl Profile {
    pub(super) const ALL: [Self; 2] = [Self::Legacy, Self::Current];
    pub(super) fn index(self) -> usize {
        usize::from(self == Self::Current)
    }
}

pub(super) fn compile(expression: &str, profile: Profile) -> Result<Regex, Error> {
    if expression.len() > 65536 {
        return Err(Error::SizeLimit);
    }
    let mut parser = Adapter {
        rest: expression,
        output: String::new(),
        profile,
    };
    parser.translate()?;
    RegexBuilder::new(&parser.output)
        .size_limit(8 * 1024 * 1024)
        .dfa_size_limit(2 * 1024 * 1024)
        .nest_limit(1000)
        .build()
        .map_err(|error| match error {
            regex::Error::CompiledTooBig(_) => Error::SizeLimit,
            _ => Error::RegexImplementation,
        })
}

struct Adapter<'a> {
    rest: &'a str,
    output: String,
    profile: Profile,
}
impl Adapter<'_> {
    fn emit(&mut self, text: &str) -> Result<(), Error> {
        if self
            .output
            .len()
            .checked_add(text.len())
            .ok_or(Error::SizeLimit)?
            > 1024 * 1024
        {
            return Err(Error::SizeLimit);
        }
        self.output
            .try_reserve(text.len())
            .map_err(|_| Error::Allocation)?;
        self.output.push_str(text);
        Ok(())
    }
    fn next(&mut self) -> Result<char, Error> {
        let ch = self.rest.chars().next().ok_or(Error::InvalidSelector)?;
        self.rest = &self.rest[ch.len_utf8()..];
        Ok(ch)
    }
    fn literal(&mut self, ch: u32) -> Result<(), Error> {
        if (0xd800..=0xdfff).contains(&ch) {
            self.emit("[a&&b]")
        } else {
            self.emit(&format!("\\x{{{ch:x}}}"))
        }
    }
    fn translate(&mut self) -> Result<(), Error> {
        let mut groups: Vec<usize> = Vec::new();
        let mut atom = false;
        let mut repeated = false;
        let mut lazy = false;
        let mut repeat_weight = 1usize;
        let mut maximum_weight = 1usize;
        while !self.rest.is_empty() {
            let ch = self.next()?;
            match ch {
                '[' => {
                    self.class()?;
                    atom = true;
                    repeated = false;
                    repeat_weight = 1;
                }
                '\\' => {
                    if self.rest.starts_with('Q') {
                        self.next()?;
                        while !self.rest.is_empty() && !self.rest.starts_with("\\E") {
                            let quoted = self.next()?;
                            self.literal(quoted as u32)?;
                            atom = true;
                        }
                        if self.rest.starts_with("\\E") {
                            self.rest = &self.rest[2..];
                        }
                    } else if !self.group_escape(false)? {
                        let literal = self.escape()?;
                        self.literal(literal)?;
                        atom = true;
                    } else {
                        atom = true;
                    }
                    repeated = false;
                    repeat_weight = 1;
                }
                '(' => {
                    let opens = self.group()?;
                    if opens {
                        if groups.len() >= 1000 {
                            return Err(Error::SizeLimit);
                        }
                        groups.push(maximum_weight);
                        maximum_weight = 1;
                        atom = false;
                    }
                    repeated = false;
                }
                ')' => {
                    let outer = groups.pop().ok_or(Error::InvalidSelector)?;
                    repeat_weight = maximum_weight;
                    maximum_weight = maximum_weight.max(outer);
                    self.emit(")")?;
                    atom = true;
                    repeated = false;
                }
                '|' => {
                    self.emit("|")?;
                    atom = false;
                    repeated = false;
                }
                '*' | '+' | '?' => {
                    if repeated && ch == '?' && !lazy {
                        lazy = true;
                    } else {
                        if !atom || repeated {
                            return Err(Error::InvalidSelector);
                        }
                        repeated = true;
                        lazy = false;
                    }
                    self.emit(&ch.to_string())?;
                }
                '{' => {
                    if let Some((length, count)) = repeat(self.rest)? {
                        if !atom || repeated {
                            return Err(Error::InvalidSelector);
                        }
                        repeat_weight = repeat_weight
                            .checked_mul(count.max(1))
                            .ok_or(Error::SizeLimit)?;
                        if repeat_weight > 1000 {
                            return Err(Error::InvalidSelector);
                        }
                        maximum_weight = maximum_weight.max(repeat_weight);
                        self.emit("{")?;
                        self.emit(&self.rest[..length])?;
                        self.rest = &self.rest[length..];
                        repeated = true;
                        lazy = false;
                    } else {
                        self.literal(ch as u32)?;
                        atom = true;
                        repeated = false;
                        repeat_weight = 1;
                    }
                }
                '.' | '^' | '$' => {
                    self.emit(&ch.to_string())?;
                    atom = true;
                    repeated = false;
                    repeat_weight = 1;
                }
                _ => {
                    self.literal(ch as u32)?;
                    atom = true;
                    repeated = false;
                    repeat_weight = 1;
                }
            }
        }
        if !groups.is_empty() {
            return Err(Error::InvalidSelector);
        }
        Ok(())
    }
    fn group_escape(&mut self, in_class: bool) -> Result<bool, Error> {
        let Some(ch) = self.rest.chars().next() else {
            return Err(Error::InvalidSelector);
        };
        let expansion = match ch {
            'd' => "[0-9]",
            'D' => "[^0-9]",
            'w' => "[A-Za-z0-9_]",
            'W' => "[^A-Za-z0-9_]",
            's' => "[\\t\\n\\f\\r ]",
            'S' => "[^\\t\\n\\f\\r ]",
            'b' if !in_class => "(?-u:\\b)",
            'B' if !in_class => "(?-u:\\B)",
            'A' if !in_class => "\\A",
            'z' if !in_class => "\\z",
            'p' | 'P' => {
                self.next()?;
                let first = self.next()?;
                let name = if first == '{' {
                    let end = self.rest.find('}').ok_or(Error::InvalidSelector)?;
                    let name = self.rest[..end].to_owned();
                    self.rest = &self.rest[end + 1..];
                    name
                } else {
                    first.to_string()
                };
                let (name, inverted) = match name.strip_prefix('^') {
                    Some(name) => (name, ch != 'P'),
                    None => (name.as_str(), ch == 'P'),
                };
                let property = property(name, self.profile)?;
                self.emit(if inverted { "[^" } else { "[" })?;
                self.emit(&property)?;
                self.emit("]")?;
                return Ok(true);
            }
            _ => return Ok(false),
        };
        self.next()?;
        self.emit(expansion)?;
        Ok(true)
    }
    fn escape(&mut self) -> Result<u32, Error> {
        let ch = self.next()?;
        Ok(match ch {
            '0'..='7' => {
                if ch != '0' && !self.rest.starts_with(|c| matches!(c, '0'..='7')) {
                    return Err(Error::InvalidSelector);
                }
                let mut number = ch as u32 - '0' as u32;
                for _ in 1..3 {
                    if !self.rest.starts_with(|c| matches!(c, '0'..='7')) {
                        break;
                    }
                    number = number * 8 + self.next()? as u32 - '0' as u32;
                }
                number
            }
            'x' => {
                let digits = if self.rest.starts_with('{') {
                    self.next()?;
                    let end = self.rest.find('}').ok_or(Error::InvalidSelector)?;
                    let digits = &self.rest[..end];
                    self.rest = &self.rest[end + 1..];
                    digits
                } else {
                    let digits = self.rest.get(..2).ok_or(Error::InvalidSelector)?;
                    self.rest = &self.rest[2..];
                    digits
                };
                if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(Error::InvalidSelector);
                }
                let mut number = 0u32;
                for digit in digits.bytes() {
                    number = number
                        .checked_mul(16)
                        .and_then(|v| v.checked_add((digit as char).to_digit(16)?))
                        .ok_or(Error::InvalidSelector)?;
                    if number > 0x10ffff {
                        return Err(Error::InvalidSelector);
                    }
                }
                number
            }
            'a' => 7,
            'f' => 12,
            'n' => 10,
            'r' => 13,
            't' => 9,
            'v' => 11,
            ch if ch.is_ascii() && !ch.is_ascii_alphanumeric() => ch as u32,
            _ => return Err(Error::InvalidSelector),
        })
    }
    fn class(&mut self) -> Result<(), Error> {
        self.emit("[")?;
        if self.rest.starts_with('^') {
            self.next()?;
            self.emit("^")?;
        }
        let mut first = true;
        while first || !self.rest.starts_with(']') {
            first = false;
            if self.rest.starts_with("[:") {
                if let Some(end) = self.rest.find(":]") {
                    let name = &self.rest[2..end];
                    let bare = name.strip_prefix('^').unwrap_or(name);
                    if ![
                        "alnum", "alpha", "ascii", "blank", "cntrl", "digit", "graph", "lower",
                        "print", "punct", "space", "upper", "word", "xdigit",
                    ]
                    .contains(&bare)
                    {
                        return Err(Error::InvalidSelector);
                    }
                    self.emit(&self.rest[..end + 2])?;
                    self.rest = &self.rest[end + 2..];
                    continue;
                }
            }
            if self.rest.starts_with('\\') {
                let before = self.rest;
                self.next()?;
                if self.group_escape(true)? {
                    continue;
                }
                self.rest = before;
            }
            let lo = self.class_char()?;
            if self.rest.starts_with('-') && !self.rest.starts_with("-]") {
                self.next()?;
                let hi = self.class_char()?;
                if hi < lo {
                    return Err(Error::InvalidSelector);
                }
                for (start, end) in [(lo, hi.min(0xd7ff)), (lo.max(0xe000), hi)] {
                    if start <= end {
                        self.literal(start)?;
                        self.emit("-")?;
                        self.literal(end)?;
                    }
                }
            } else {
                self.literal(lo)?;
            }
        }
        self.next()?;
        self.emit("]")
    }
    fn class_char(&mut self) -> Result<u32, Error> {
        let ch = self.next()?;
        if ch == '\\' {
            self.escape()
        } else {
            Ok(ch as u32)
        }
    }
    fn group(&mut self) -> Result<bool, Error> {
        if !self.rest.starts_with('?') {
            self.emit("(")?;
            return Ok(true);
        }
        self.next()?;
        if self.rest.starts_with("P<") || self.rest.starts_with('<') {
            if self.rest.starts_with('P') {
                self.next()?;
            }
            self.next()?;
            let end = self.rest.find('>').ok_or(Error::InvalidSelector)?;
            let name = &self.rest[..end];
            if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
                return Err(Error::InvalidSelector);
            }
            self.rest = &self.rest[end + 1..];
            self.emit("(?:")?;
            return Ok(true);
        }
        let mut minus = false;
        let mut after_minus = false;
        let mut flags = String::new();
        loop {
            let ch = self.next()?;
            match ch {
                'i' | 'm' | 's' | 'U' => {
                    flags.push(ch);
                    if minus {
                        after_minus = true;
                    }
                }
                '-' if !minus => {
                    flags.push('-');
                    minus = true;
                }
                ':' | ')' => {
                    if (minus && !after_minus) || (ch == ')' && flags.is_empty()) {
                        return Err(Error::InvalidSelector);
                    }
                    self.emit("(?")?;
                    self.emit(&flags)?;
                    self.emit(&ch.to_string())?;
                    return Ok(ch == ':');
                }
                _ => return Err(Error::InvalidSelector),
            }
        }
    }
}

fn repeat(rest: &str) -> Result<Option<(usize, usize)>, Error> {
    let Some(end) = rest.find('}') else {
        return Ok(None);
    };
    let body = &rest[..end];
    let (min, max) = body.split_once(',').map_or((body, Some(body)), |(a, b)| {
        (a, if b.is_empty() { None } else { Some(b) })
    });
    let decimal = |s: &str| {
        !s.is_empty()
            && s.bytes().all(|b| b.is_ascii_digit())
            && (s.len() == 1 || !s.starts_with('0'))
    };
    if !decimal(min) || max.is_some_and(|s| !decimal(s)) {
        return Ok(None);
    }
    let min = min.parse::<usize>().map_err(|_| Error::InvalidSelector)?;
    let max = max
        .map(|s| s.parse::<usize>().map_err(|_| Error::InvalidSelector))
        .transpose()?
        .unwrap_or(min);
    if min > max || max > 1000 {
        return Err(Error::InvalidSelector);
    }
    Ok(Some((end + 1, max)))
}

fn property(name: &str, profile: Profile) -> Result<String, Error> {
    let normalized;
    let mut name = name;
    if profile == Profile::Current {
        normalized = canonical(name);
        name = &normalized;
        if let Some((_, short)) = CATEGORY_ALIASES
            .iter()
            .find(|(alias, _)| canonical(alias) == name)
        {
            name = short;
        }
    }
    if name == "Any" {
        return Ok("\\x{0}-\\x{10ffff}".to_owned());
    }
    if profile == Profile::Current {
        match name {
            "Ascii" => return Ok("\\x00-\\x7f".to_owned()),
            "Assigned" => return Ok("\\P{Cn}".to_owned()),
            "Lc" | "LC" => return Ok("\\p{Lu}\\p{Ll}\\p{Lt}".to_owned()),
            _ => {}
        }
    }
    if name == "Cs" {
        return Ok("[a&&b]".to_owned());
    }
    if CATEGORIES.contains(&name) || (name == "Cn" && profile == Profile::Current) {
        return Ok(if name == "C" && profile == Profile::Legacy {
            "\\p{Cc}\\p{Cf}\\p{Co}".to_owned()
        } else {
            format!("\\p{{{name}}}")
        });
    }
    if SCRIPTS.contains(&name) {
        return Ok(format!("\\p{{{name}}}"));
    }
    Err(Error::InvalidSelector)
}
fn canonical(name: &str) -> String {
    let mut name: String = name
        .chars()
        .filter(|c| !matches!(c, '_' | '-' | ' '))
        .collect();
    name.make_ascii_lowercase();
    if let Some(first) = name.get_mut(..1) {
        first.make_ascii_uppercase();
    }
    name
}

const CATEGORIES: &[&str] = &[
    "C", "Cc", "Cf", "Co", "Cs", "L", "Ll", "Lm", "Lo", "Lt", "Lu", "M", "Mc", "Me", "Mn", "N",
    "Nd", "Nl", "No", "P", "Pc", "Pd", "Pe", "Pf", "Pi", "Po", "Ps", "S", "Sc", "Sk", "Sm", "So",
    "Z", "Zl", "Zp", "Zs",
];
const SCRIPTS: &[&str] = &[
    "Adlam",
    "Ahom",
    "Anatolian_Hieroglyphs",
    "Arabic",
    "Armenian",
    "Avestan",
    "Balinese",
    "Bamum",
    "Bassa_Vah",
    "Batak",
    "Bengali",
    "Bhaiksuki",
    "Bopomofo",
    "Brahmi",
    "Braille",
    "Buginese",
    "Buhid",
    "Canadian_Aboriginal",
    "Carian",
    "Caucasian_Albanian",
    "Chakma",
    "Cham",
    "Cherokee",
    "Chorasmian",
    "Common",
    "Coptic",
    "Cuneiform",
    "Cypriot",
    "Cypro_Minoan",
    "Cyrillic",
    "Deseret",
    "Devanagari",
    "Dives_Akuru",
    "Dogra",
    "Duployan",
    "Egyptian_Hieroglyphs",
    "Elbasan",
    "Elymaic",
    "Ethiopic",
    "Georgian",
    "Glagolitic",
    "Gothic",
    "Grantha",
    "Greek",
    "Gujarati",
    "Gunjala_Gondi",
    "Gurmukhi",
    "Han",
    "Hangul",
    "Hanifi_Rohingya",
    "Hanunoo",
    "Hatran",
    "Hebrew",
    "Hiragana",
    "Imperial_Aramaic",
    "Inherited",
    "Inscriptional_Pahlavi",
    "Inscriptional_Parthian",
    "Javanese",
    "Kaithi",
    "Kannada",
    "Katakana",
    "Kawi",
    "Kayah_Li",
    "Kharoshthi",
    "Khitan_Small_Script",
    "Khmer",
    "Khojki",
    "Khudawadi",
    "Lao",
    "Latin",
    "Lepcha",
    "Limbu",
    "Linear_A",
    "Linear_B",
    "Lisu",
    "Lycian",
    "Lydian",
    "Mahajani",
    "Makasar",
    "Malayalam",
    "Mandaic",
    "Manichaean",
    "Marchen",
    "Masaram_Gondi",
    "Medefaidrin",
    "Meetei_Mayek",
    "Mende_Kikakui",
    "Meroitic_Cursive",
    "Meroitic_Hieroglyphs",
    "Miao",
    "Modi",
    "Mongolian",
    "Mro",
    "Multani",
    "Myanmar",
    "Nabataean",
    "Nag_Mundari",
    "Nandinagari",
    "New_Tai_Lue",
    "Newa",
    "Nko",
    "Nushu",
    "Nyiakeng_Puachue_Hmong",
    "Ogham",
    "Ol_Chiki",
    "Old_Hungarian",
    "Old_Italic",
    "Old_North_Arabian",
    "Old_Permic",
    "Old_Persian",
    "Old_Sogdian",
    "Old_South_Arabian",
    "Old_Turkic",
    "Old_Uyghur",
    "Oriya",
    "Osage",
    "Osmanya",
    "Pahawh_Hmong",
    "Palmyrene",
    "Pau_Cin_Hau",
    "Phags_Pa",
    "Phoenician",
    "Psalter_Pahlavi",
    "Rejang",
    "Runic",
    "Samaritan",
    "Saurashtra",
    "Sharada",
    "Shavian",
    "Siddham",
    "SignWriting",
    "Sinhala",
    "Sogdian",
    "Sora_Sompeng",
    "Soyombo",
    "Sundanese",
    "Syloti_Nagri",
    "Syriac",
    "Tagalog",
    "Tagbanwa",
    "Tai_Le",
    "Tai_Tham",
    "Tai_Viet",
    "Takri",
    "Tamil",
    "Tangsa",
    "Tangut",
    "Telugu",
    "Thaana",
    "Thai",
    "Tibetan",
    "Tifinagh",
    "Tirhuta",
    "Toto",
    "Ugaritic",
    "Vai",
    "Vithkuqi",
    "Wancho",
    "Warang_Citi",
    "Yezidi",
    "Yi",
    "Zanabazar_Square",
];
const CATEGORY_ALIASES: &[(&str, &str)] = &[
    ("Cased_Letter", "LC"),
    ("Close_Punctuation", "Pe"),
    ("Combining_Mark", "M"),
    ("Connector_Punctuation", "Pc"),
    ("Control", "Cc"),
    ("Currency_Symbol", "Sc"),
    ("Dash_Punctuation", "Pd"),
    ("Decimal_Number", "Nd"),
    ("Enclosing_Mark", "Me"),
    ("Final_Punctuation", "Pf"),
    ("Format", "Cf"),
    ("Initial_Punctuation", "Pi"),
    ("Letter", "L"),
    ("Letter_Number", "Nl"),
    ("Line_Separator", "Zl"),
    ("Lowercase_Letter", "Ll"),
    ("Mark", "M"),
    ("Math_Symbol", "Sm"),
    ("Modifier_Letter", "Lm"),
    ("Modifier_Symbol", "Sk"),
    ("Nonspacing_Mark", "Mn"),
    ("Number", "N"),
    ("Open_Punctuation", "Ps"),
    ("Other", "C"),
    ("Other_Letter", "Lo"),
    ("Other_Number", "No"),
    ("Other_Punctuation", "Po"),
    ("Other_Symbol", "So"),
    ("Paragraph_Separator", "Zp"),
    ("Private_Use", "Co"),
    ("Punctuation", "P"),
    ("Separator", "Z"),
    ("Space_Separator", "Zs"),
    ("Spacing_Mark", "Mc"),
    ("Surrogate", "Cs"),
    ("Symbol", "S"),
    ("Titlecase_Letter", "Lt"),
    ("Unassigned", "Cn"),
    ("Uppercase_Letter", "Lu"),
    ("cntrl", "Cc"),
    ("digit", "Nd"),
    ("punct", "P"),
];
