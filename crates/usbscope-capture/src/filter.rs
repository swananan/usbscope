//! USB filter parser and evaluator. Missing event fields use three-valued logic:
//! `not unknown` remains unknown and cannot match. Payloads are scanned in chunks.
use crate::Event;
use anyhow::{Context, Result, bail, ensure};
use std::io::{Read, Seek, SeekFrom};
use usbscope_common::{EventMeta, KernelPredicate};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Truth {
    False,
    True,
    Unknown,
}
impl Truth {
    fn not(self) -> Self {
        match self {
            Self::False => Self::True,
            Self::True => Self::False,
            Self::Unknown => self,
        }
    }
    fn and(self, other: Self) -> Self {
        match (self, other) {
            (Self::False, _) | (_, Self::False) => Self::False,
            (Self::True, Self::True) => Self::True,
            _ => Self::Unknown,
        }
    }
    fn or(self, other: Self) -> Self {
        match (self, other) {
            (Self::True, _) | (_, Self::True) => Self::True,
            (Self::False, Self::False) => Self::False,
            _ => Self::Unknown,
        }
    }
}
impl From<bool> for Truth {
    fn from(value: bool) -> Self {
        if value { Self::True } else { Self::False }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Field {
    Bus,
    Device,
    Vid,
    Pid,
    Endpoint,
    EpNum,
    Direction,
    Transfer,
    Requested,
    Actual,
    Length,
    Captured,
    Frames,
    Status,
    Event,
    Interval,
    StartFrame,
    Errors,
    UrbId,
    Request,
    RequestType,
    Value,
    Index,
    SetupLength,
    Latency,
    Payload(u64, u8),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Compare {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}
impl Compare {
    fn matches(self, a: i128, b: i128) -> bool {
        match self {
            Self::Eq => a == b,
            Self::Ne => a != b,
            Self::Lt => a < b,
            Self::Le => a <= b,
            Self::Gt => a > b,
            Self::Ge => a >= b,
        }
    }
    fn invert(self) -> Self {
        match self {
            Self::Eq => Self::Ne,
            Self::Ne => Self::Eq,
            Self::Lt => Self::Ge,
            Self::Le => Self::Gt,
            Self::Gt => Self::Le,
            Self::Ge => Self::Lt,
        }
    }
    fn code(self) -> u32 {
        match self {
            Self::Eq => 0,
            Self::Ne => 1,
            Self::Lt => 2,
            Self::Le => 3,
            Self::Gt => 4,
            Self::Ge => 5,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Predicate {
    field: Field,
    mask: Option<u64>,
    comparison: Compare,
    value: i128,
}
#[derive(Debug)]
enum Expr {
    All,
    Predicate(Predicate),
    Contains(Vec<u8>),
    And(Box<Self>, Box<Self>),
    Or(Box<Self>, Box<Self>),
    Not(Box<Self>),
}

#[derive(Debug)]
pub struct Filter {
    expression: Expr,
}
impl Filter {
    pub fn parse(source: &str) -> Result<Self> {
        let tokens = tokenize(source)?;
        if tokens.is_empty() {
            return Ok(Self {
                expression: Expr::All,
            });
        }
        let mut parser = Parser {
            tokens,
            at: 0,
            depth: 0,
        };
        let expression = parser.or()?;
        ensure!(
            parser.peek().is_none(),
            "unexpected token {:?}",
            parser.peek()
        );
        Ok(Self { expression })
    }
    pub fn matches(&self, event: &mut Event, latency_ns: Option<u64>) -> Result<bool> {
        Ok(self.expression.evaluate(event, latency_ns)? == Truth::True)
    }
    pub fn needs_latency(&self) -> bool {
        self.expression.needs_latency()
    }
    /// Only predicates that are necessary for the whole expression, and whose
    /// fields cannot change between S and C, are safe to reject in the kernel.
    /// In particular `bus 1 or payload contains ...` has no bus prefilter.
    pub fn kernel_predicates(&self) -> Vec<KernelPredicate> {
        self.expression
            .required(false)
            .into_iter()
            .filter_map(|p| {
                let field = match p.field {
                    Field::Bus => 1,
                    Field::Device => 2,
                    Field::Vid => 3,
                    Field::Pid => 4,
                    Field::Endpoint => 5,
                    Field::EpNum => 6,
                    Field::Direction => 7,
                    Field::Transfer => 8,
                    Field::Requested => 9,
                    Field::Frames => 10,
                    _ => return None,
                };
                Some(KernelPredicate {
                    field,
                    comparison: p.comparison.code(),
                    value: p.value.try_into().ok()?,
                    mask: p.mask.unwrap_or(u64::MAX),
                })
            })
            .take(usbscope_common::MAX_KERNEL_PREDICATES as usize)
            .collect()
    }
}
impl Expr {
    fn needs_latency(&self) -> bool {
        match self {
            Self::Predicate(p) => p.field == Field::Latency,
            Self::Not(inner) => inner.needs_latency(),
            Self::And(a, b) | Self::Or(a, b) => a.needs_latency() || b.needs_latency(),
            _ => false,
        }
    }
    fn required(&self, negated: bool) -> Vec<Predicate> {
        match self {
            Self::Predicate(p) => {
                let mut p = p.clone();
                if negated {
                    p.comparison = p.comparison.invert();
                }
                vec![p]
            }
            Self::Not(inner) => inner.required(!negated),
            Self::And(a, b) | Self::Or(a, b) => {
                let left = a.required(negated);
                let right = b.required(negated);
                if matches!(self, Self::And(..)) != negated {
                    let mut result = left;
                    for p in right {
                        if !result.contains(&p) {
                            result.push(p);
                        }
                    }
                    result
                } else {
                    left.into_iter().filter(|p| right.contains(p)).collect()
                }
            }
            _ => vec![],
        }
    }
    fn evaluate(&self, event: &mut Event, latency: Option<u64>) -> Result<Truth> {
        Ok(match self {
            Self::All => Truth::True,
            Self::Not(inner) => inner.evaluate(event, latency)?.not(),
            Self::And(a, b) => {
                let a = a.evaluate(event, latency)?;
                if a == Truth::False {
                    a
                } else {
                    a.and(b.evaluate(event, latency)?)
                }
            }
            Self::Or(a, b) => {
                let a = a.evaluate(event, latency)?;
                if a == Truth::True {
                    a
                } else {
                    a.or(b.evaluate(event, latency)?)
                }
            }
            Self::Predicate(p) => {
                if let Some(mut value) = value(p.field, event, latency)? {
                    if let Some(mask) = p.mask {
                        value = i128::from((value as u64) & mask);
                    }
                    p.comparison.matches(value, p.value).into()
                } else {
                    Truth::Unknown
                }
            }
            Self::Contains(needle) => {
                if event.meta.has_data == 0 {
                    Truth::Unknown
                } else {
                    contains(event, needle)?.into()
                }
            }
        })
    }
}
fn value(field: Field, event: &mut Event, latency: Option<u64>) -> Result<Option<i128>> {
    if matches!(field, Field::Vid | Field::Pid) && !event.identity_known
        || field == Field::Requested && !event.requested_known
    {
        return Ok(None);
    }
    let m: &EventMeta = &event.meta;
    let v = match field {
        Field::Bus => i128::from(m.bus),
        Field::Device => i128::from(m.device),
        Field::Vid => i128::from(m.vid),
        Field::Pid => i128::from(m.pid),
        Field::Endpoint => i128::from(m.endpoint),
        Field::EpNum => i128::from(m.endpoint & 15),
        Field::Direction => i128::from(m.endpoint >> 7),
        Field::Transfer => i128::from(m.transfer_type),
        Field::Requested => i128::from(m.requested_len),
        Field::Actual => {
            if m.event_type == b'S' {
                return Ok(None);
            }
            i128::from(m.actual_len)
        }
        Field::Length => i128::from(if m.event_type == b'S' {
            m.requested_len
        } else {
            m.actual_len
        }),
        Field::Captured => i128::from(m.payload_len),
        Field::Frames => i128::from(m.iso_count),
        Field::Status => i128::from(m.status),
        Field::Event => i128::from(m.event_type),
        Field::Interval => i128::from(m.interval),
        Field::StartFrame => i128::from(m.start_frame),
        Field::Errors => i128::from(m.error_count),
        Field::UrbId => i128::from(m.urb_id),
        Field::Latency => return Ok(latency.map(i128::from)),
        Field::Request | Field::RequestType | Field::Value | Field::Index | Field::SetupLength => {
            if m.setup_present == 0 {
                return Ok(None);
            }
            match field {
                Field::Request => i128::from(m.setup[1]),
                Field::RequestType => i128::from(m.setup[0]),
                Field::Value => i128::from(u16::from_le_bytes([m.setup[2], m.setup[3]])),
                Field::Index => i128::from(u16::from_le_bytes([m.setup[4], m.setup[5]])),
                _ => i128::from(u16::from_le_bytes([m.setup[6], m.setup[7]])),
            }
        }
        Field::Payload(offset, size) => {
            let Some(end) = offset.checked_add(u64::from(size)) else {
                return Ok(None);
            };
            if m.has_data == 0 || end > u64::from(m.payload_len) {
                return Ok(None);
            }
            // ISO padding is not captured data and must not satisfy byte filters.
            if m.transfer_type == 0
                && !event.iso.iter().any(|d| {
                    offset >= u64::from(d.offset)
                        && end <= u64::from(d.offset) + u64::from(d.length)
                })
            {
                return Ok(None);
            }
            event.payload.seek(SeekFrom::Start(offset))?;
            let mut bytes = [0u8; 8];
            event
                .payload
                .read_exact(&mut bytes[8 - usize::from(size)..])?;
            i128::from(u64::from_be_bytes(bytes))
        }
    };
    Ok(Some(v))
}
fn contains(event: &mut Event, needle: &[u8]) -> Result<bool> {
    // Streaming KMP: matches crossing transport/spool boundaries, with O(n+m)
    // work and no payload-sized allocation. Never scan fabricated ISO padding.
    let mut prefix = vec![0usize; needle.len()];
    let mut matched = 0;
    for i in 1..needle.len() {
        while matched != 0 && needle[i] != needle[matched] {
            matched = prefix[matched - 1];
        }
        if needle[i] == needle[matched] {
            matched += 1;
        }
        prefix[i] = matched;
    }
    let ranges: Vec<_> = if event.meta.transfer_type == 0 {
        event
            .iso
            .iter()
            .map(|d| (u64::from(d.offset), u64::from(d.length)))
            .collect()
    } else {
        vec![(0, u64::from(event.meta.payload_len))]
    };
    let mut buffer = [0u8; 16384];
    for (offset, mut length) in ranges {
        event.payload.seek(SeekFrom::Start(offset))?;
        matched = 0;
        while length != 0 {
            let n = length.min(buffer.len() as u64) as usize;
            event.payload.read_exact(&mut buffer[..n])?;
            for byte in &buffer[..n] {
                while matched != 0 && *byte != needle[matched] {
                    matched = prefix[matched - 1];
                }
                if *byte == needle[matched] {
                    matched += 1;
                }
                if matched == needle.len() {
                    return Ok(true);
                }
            }
            length -= n as u64;
        }
    }
    Ok(false)
}

#[derive(Clone, Debug)]
struct Token {
    text: String,
    quoted: bool,
}
fn tokenize(input: &str) -> Result<Vec<Token>> {
    let mut tokens = Vec::new();
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch.is_whitespace() {
            continue;
        }
        if ch == '\'' || ch == '"' {
            let mut text = String::new();
            let mut closed = false;
            while let Some(c) = chars.next() {
                if c == ch {
                    closed = true;
                    break;
                }
                if c == '\\' {
                    text.push(chars.next().context("unfinished quoted escape")?);
                } else {
                    text.push(c);
                }
            }
            ensure!(closed, "unterminated quoted string");
            tokens.push(Token { text, quoted: true });
        } else if "()[]:&|!=<>".contains(ch) {
            let mut text = ch.to_string();
            if chars
                .peek()
                .is_some_and(|c| *c == '=' && "!=<>".contains(ch) || *c == ch && "&|".contains(ch))
            {
                text.push(chars.next().unwrap());
            }
            tokens.push(Token {
                text,
                quoted: false,
            });
        } else {
            let mut text = ch.to_string();
            while chars
                .peek()
                .is_some_and(|c| !c.is_whitespace() && !"()[]:&|!=<>\"'".contains(*c))
            {
                text.push(chars.next().unwrap());
            }
            tokens.push(Token {
                text,
                quoted: false,
            });
        }
    }
    Ok(tokens)
}
struct Parser {
    tokens: Vec<Token>,
    at: usize,
    depth: usize,
}
impl Parser {
    fn peek(&self) -> Option<&str> {
        self.tokens.get(self.at).map(|t| t.text.as_str())
    }
    fn take(&mut self) -> Result<Token> {
        let token = self
            .tokens
            .get(self.at)
            .context("unexpected end of filter")?
            .clone();
        self.at += 1;
        Ok(token)
    }
    fn accept(&mut self, text: &str) -> bool {
        if self.peek() == Some(text) {
            self.at += 1;
            true
        } else {
            false
        }
    }
    fn expect(&mut self, text: &str) -> Result<()> {
        ensure!(
            self.accept(text),
            "expected '{text}', found {:?}",
            self.peek()
        );
        Ok(())
    }
    fn or(&mut self) -> Result<Expr> {
        let mut nodes = vec![self.and()?];
        while self.accept("or") || self.accept("||") {
            nodes.push(self.and()?);
        }
        Ok(balanced(nodes, false))
    }
    fn and(&mut self) -> Result<Expr> {
        let mut nodes = vec![self.unary()?];
        loop {
            if matches!(self.peek(), None | Some(")" | "or" | "||")) {
                break;
            }
            if !self.accept("and") {
                self.accept("&&");
            }
            nodes.push(self.unary()?);
        }
        Ok(balanced(nodes, true))
    }
    fn unary(&mut self) -> Result<Expr> {
        self.depth += 1;
        ensure!(
            self.depth <= 128,
            "filter nesting exceeds parser resource limit"
        );
        let node = if self.accept("not") || self.accept("!") {
            Expr::Not(Box::new(self.unary()?))
        } else if self.accept("(") {
            let node = self.or()?;
            self.expect(")")?;
            node
        } else {
            self.predicate()?
        };
        self.depth -= 1;
        Ok(node)
    }
    fn predicate(&mut self) -> Result<Expr> {
        let name = self.take()?.text;
        let (field, shorthand) = match name.as_str() {
            "bus" => (Field::Bus, None),
            "dev" | "device" => (Field::Device, None),
            "vid" => (Field::Vid, None),
            "pid" => (Field::Pid, None),
            "ep" | "endpoint" => (Field::Endpoint, None),
            "epnum" => (Field::EpNum, None),
            "in" => (Field::Direction, Some(1)),
            "out" => (Field::Direction, Some(0)),
            "dir" | "direction" => (Field::Direction, None),
            "iso" | "isoc" => (Field::Transfer, Some(0)),
            "interrupt" | "intr" => (Field::Transfer, Some(1)),
            "control" | "ctrl" => (Field::Transfer, Some(2)),
            "bulk" => (Field::Transfer, Some(3)),
            "type" => (Field::Transfer, None),
            "requested" => (Field::Requested, None),
            "actual" => (Field::Actual, None),
            "len" | "length" => (Field::Length, None),
            "captured" => (Field::Captured, None),
            "frames" => (Field::Frames, None),
            "status" => (Field::Status, None),
            "event" => (Field::Event, None),
            "interval" => (Field::Interval, None),
            "start_frame" => (Field::StartFrame, None),
            "errors" => (Field::Errors, None),
            "urb" => (Field::UrbId, None),
            "setup.request" => (Field::Request, None),
            "setup.type" => (Field::RequestType, None),
            "setup.value" => (Field::Value, None),
            "setup.index" => (Field::Index, None),
            "setup.length" => (Field::SetupLength, None),
            "latency" => (Field::Latency, None),
            "payload" => {
                if self.accept("contains") {
                    let token = self.take()?;
                    let bytes = if token.quoted {
                        token.text.into_bytes()
                    } else {
                        let hex = token.text.strip_prefix("0x").context(
                            "payload pattern must be quoted text or 0x-prefixed hex bytes",
                        )?;
                        ensure!(hex.len() % 2 == 0, "hex pattern must contain whole bytes");
                        hex.as_bytes()
                            .chunks(2)
                            .map(|pair| -> Result<_> {
                                Ok(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?)
                            })
                            .collect::<Result<Vec<_>>>()?
                    };
                    ensure!(!bytes.is_empty(), "empty payload pattern");
                    return Ok(Expr::Contains(bytes));
                }
                self.expect("[")?;
                let offset = number(&self.take()?.text)?
                    .try_into()
                    .context("payload offset must be nonnegative and fit u64")?;
                let size: u8 = if self.accept(":") {
                    number(&self.take()?.text)?
                        .try_into()
                        .context("invalid payload width")?
                } else {
                    1
                };
                ensure!(
                    matches!(size, 1 | 2 | 4 | 8),
                    "payload width must be 1, 2, 4, or 8"
                );
                self.expect("]")?;
                (Field::Payload(offset, size), None)
            }
            _ => bail!("unknown USB filter field '{name}'"),
        };
        if let Some(value) = shorthand {
            return Ok(Expr::Predicate(Predicate {
                field,
                mask: None,
                comparison: Compare::Eq,
                value,
            }));
        }
        let mask = if self.accept("&") {
            Some(
                number(&self.take()?.text)?
                    .try_into()
                    .context("mask must fit u64")?,
            )
        } else {
            None
        };
        let comparison = match self.peek() {
            Some("=" | "==") => {
                self.take()?;
                Compare::Eq
            }
            Some("!=") => {
                self.take()?;
                Compare::Ne
            }
            Some("<") => {
                self.take()?;
                Compare::Lt
            }
            Some("<=") => {
                self.take()?;
                Compare::Le
            }
            Some(">") => {
                self.take()?;
                Compare::Gt
            }
            Some(">=") => {
                self.take()?;
                Compare::Ge
            }
            _ => Compare::Eq,
        };
        let token = self.take()?.text;
        let value = match (field, token.as_str()) {
            (Field::Direction, "in") => 1,
            (Field::Direction, "out") => 0,
            (Field::Transfer, "iso" | "isoc") => 0,
            (Field::Transfer, "interrupt" | "intr") => 1,
            (Field::Transfer, "control" | "ctrl") => 2,
            (Field::Transfer, "bulk") => 3,
            (Field::Event, "S" | "submit") => i128::from(b'S'),
            (Field::Event, "C" | "complete") => i128::from(b'C'),
            (Field::Event, "E" | "error") => i128::from(b'E'),
            (Field::Latency, _) => duration(&token)?,
            _ => number(&token)?,
        };
        Ok(Expr::Predicate(Predicate {
            field,
            mask,
            comparison,
            value,
        }))
    }
}

// Long flat expressions do not turn into deeply recursive evaluation/drop.
fn balanced(mut nodes: Vec<Expr>, and: bool) -> Expr {
    while nodes.len() > 1 {
        let mut next = Vec::new();
        let mut iter = nodes.into_iter();
        while let Some(a) = iter.next() {
            next.push(if let Some(b) = iter.next() {
                if and {
                    Expr::And(Box::new(a), Box::new(b))
                } else {
                    Expr::Or(Box::new(a), Box::new(b))
                }
            } else {
                a
            });
        }
        nodes = next;
    }
    nodes.pop().unwrap()
}
fn number(text: &str) -> Result<i128> {
    if let Some(hex) = text.strip_prefix("0x") {
        Ok(i128::from(
            u64::from_str_radix(hex, 16).context("invalid hex number")?,
        ))
    } else {
        let value: i128 = text
            .parse()
            .with_context(|| format!("invalid number '{text}'"))?;
        ensure!(
            (i128::from(i64::MIN)..=i128::from(u64::MAX)).contains(&value),
            "number out of range"
        );
        Ok(value)
    }
}
fn duration(text: &str) -> Result<i128> {
    for (suffix, multiplier) in [
        ("ns", 1),
        ("us", 1000),
        ("ms", 1_000_000),
        ("s", 1_000_000_000),
    ] {
        if let Some(value) = text.strip_suffix(suffix) {
            let value = number(value)?;
            return value.checked_mul(multiplier).context("duration overflow");
        }
    }
    number(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::SpooledTempFile;

    #[test]
    fn kernel_requirements_never_reject_a_matching_completion() {
        let expressions = [
            "bus 1 and (in or payload contains 0x61)",
            "bus 1 or payload contains 0x61",
            "not (bus 1 and status 0)",
            "not (bus 1 or status 0)",
            "(bus 1 and status 0) or (bus 1 and event submit)",
            "not (not in or not bulk)",
            "not (payload[0] = 0x61 or not bus 1)",
            "bus > -1 and dev & 3 != 2",
            "vid = 0x1234 and requested >= 1 and event complete",
            "status = -32 or latency > 1ms",
        ];
        for expression in expressions {
            let filter = Filter::parse(expression).unwrap();
            let kernel = filter.kernel_predicates();
            for bus in 1..=2 {
                for endpoint in [1, 0x81] {
                    for status in [0, -32] {
                        for payload in *b"ab" {
                            let mut event = Event {
                                source_id: 0,
                                meta: EventMeta {
                                    bus,
                                    device: 5,
                                    endpoint,
                                    transfer_type: 3,
                                    event_type: b'C',
                                    status,
                                    vid: 0x1234,
                                    requested_len: 1,
                                    actual_len: 1,
                                    payload_len: 1,
                                    has_data: 1,
                                    ..EventMeta::default()
                                },
                                iso: vec![],
                                payload: SpooledTempFile::new(1024),
                                identity_known: true,
                                requested_known: true,
                            };
                            event.payload.write_all(&[payload]).unwrap();
                            if filter.matches(&mut event, Some(2_000_000)).unwrap() {
                                let submit = EventMeta {
                                    event_type: b'S',
                                    status: -115,
                                    actual_len: 0,
                                    has_data: 0,
                                    payload_len: 0,
                                    ..event.meta
                                };
                                assert!(
                                    kernel.iter().all(|p| p.matches(&submit)),
                                    "false negative: {expression} {submit:?}"
                                );
                            }
                        }
                    }
                }
            }
        }
    }
}
