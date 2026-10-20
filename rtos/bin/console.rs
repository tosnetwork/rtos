/*
 * RTOS project modifications (2026-10-10): project and crate naming.
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */

//! The node console. It talks to the control port with the reference
//! console's command names, argument syntax, output text and exit codes.

use adnl::{
    client::{AdnlClient, AdnlClientConfig},
    common::{TaggedTlObject, Timeouts},
};
use rtos_api::{
    deserialize_boxed, serialize_boxed,
    ton::{
        self,
        engine::validator::ControlQueryError,
        rpc::engine::validator::{
            AddAdnlId, AddCustomOverlay, AddValidatorAdnlAddress, AddValidatorPermanentKey,
            AddValidatorTempKey, ControlQuery, DelAdnlId, DelCustomOverlay,
            DelValidatorAdnlAddress, DelValidatorPermanentKey, DelValidatorTempKey,
            ExportAllPrivateKeys, ExportPublicKey, GenerateKeyPair, GetConfig, GetStats, GetTime,
            ImportPrivateKey, ImportShardOverlayCertificate, SetExtMessagesBroadcastDisabled,
            SetVerbosity, ShowCustomOverlays, Sign, SignShardOverlayCertificate,
        },
        Bool,
    },
    AnyBoxedSerialize, Constructor, IntoBoxed, TLObject, WireProfile,
};
use rtos_block::{base64_encode, sha256_digest, KeyOption, KeyOptionJson, UInt256};
use secrets_vault::vault_block::get_key_option_factory;
use std::{
    collections::VecDeque,
    fmt,
    io::{BufRead, Write},
    net::SocketAddr,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    sync::Arc,
    time::{Duration, Instant},
};

/// The reference console's per-query timeout.
const QUERY_TIMEOUT: Duration = Duration::from_secs(10);
/// The reference error codes the console reports itself.
const ERROR_CODE_ERROR: i32 = 602;
const ERROR_CODE_PROTOVIOLATION: i32 = 621;
const ERROR_CODE_TIMEOUT: i32 = 652;

/// A reference status: a general error or an OS error, printed as the
/// reference prints a failed status.
#[derive(Clone, Debug, PartialEq)]
struct Status {
    /// The OS error text of an OS error.
    os: Option<String>,
    code: i32,
    message: String,
}

impl Status {
    fn error(message: impl Into<String>) -> Self {
        Self { os: None, code: 0, message: message.into() }
    }

    fn with_code(code: i32, message: impl Into<String>) -> Self {
        Self { os: None, code, message: message.into() }
    }

    /// An OS error with the reference message for the failed operation.
    fn io(error: &std::io::Error, message: String) -> Self {
        match error.raw_os_error() {
            Some(errno) => {
                let text = std::io::Error::from_raw_os_error(errno).to_string();
                let text = match text.rfind(" (os error ") {
                    Some(at) => text[..at].to_string(),
                    None => text,
                };
                Self { os: Some(text), code: errno, message }
            }
            None => Self::error(format!("{message}: {error}")),
        }
    }

    fn prefix(mut self, prefix: &str) -> Self {
        self.message = format!("{prefix}{}", self.message);
        self
    }
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.os {
            None => write!(f, "[Error : {} : {}]", self.code, self.message),
            Some(text) => write!(f, "[PosixError : {} : {} : {}]", text, self.code, self.message),
        }
    }
}

type Res<T> = std::result::Result<T, Status>;

/// Reads a file as the reference file helpers read it.
fn read_file(path: &str) -> Res<Vec<u8>> {
    std::fs::read(path)
        .map_err(|e| Status::io(&e, format!("File \"{path}\" can't be opened for reading")))
}

/// Writes a file as the reference file helpers write it: created for the
/// owner only, truncated if it exists.
fn write_file(path: &str, data: &[u8]) -> Res<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| {
            Status::io(
                &e,
                format!("File \"{path}\" can't be opened/created for writing with truncation"),
            )
        })?;
    file.write_all(data)
        .and_then(|_| file.sync_all())
        .map_err(|e| Status::io(&e, format!("Failed to write file \"{path}\"")))
}

/// The reference decimal parser: the token must be the canonical text of a
/// value of the type.
fn integer<T: std::str::FromStr + ToString>(word: &str) -> Res<T> {
    match word.parse::<T>() {
        Ok(value) if value.to_string() == word => Ok(value),
        _ => Err(Status::error(format!("Can't parse \"{word}\" as number"))),
    }
}

fn hex_decode(word: &str) -> Res<Vec<u8>> {
    if word.len() % 2 != 0 {
        return Err(Status::error("Wrong hex string length"));
    }
    hex::decode(word).map_err(|_| Status::error("Wrong hex string"))
}

/// The reference base64 decoder: padding is required, and bits left over
/// must be zero.
fn base64_decode(text: &str) -> Res<Vec<u8>> {
    let mut data = text.as_bytes();
    let mut padding = 0;
    while let Some((b'=', rest)) = data.split_last() {
        data = rest;
        padding += 1;
    }
    if padding >= 3 {
        return Err(Status::error("Wrong string padding"));
    }
    if (data.len() + padding) & 3 != 0 {
        return Err(Status::error("Wrong padding length"));
    }
    fn value(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some(u32::from(c - b'A')),
            b'a'..=b'z' => Some(u32::from(c - b'a') + 26),
            b'0'..=b'9' => Some(u32::from(c - b'0') + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let mut out = Vec::with_capacity(data.len() / 4 * 3 + 2);
    for chunk in data.chunks(4) {
        let mut c = 0u32;
        for (t, byte) in chunk.iter().enumerate() {
            let v = value(*byte).ok_or_else(|| Status::error("Wrong character in the string"))?;
            c |= v << ((3 - t) * 6);
        }
        let [_, b0, b1, b2] = c.to_be_bytes();
        out.push(b0);
        match chunk.len() {
            2 if c & 0xffff != 0 => return Err(Status::error("Wrong padding in the string")),
            2 => {}
            3 if c & 0xff != 0 => return Err(Status::error("Wrong padding in the string")),
            3 => out.push(b1),
            _ => {
                out.push(b1);
                out.push(b2);
            }
        }
    }
    Ok(out)
}

/// The reference command tokenizer: words separated by white space.
struct Tokenizer<'a> {
    rest: &'a str,
}

impl<'a> Tokenizer<'a> {
    fn new(line: &'a str) -> Self {
        Self { rest: line }
    }

    fn skip_space(&mut self) {
        self.rest = self.rest.trim_start_matches(|c: char| c.is_ascii_whitespace() || c == '\x0b');
    }

    fn endl(&mut self) -> bool {
        self.skip_space();
        self.rest.is_empty()
    }

    fn check_endl(&mut self) -> Res<()> {
        if self.endl() {
            Ok(())
        } else {
            Err(Status::error("extra data after query"))
        }
    }

    fn raw(&mut self) -> Res<&'a str> {
        self.skip_space();
        if self.rest.is_empty() {
            return Err(Status::error("failed to parse token: EOL"));
        }
        let end = self
            .rest
            .find(|c: char| c.is_ascii_whitespace() || c == '\x0b')
            .unwrap_or(self.rest.len());
        let (word, rest) = self.rest.split_at(end);
        self.rest = rest;
        Ok(word)
    }

    fn string(&mut self) -> Res<String> {
        self.raw().map(str::to_string)
    }

    fn integer<T: std::str::FromStr + ToString>(&mut self) -> Res<T> {
        integer(self.raw()?)
    }

    fn hex(&mut self) -> Res<Vec<u8>> {
        hex_decode(self.raw()?)
    }

    /// A key hash: 64 hex digits or 44 base64 characters. A shorter decoded
    /// hash is zero-filled; a longer one is refused.
    fn key_hash(&mut self) -> Res<UInt256> {
        let word = self.raw()?;
        let data = match word.len() {
            64 => hex_decode(word)?,
            44 => base64_decode(word)?,
            _ => return Err(Status::error("cannot parse keyhash: bad length")),
        };
        if data.len() > 32 {
            return Err(Status::error("cannot parse keyhash: bad length"));
        }
        let mut hash = [0u8; 32];
        hash[..data.len()].copy_from_slice(&data);
        Ok(UInt256::from(hash))
    }

    /// A shard: a workchain and a signed shard as two words, or one
    /// `wc:shard` word with 16 hex digits, optionally in parentheses.
    fn shard(&mut self) -> Res<(i32, i64)> {
        let word = self.raw()?;
        if let Ok(workchain) = integer::<i32>(word) {
            let shard = self.integer::<i64>()?;
            return Ok((workchain, shard));
        }
        let text = match word.strip_prefix('(').and_then(|w| w.strip_suffix(')')) {
            Some(inner) => inner,
            None => word,
        };
        let separator = text.find(':').or_else(|| text.find(','));
        let separator = match separator {
            Some(at) if text.len() - at - 1 == 16 => at,
            _ => return Err(Status::error(format!("invalid shard {text}"))),
        };
        let workchain = integer::<i32>(&text[..separator])?;
        let mut shard = 0u64;
        for c in text[separator + 1..].chars() {
            let digit = c.to_digit(16).ok_or_else(|| Status::error("not a hex digit"))?;
            shard = shard.wrapping_mul(16).wrapping_add(u64::from(digit));
        }
        Ok((workchain, shard as i64))
    }
}

/// The key hash as the reference prints it.
fn hex_upper(bytes: &[u8]) -> String {
    hex::encode_upper(bytes)
}

/// The JSON value type names of the reference JSON parser.
fn json_type(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "Null",
        serde_json::Value::Number(_) => "Number",
        serde_json::Value::Bool(_) => "Boolean",
        serde_json::Value::String(_) => "String",
        serde_json::Value::Array(_) => "Array",
        serde_json::Value::Object(_) => "Object",
    }
}

/// Reads TL objects from JSON as the reference schema reader does: absent
/// and null fields keep their defaults, numbers may be strings.
mod tl_json {
    use super::{base64_decode, integer, json_type, Res, Status};
    use rtos_api::ton::{self, Bool};
    use rtos_block::UInt256;
    use serde_json::{Map, Value};

    fn number_text(value: &Value) -> Res<String> {
        match value {
            Value::Number(number) => Ok(number.to_string()),
            Value::String(text) => Ok(text.clone()),
            other => Err(Status::error(format!("Expected number, got {}", json_type(other)))),
        }
    }

    fn int32(value: &Value) -> Res<i32> {
        integer::<i32>(&number_text(value)?)
    }

    fn int64(value: &Value) -> Res<i64> {
        integer::<i64>(&number_text(value)?)
    }

    fn boolean(value: &Value) -> Res<Bool> {
        let flag = match value {
            Value::Bool(flag) => *flag,
            other => match int32(other) {
                Ok(number) => number != 0,
                Err(_) => {
                    return Err(Status::error(format!("Expected bool, got {}", json_type(other))))
                }
            },
        };
        Ok(if flag { Bool::BoolTrue } else { Bool::BoolFalse })
    }

    fn string(value: &Value) -> Res<String> {
        match value {
            Value::String(text) => Ok(text.clone()),
            other => Err(Status::error(format!("Expected string, got {}", json_type(other)))),
        }
    }

    fn int256(value: &Value) -> Res<UInt256> {
        let raw = base64_decode(&string(value)?)?;
        let raw: [u8; 32] = raw.try_into().map_err(|_| Status::error("Wrong length for UInt"))?;
        Ok(UInt256::from(raw))
    }

    fn array(value: &Value) -> Res<&Vec<Value>> {
        match value {
            Value::Array(items) => Ok(items),
            other => Err(Status::error(format!("Expected array, got {}", json_type(other)))),
        }
    }

    /// An object field: `None` when absent or null.
    fn field<'a>(object: &'a Map<String, Value>, name: &str) -> Option<&'a Value> {
        object.get(name).filter(|value| !value.is_null())
    }

    /// Each element of a vector of objects; a null element is a default
    /// object.
    fn objects<T: Default>(
        value: &Value,
        read: impl Fn(&Map<String, Value>) -> Res<T>,
    ) -> Res<Vec<T>> {
        array(value)?
            .iter()
            .map(|item| match item {
                Value::Object(object) => read(object),
                Value::Null => Ok(T::default()),
                other => Err(Status::error(format!("Expected object, got {}", json_type(other)))),
            })
            .collect()
    }

    fn node(
        object: &Map<String, Value>,
    ) -> Res<ton::engine::validator::customoverlaynode::CustomOverlayNode> {
        let mut node = ton::engine::validator::customoverlaynode::CustomOverlayNode::default();
        if let Some(value) = field(object, "adnl_id") {
            node.adnl_id = int256(value)?;
        }
        if let Some(value) = field(object, "msg_sender") {
            node.msg_sender = boolean(value)?;
        }
        if let Some(value) = field(object, "msg_sender_priority") {
            node.msg_sender_priority = int32(value)?;
        }
        if let Some(value) = field(object, "block_sender") {
            node.block_sender = boolean(value)?;
        }
        Ok(node)
    }

    fn shard(object: &Map<String, Value>) -> Res<ton::ton_node::shardid::ShardId> {
        let mut shard = ton::ton_node::shardid::ShardId::default();
        if let Some(value) = field(object, "workchain") {
            shard.workchain = int32(value)?;
        }
        if let Some(value) = field(object, "shard") {
            shard.shard = int64(value)?;
        }
        Ok(shard)
    }

    /// A custom overlay description.
    pub(super) fn custom_overlay(
        object: &Map<String, Value>,
    ) -> Res<ton::engine::validator::customoverlay::CustomOverlay> {
        let mut overlay = ton::engine::validator::customoverlay::CustomOverlay::default();
        if let Some(value) = field(object, "name") {
            overlay.name = string(value)?;
        }
        if let Some(value) = field(object, "nodes") {
            overlay.nodes = objects(value, node)?;
        }
        if let Some(value) = field(object, "sender_shards") {
            overlay.sender_shards = objects(value, shard)?;
        }
        if let Some(value) = field(object, "skip_public_msg_send") {
            overlay.skip_public_msg_send = boolean(value)?;
        }
        if let Some(value) = field(object, "use_quic") {
            overlay.use_quic = boolean(value)?;
        }
        Ok(overlay)
    }
}

/// A private key read from its serialized form, as the reference key
/// import reads it.
fn import_private_key(data: &[u8]) -> Res<ton::PrivateKey> {
    if data.len() < 4 {
        return Err(Status::with_code(ERROR_CODE_PROTOVIOLATION, "too short key"));
    }
    let id = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let key = &data[4..];
    let key = || -> Res<UInt256> {
        let key: [u8; 32] =
            key.try_into().map_err(|_| Status::with_code(ERROR_CODE_ERROR, "bad length"))?;
        Ok(UInt256::from(key))
    };
    if id == ton::pk::privatekey::Ed25519::constructor_const() {
        Ok(ton::PrivateKey::Pk_Ed25519(ton::pk::privatekey::Ed25519 { key: key()? }))
    } else if id == ton::pk::privatekey::Aes::constructor_const() {
        Ok(ton::PrivateKey::Pk_Aes(ton::pk::privatekey::Aes { key: key()? }))
    } else {
        Err(Status::with_code(ERROR_CODE_PROTOVIOLATION, format!("unknown magic {}", id as i32)))
    }
}

/// The short id of a private key: the hash of its serialized public key.
fn private_key_hash(key: &ton::PrivateKey) -> Res<[u8; 32]> {
    let public = match key {
        ton::PrivateKey::Pk_Ed25519(key) => {
            let option = get_key_option_factory()
                .from_private_key(key.key.as_array())
                .map_err(|e| Status::error(e.to_string()))?;
            return Ok(*option.id().data());
        }
        ton::PrivateKey::Pk_Aes(key) => {
            ton::PublicKey::Pub_Aes(ton::pub_::publickey::Aes { key: key.key.clone() })
        }
        _ => return Err(Status::error("private key is not exportable")),
    };
    let bytes = serialize_boxed(&public).map_err(|e| Status::error(e.to_string()))?;
    Ok(sha256_digest(bytes))
}

fn serialized(key: &ton::PrivateKey) -> Res<Vec<u8>> {
    serialize_boxed(key).map_err(|e| Status::error(e.to_string()))
}

/// Reads the answer as the expected type, or fails as the reference console
/// fails on an answer it cannot read.
fn answer<T: AnyBoxedSerialize>(data: &[u8], prefix: &str) -> Res<T> {
    let object = deserialize_boxed(data).map_err(|e| Status::error(format!("{prefix}{e}")))?;
    object
        .downcast::<T>()
        .map_err(|_| Status::error(format!("{prefix}Wrong constructor found at 4")))
}

const INCORRECT: &str = "received incorrect answer: ";

/// What a command does once it is parsed.
enum Action {
    /// Send a query; the closure reads the answer and returns the output.
    Query(TLObject, Box<dyn FnOnce(&[u8]) -> Res<String> + Send>),
    /// Print text without asking the server.
    Print(String),
    /// Close the console.
    Quit,
}

fn query<Q: AnyBoxedSerialize>(
    function: Q,
    receive: impl FnOnce(&[u8]) -> Res<String> + Send + 'static,
) -> Action {
    Action::Query(function.into_tl_object(), Box::new(receive))
}

fn success(data: &[u8]) -> Res<String> {
    answer::<ton::engine::validator::Success>(data, INCORRECT)?;
    Ok("success\n".to_string())
}

/// The commands, by name, with the reference help text.
const COMMANDS: &[(&str, &str)] = &[
    ("add-adnl", "add-adnl <keyhash> <category>\tuse key as ADNL addr"),
    (
        "add-custom-overlay",
        "add-custom-overlay <filename>\tadd custom overlay with config from file <filename>",
    ),
    (
        "add-perm-key",
        "add-perm-key <keyhash> <election-date> <expire-at>\tadd validator permanent key",
    ),
    ("add-temp-key", "add-temp-key <permkeyhash> <keyhash> <expireat>\tadd validator temp key"),
    (
        "add-validator-addr",
        "add-validator-addr <permkeyhash> <keyhash> <expireat>\tadd validator ADNL addr",
    ),
    ("del-adnl", "del-adnl <keyhash>\tdel unused ADNL addr"),
    ("del-custom-overlay", "del-custom-overlay <name>\tdelete custom overlay with name <name>"),
    ("del-perm-key", "del-perm-key <keyhash>\tforce del unused validator permanent key"),
    ("del-temp-key", "del-temp-key <permkeyhash> <keyhash>\tforce del unused validator temp key"),
    (
        "del-validator-addr",
        "del-validator-addr <permkeyhash> <keyhash>\tforce del unused validator ADNL addr",
    ),
    (
        "export-all-private-keys",
        "export-all-private-keys <directory>\texports all private keys from validator engine and \
         stores them to <directory>",
    ),
    ("export-pub", "export-pub <keyhash>\texports public key by key hash"),
    ("export-pubf", "export-pub-f <keyhash> <filename>\texports public key by key hash"),
    ("get-config", "get-config\tdownloads current config"),
    ("get-stats", "get-stats\tprints stats"),
    ("get-time", "get-time\tshows current server unixtime"),
    ("help", "help [command]\tshows help"),
    ("import-f", "import-f <filename>\timport private key"),
    (
        "import-shard-overlay-cert",
        "import-shard-overlay-cert <wc>:<shard> <key> <certfile>\timport certificate for <key> in \
         currently active shard overlay",
    ),
    ("license", "license\tshows license info"),
    ("new-key", "new-key\tgenerates new key pair on server"),
    ("quit", "quit\tcloses client"),
    (
        "set-ext-messages-broadcast-disabled",
        "set-ext-messages-broadcast-disabled <value>\tdisable broadcasting and rebroadcasting ext \
         messages; value is 0 or 1.",
    ),
    ("set-verbosity", "set-verbosity <value>\tchanges verbosity level"),
    ("show-custom-overlays", "show-custom-overlays\tshow all custom overlays"),
    ("sign", "sign <keyhash> <data>\tsigns bytestring with privkey"),
    ("sign-f", "sign-f <keyhash> <infile> <outfile>\tsigns bytestring with privkey"),
    (
        "sign-shard-overlay-cert",
        "sign-shard-overlay-cert <wc>:<shard> <key> <expireat> <maxsize> <outfile>\tsign \
         certificate for <key> in currently active shard overlay",
    ),
];

const LICENSE: &str = "Copyright (C) 2019 Telegram Systems LLP.\n\
License GPLv2+: GNU GPL version 2 or later <https://www.gnu.org/licenses/gpl-2.0.html>\n\
This is free software: you are free to change and redistribute it.\n\
There is NO WARRANTY, to the extent permitted by law.\n";

fn help(command: Option<&str>) -> String {
    match command {
        None => {
            let mut text = "list of available commands:\n".to_string();
            for (_, help) in COMMANDS {
                text.push_str(help);
                text.push('\n');
            }
            text
        }
        Some(name) => match COMMANDS.iter().find(|(command, _)| *command == name) {
            Some((_, help)) => format!("{help}\n"),
            None => format!("unknown command '{name}'\n"),
        },
    }
}

/// Parses a command and prepares what it does, as the reference command's
/// argument reading and sending do. `Ok(None)` is a name that is not a
/// command.
fn prepare(name: &str, t: &mut Tokenizer<'_>) -> Res<Option<Action>> {
    let action = match name {
        "get-time" => {
            t.check_endl()?;
            query(GetTime, |data| {
                let time = answer::<ton::engine::validator::Time>(data, INCORRECT)?.only();
                Ok(format!("received validator time: time={}\n", time.time))
            })
        }
        "help" => {
            if t.endl() {
                return Ok(Some(Action::Print(help(None))));
            }
            let command = t.string()?;
            t.check_endl()?;
            Action::Print(help(Some(&command)))
        }
        "license" => {
            t.check_endl()?;
            Action::Print(LICENSE.to_string())
        }
        "quit" => {
            t.check_endl()?;
            Action::Quit
        }
        "new-key" => {
            t.check_endl()?;
            query(GenerateKeyPair, |data| {
                let hash = answer::<ton::engine::validator::KeyHash>(data, INCORRECT)?.only();
                Ok(format!("created new key {}\n", hex_upper(hash.key_hash.as_slice())))
            })
        }
        "import-f" => {
            let file = t.string()?;
            t.check_endl()?;
            let key = import_private_key(&read_file(&file)?)?;
            query(ImportPrivateKey { key }, |data| {
                let hash = answer::<ton::engine::validator::KeyHash>(data, INCORRECT)?.only();
                Ok(format!("imported key {}\n", hex_upper(hash.key_hash.as_slice())))
            })
        }
        "export-pub" => {
            let key_hash = t.key_hash()?;
            t.check_endl()?;
            query(ExportPublicKey { key_hash }, |data| {
                answer::<ton::PublicKey>(data, INCORRECT)?;
                Ok(format!("got public key: {}\n", base64_encode(data)))
            })
        }
        "export-pubf" => {
            let key_hash = t.key_hash()?;
            let file = t.string()?;
            t.check_endl()?;
            query(ExportPublicKey { key_hash }, move |data| {
                answer::<ton::PublicKey>(data, INCORRECT)?;
                write_file(&file, data)?;
                Ok("got public key\n".to_string())
            })
        }
        "sign" => {
            let key_hash = t.key_hash()?;
            let data = t.hex()?;
            t.check_endl()?;
            query(Sign { key_hash, data }, |data| {
                let signature =
                    answer::<ton::engine::validator::Signature>(data, INCORRECT)?.only();
                Ok(format!("got signature {}\n", base64_encode(&signature.signature)))
            })
        }
        "sign-f" => {
            let key_hash = t.key_hash()?;
            let in_file = t.string()?;
            let out_file = t.string()?;
            t.check_endl()?;
            let data = read_file(&in_file)?;
            query(Sign { key_hash, data }, move |data| {
                let signature =
                    answer::<ton::engine::validator::Signature>(data, INCORRECT)?.only();
                write_file(&out_file, &signature.signature)?;
                Ok("got signature\n".to_string())
            })
        }
        "export-all-private-keys" => {
            let directory = t.string()?;
            t.check_endl()?;
            let client =
                get_key_option_factory().generate().map_err(|e| Status::error(e.to_string()))?;
            let public: [u8; 32] = client
                .pub_key()
                .ok()
                .and_then(|key| key.try_into().ok())
                .ok_or_else(|| Status::error("cannot create the client key"))?;
            let encryption_key = ton::PublicKey::Pub_Ed25519(ton::pub_::publickey::Ed25519 {
                key: UInt256::from(public),
            });
            query(ExportAllPrivateKeys { encryption_key }, move |data| {
                export_keys(&client, data, &directory)
            })
        }
        "add-adnl" => {
            let key_hash = t.key_hash()?;
            let category = t.integer::<u32>()?;
            if category > 15 {
                return Err(Status::error("too big category"));
            }
            t.check_endl()?;
            query(AddAdnlId { key_hash, category: category as i32 }, success)
        }
        "add-perm-key" => {
            let key_hash = t.key_hash()?;
            let election_date = t.integer::<u32>()?;
            let expire_at = t.integer::<u32>()?;
            t.check_endl()?;
            // The wire fields keep the bit patterns of the unsigned values.
            query(
                AddValidatorPermanentKey {
                    key_hash,
                    election_date: election_date as i32,
                    ttl: expire_at as i32,
                },
                success,
            )
        }
        "add-temp-key" => {
            let permanent_key_hash = t.key_hash()?;
            let key_hash = t.key_hash()?;
            let expire_at = t.integer::<u32>()?;
            t.check_endl()?;
            query(
                AddValidatorTempKey { permanent_key_hash, key_hash, ttl: expire_at as i32 },
                success,
            )
        }
        "add-validator-addr" => {
            let permanent_key_hash = t.key_hash()?;
            let key_hash = t.key_hash()?;
            let expire_at = t.integer::<u32>()?;
            t.check_endl()?;
            query(
                AddValidatorAdnlAddress { permanent_key_hash, key_hash, ttl: expire_at as i32 },
                success,
            )
        }
        "del-adnl" => {
            let key_hash = t.key_hash()?;
            t.check_endl()?;
            query(DelAdnlId { key_hash }, success)
        }
        "del-perm-key" => {
            let key_hash = t.key_hash()?;
            t.check_endl()?;
            query(DelValidatorPermanentKey { key_hash }, success)
        }
        "del-temp-key" => {
            let permanent_key_hash = t.key_hash()?;
            let key_hash = t.key_hash()?;
            t.check_endl()?;
            query(DelValidatorTempKey { permanent_key_hash, key_hash }, success)
        }
        "del-validator-addr" => {
            let permanent_key_hash = t.key_hash()?;
            let key_hash = t.key_hash()?;
            t.check_endl()?;
            query(DelValidatorAdnlAddress { permanent_key_hash, key_hash }, success)
        }
        "get-config" => {
            t.check_endl()?;
            query(GetConfig, |data| {
                let config = answer::<ton::engine::validator::JsonConfig>(data, INCORRECT)?.only();
                Ok(format!("---------\n{}--------\n", config.data))
            })
        }
        "set-verbosity" => {
            let verbosity = t.integer::<u8>()?;
            t.check_endl()?;
            query(SetVerbosity { verbosity: i32::from(verbosity) }, success)
        }
        "get-stats" => {
            t.check_endl()?;
            query(GetStats, |data| {
                let stats = answer::<ton::engine::validator::Stats>(data, INCORRECT)?.only();
                Ok(stats
                    .stats
                    .iter()
                    .map(|stat| format!("{}\t\t\t{}\n", stat.key, stat.value))
                    .collect())
            })
        }
        // The reference reads no end of line for the three commands below.
        "sign-shard-overlay-cert" => {
            let (workchain, shard) = t.shard()?;
            let key = t.key_hash()?;
            let expire_at = t.integer::<i32>()?;
            let max_size = t.integer::<u32>()?;
            let out_file = t.string()?;
            query(
                SignShardOverlayCertificate {
                    workchain,
                    shard,
                    signed_key: ton::engine::validator::keyhash::KeyHash { key_hash: key }
                        .into_boxed(),
                    expire_at,
                    // The wire field is signed; the size keeps its bit pattern.
                    max_size: max_size as i32,
                },
                move |data| {
                    match answer::<ton::overlay::Certificate>(data, "received incorrect cert: ")? {
                        ton::overlay::Certificate::Overlay_Certificate(_) => {}
                        _ => {
                            return Err(Status::error(
                                "received incorrect cert: Wrong constructor found at 4",
                            ))
                        }
                    }
                    write_file(&out_file, data)
                        .map_err(|e| e.prefix("Failed to write certificate to file: "))?;
                    Ok("saved certificate\n".to_string())
                },
            )
        }
        "import-shard-overlay-cert" => {
            let (workchain, shard) = t.shard()?;
            let key = t.key_hash()?;
            let in_file = t.string()?;
            let data = read_file(&in_file)?;
            let cert = certificate(&data)?;
            query(
                ImportShardOverlayCertificate {
                    workchain,
                    shard,
                    signed_key: ton::engine::validator::keyhash::KeyHash { key_hash: key }
                        .into_boxed(),
                    cert,
                },
                |data| {
                    answer::<ton::engine::validator::Success>(data, INCORRECT)?;
                    Ok("successfully sent certificate to overlay manager\n".to_string())
                },
            )
        }
        "set-ext-messages-broadcast-disabled" => {
            let value = t.integer::<i32>()?;
            if !(0..=1).contains(&value) {
                return Err(Status::error("value should be 0 or 1"));
            }
            let disabled = if value == 1 { Bool::BoolTrue } else { Bool::BoolFalse };
            query(SetExtMessagesBroadcastDisabled { disabled }, success)
        }
        "add-custom-overlay" => {
            let file = t.string()?;
            t.check_endl()?;
            let data = read_file(&file)?;
            let json: serde_json::Value =
                serde_json::from_slice(&data).map_err(|e| Status::error(e.to_string()))?;
            let object = json.as_object().ok_or_else(|| {
                Status::error(format!("Expected object, got {}", json_type(&json)))
            })?;
            let overlay = tl_json::custom_overlay(object)?;
            query(AddCustomOverlay { overlay }, success)
        }
        "del-custom-overlay" => {
            let name = t.string()?;
            t.check_endl()?;
            query(DelCustomOverlay { name }, success)
        }
        "show-custom-overlays" => {
            t.check_endl()?;
            query(ShowCustomOverlays, |data| {
                let config =
                    answer::<ton::engine::validator::CustomOverlaysConfig>(data, INCORRECT)?;
                Ok(show_custom_overlays(&config.only()))
            })
        }
        _ => return Ok(None),
    };
    Ok(Some(action))
}

/// An overlay certificate from a file, read as the reference reads it.
fn certificate(data: &[u8]) -> Res<ton::overlay::Certificate> {
    if data.len() < 4 {
        return Err(Status::error("incorrect certificateNot enough data to read at 0"));
    }
    match deserialize_boxed(data) {
        Ok(object) => object.downcast::<ton::overlay::Certificate>().map_err(|_| {
            let id = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            Status::error(format!("incorrect certificateUnknown constructor found 0x{id:08x} at 4"))
        }),
        Err(error) => {
            let id = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            let known = [
                ton::overlay::Certificate::Overlay_Certificate(Default::default()),
                ton::overlay::Certificate::Overlay_CertificateV2(Default::default()),
                ton::overlay::Certificate::Overlay_EmptyCertificate,
            ]
            .iter()
            .filter_map(|certificate| serialize_boxed(certificate).ok())
            .any(|bytes| bytes.get(..4) == Some(&data[..4]));
            if known {
                Err(Status::error(format!("incorrect certificate{error}")))
            } else {
                Err(Status::error(format!(
                    "incorrect certificateUnknown constructor found 0x{id:08x} at 4"
                )))
            }
        }
    }
}

/// The reference listing of custom overlays.
fn show_custom_overlays(
    config: &ton::engine::validator::customoverlaysconfig::CustomOverlaysConfig,
) -> String {
    let mut text = format!("{} custom overlays:\n\n", config.overlays.len());
    for overlay in config.overlays.iter() {
        text.push_str(&format!("Overlay \"{}\": {} nodes\n", overlay.name, overlay.nodes.len()));
        for node in overlay.nodes.iter() {
            text.push_str(&format!("  {}", base64_encode(node.adnl_id.as_slice())));
            if node.msg_sender == Bool::BoolTrue {
                text.push_str(&format!(" (msg sender, p={})", node.msg_sender_priority));
            }
            if node.block_sender == Bool::BoolTrue {
                text.push_str(" (block sender)");
            }
            text.push('\n');
        }
        if !overlay.sender_shards.is_empty() {
            text.push_str("Sender shards:\n");
            for shard in overlay.sender_shards.iter() {
                text.push_str(&format!("  ({},{:016x})\n", shard.workchain, shard.shard as u64));
            }
        }
        if overlay.skip_public_msg_send == Bool::BoolTrue {
            text.push_str("Don't send external messages to public overlays\n");
        }
        if overlay.use_quic == Bool::BoolTrue {
            text.push_str("Use QUIC for custom overlay broadcasts\n");
        }
        text.push('\n');
    }
    text
}

/// Decrypts the exported key set and stores each key in the directory under
/// its hash, as the reference console does.
fn export_keys(client: &Arc<dyn KeyOption>, data: &[u8], directory: &str) -> Res<String> {
    let exported = answer::<ton::engine::validator::ExportedPrivateKeys>(data, INCORRECT)?.only();
    let plain = rtos::network::control::decrypt_with(client, &exported.encrypted_data)
        .map_err(|e| Status::error(format!("cannot decrypt data: {e}")))?;
    if plain.len() < 32 {
        return Err(Status::error("data is too small"));
    }
    let mut rest = &plain[..plain.len() - 32];
    let mut keys = Vec::new();
    while !rest.is_empty() {
        if rest.len() < 4 {
            return Err(Status::error("unexpected end of data"));
        }
        let size = u32::from_le_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
        // The reference compares the size with what is left before the
        // size word is taken off.
        if size > rest.len() {
            return Err(Status::error("unexpected end of data"));
        }
        rest = &rest[4..];
        let take = size.min(rest.len());
        let key = import_private_key(&rest[..take])
            .map_err(|e| e.prefix("cannot parse private key: "))?;
        keys.push(key);
        rest = &rest[take..];
    }
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(directory)
        .map_err(|e| Status::io(&e, format!("cannot create directory {directory}: ")))?;
    let mut text = format!("exported {} private keys\n", keys.len());
    for key in &keys {
        let hash = hex_upper(&private_key_hash(key)?);
        write_file(&format!("{directory}/{hash}"), &serialized(key)?)
            .map_err(|e| e.prefix("failed to write file: "))?;
        text.push_str(&format!("pubkey_hash {hash}\n"));
    }
    text.push_str(&format!("written all files to {directory}\n"));
    Ok(text)
}

/// The control port connection; a test replaces it.
#[async_trait::async_trait]
trait Transport: Send {
    /// Sends one function wrapped in a control query; the answer bytes, or
    /// the error the server or the connection reports.
    async fn send(&mut self, function: &TLObject) -> Res<Vec<u8>>;
}

struct ControlPort {
    adnl: AdnlClient,
}

#[async_trait::async_trait]
impl Transport for ControlPort {
    async fn send(&mut self, function: &TLObject) -> Res<Vec<u8>> {
        let data = serialize_boxed(function).map_err(|e| Status::error(e.to_string()))?;
        let wrapped: TaggedTlObject = ControlQuery { data }.into_tl_object().into();
        let answer =
            tokio::time::timeout(QUERY_TIMEOUT, self.adnl.query_raw(&wrapped, WireProfile::Legacy))
                .await
                .map_err(|_| Status::with_code(ERROR_CODE_TIMEOUT, "timeout for adnl query query"))?
                .map_err(|e| Status::error(e.to_string()))?;
        if let Ok(object) = deserialize_boxed(&answer) {
            if let Ok(error) = object.downcast::<ControlQueryError>() {
                let error = error.only();
                return Err(Status::with_code(error.code, error.message));
            }
        }
        Ok(answer)
    }
}

/// How one command line ended.
#[derive(Debug, PartialEq)]
enum Outcome {
    Done,
    Failed,
    /// Not a command: the reference console goes on waiting.
    Unknown,
    Quit,
}

/// Runs one command line and returns its output and outcome.
async fn run_line(line: &str, transport: &mut dyn Transport) -> (String, Outcome) {
    let mut tokenizer = Tokenizer::new(line);
    if tokenizer.endl() {
        return (String::new(), Outcome::Unknown);
    }
    let name = match tokenizer.raw() {
        Ok(name) => name,
        Err(_) => return (String::new(), Outcome::Unknown),
    };
    let failed = |status: Status| (format!("Failed {name} query: {status}\n"), Outcome::Failed);
    match prepare(name, &mut tokenizer) {
        Ok(None) => (format!("unknown command '{name}'\n"), Outcome::Unknown),
        Ok(Some(Action::Print(text))) => (text, Outcome::Done),
        Ok(Some(Action::Quit)) => (String::new(), Outcome::Quit),
        Ok(Some(Action::Query(function, receive))) => match transport.send(&function).await {
            Ok(data) => match receive(&data) {
                Ok(text) => (text, Outcome::Done),
                Err(status) => failed(status),
            },
            Err(status) => failed(status),
        },
        Err(status) => failed(status),
    }
}

/// The console's connection settings file: the client key, the server
/// address and the server key.
#[derive(serde::Deserialize)]
struct ConnectionJson {
    client_key: Option<KeyOptionJson>,
    server_address: String,
    server_key: KeyOptionJson,
    timeouts: Option<Timeouts>,
}

#[derive(serde::Deserialize)]
struct ConsoleJson {
    config: Option<ConnectionJson>,
}

struct Connection {
    address: SocketAddr,
    client: Arc<dyn KeyOption>,
    server: Arc<dyn KeyOption>,
    timeouts: Timeouts,
}

fn fatal(message: String) -> ! {
    eprintln!("{message}");
    std::process::exit(2)
}

/// A key from a file holding the serialized key, as the reference console
/// reads its key files.
fn key_file(path: &str, private: bool) -> Res<Arc<dyn KeyOption>> {
    let data = read_file(path).map_err(|e| e.prefix("failed to read: "))?;
    if private {
        match import_private_key(&data)? {
            ton::PrivateKey::Pk_Ed25519(key) => get_key_option_factory()
                .from_private_key(key.key.as_array())
                .map_err(|e| Status::error(e.to_string())),
            _ => Err(Status::error("the console key must be an Ed25519 key")),
        }
    } else {
        let key = deserialize_boxed(&data)
            .ok()
            .and_then(|object| object.downcast::<ton::PublicKey>().ok())
            .ok_or_else(|| Status::error("bad public key"))?;
        match key {
            ton::PublicKey::Pub_Ed25519(key) => {
                Ok(get_key_option_factory().from_public_key(key.key.as_array()))
            }
            _ => Err(Status::error("the server key must be an Ed25519 key")),
        }
    }
}

/// The connection from a settings file: `{"config": {"client_key",
/// "server_address", "server_key"}}`. Without a client key the console
/// uses a new one.
fn connection_from_json(text: &[u8]) -> Res<Connection> {
    let json: ConsoleJson =
        serde_json::from_slice(text).map_err(|e| Status::error(format!("bad config: {e}")))?;
    let json = json.config.ok_or_else(|| Status::error("config must hold \"config\""))?;
    let factory = get_key_option_factory();
    let client = match &json.client_key {
        Some(key) => factory.from_private_key_json(key),
        None => factory.generate(),
    }
    .map_err(|e| Status::error(e.to_string()))?;
    let server =
        factory.from_public_key_json(&json.server_key).map_err(|e| Status::error(e.to_string()))?;
    let address = json
        .server_address
        .parse()
        .map_err(|e| Status::error(format!("bad server address: {e}")))?;
    let timeouts = json.timeouts.unwrap_or_default();
    Ok(Connection { address, client, server, timeouts })
}

fn connection(args: &clap::ArgMatches) -> Res<Connection> {
    if let Some(path) = args.get_one::<String>("config") {
        return connection_from_json(&read_file(path)?);
    }
    let address = args
        .get_one::<String>("address")
        .ok_or_else(|| Status::error("server address is not set"))?;
    let address = std::net::ToSocketAddrs::to_socket_addrs(address.as_str())
        .ok()
        .and_then(|mut all| all.next())
        .ok_or_else(|| Status::error(format!("bad server address {address}")))?;
    let client = key_file(
        args.get_one::<String>("key").ok_or_else(|| Status::error("private key is not set"))?,
        true,
    )
    .map_err(|e| Status::error(format!("bad private key: {e}")))?;
    let server = key_file(
        args.get_one::<String>("pub")
            .ok_or_else(|| Status::error("server public key is not set"))?,
        false,
    )
    .map_err(|e| Status::error(format!("bad server public key: {e}")))?;
    Ok(Connection { address, client, server, timeouts: Timeouts::default() })
}

fn args() -> clap::ArgMatches {
    clap::Command::new("console")
        .about("console for validator for TOS Blockchain")
        .version(env!("CARGO_PKG_VERSION"))
        .arg(
            clap::Arg::new("address").short('a').long("address").help("server address").num_args(1),
        )
        .arg(clap::Arg::new("key").short('k').long("key").help("private key").num_args(1))
        .arg(clap::Arg::new("pub").short('p').long("pub").help("server public key").num_args(1))
        .arg(
            clap::Arg::new("config")
                .short('C')
                .long("config")
                .help("connection settings file: client key, server address and server key")
                .num_args(1),
        )
        .arg(
            clap::Arg::new("disable-readline")
                .short('r')
                .long("disable-readline")
                .help("disable readline")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            clap::Arg::new("enable-readline")
                .short('R')
                .long("enable-readline")
                .help("enable readline")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            clap::Arg::new("verbosity")
                .short('v')
                .long("verbosity")
                .help("set verbosity level")
                .num_args(1)
                .value_parser(|value: &str| match integer::<i32>(value) {
                    Ok(level @ 0..=9) => Ok(level),
                    _ => Err("verbosity must be 0..9".to_string()),
                }),
        )
        .arg(
            clap::Arg::new("cmd")
                .short('c')
                .long("cmd")
                .help("schedule command")
                .allow_hyphen_values(true)
                .action(clap::ArgAction::Append)
                .num_args(1),
        )
        .arg(
            clap::Arg::new("timeout")
                .short('t')
                .long("timeout")
                .help("timeout in batch mode")
                .num_args(1)
                .value_parser(|value: &str| value.parse::<f64>().map_err(|e| e.to_string())),
        )
        .get_matches()
}

/// Connects, retrying until the server answers, as the reference client
/// keeps reconnecting.
async fn connect(connection: &Connection) -> AdnlClient {
    let config = AdnlClientConfig::new(
        Some(connection.client.clone()),
        connection.address,
        connection.server.clone(),
        connection.timeouts.clone(),
    );
    loop {
        match AdnlClient::connect(&config).await {
            Ok(client) => return client,
            Err(error) => {
                log::debug!("connection to {} failed: {error}", connection.address);
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }
}

fn say(text: &str) {
    let mut stdout = std::io::stdout().lock();
    // A closed output is not the console's failure to report.
    let _ = stdout.write_all(text.as_bytes());
    let _ = stdout.flush();
}

async fn console(args: clap::ArgMatches) -> i32 {
    let connection = match connection(&args) {
        Ok(connection) => connection,
        Err(status) => fatal(status.message),
    };
    let commands: VecDeque<String> =
        args.get_many::<String>("cmd").map(|all| all.cloned().collect()).unwrap_or_default();
    let batch = !commands.is_empty();
    say(&format!(
        "connecting to [{}]\nlocal key: {}\nremote key: {}\n",
        connection.address,
        hex_upper(connection.client.id().data()),
        hex_upper(connection.server.id().data()),
    ));
    let mut port = ControlPort { adnl: connect(&connection).await };
    say("conn ready\n");
    if batch {
        run_batch(commands, &mut port).await
    } else {
        run_interactive(&mut port).await
    }
}

/// Runs the scheduled commands in order. A failure exits with 2. A line
/// that is not a command stops the run; with nothing after it the console
/// exits with 0, otherwise it waits, as the reference console does.
async fn run_batch(mut commands: VecDeque<String>, transport: &mut dyn Transport) -> i32 {
    while let Some(line) = commands.pop_front() {
        let (text, outcome) = run_line(&line, transport).await;
        say(&text);
        match outcome {
            Outcome::Done => {}
            Outcome::Failed => return 2,
            Outcome::Quit => return 0,
            Outcome::Unknown if commands.is_empty() => return 0,
            Outcome::Unknown => std::future::pending::<()>().await,
        }
    }
    0
}

async fn run_interactive(transport: &mut dyn Transport) -> i32 {
    let (lines_tx, mut lines) = tokio::sync::mpsc::unbounded_channel::<String>();
    std::thread::spawn(move || {
        for line in std::io::stdin().lock().lines() {
            let Ok(line) = line else { break };
            if lines_tx.send(line).is_err() {
                break;
            }
        }
    });
    while let Some(line) = lines.recv().await {
        let (text, outcome) = run_line(&line, transport).await;
        say(&text);
        if outcome == Outcome::Quit {
            break;
        }
    }
    0
}

#[tokio::main]
async fn main() {
    let args = args();
    // The batch deadline exits with 7 wherever the console is.
    if let Some(seconds) = args.get_one::<f64>("timeout").copied() {
        // A deadline too far to represent never comes.
        if let Ok(delay) = Duration::try_from_secs_f64(seconds.max(0.0)) {
            let deadline = Instant::now() + delay;
            std::thread::spawn(move || {
                std::thread::sleep(deadline.saturating_duration_since(Instant::now()));
                std::process::exit(7);
            });
        }
    }
    let code = console(args).await;
    std::process::exit(code);
}

#[cfg(test)]
mod tests {

    use super::*;
    use rtos::{
        collator_test_bundle::create_engine_allocated,
        config::TonNodeConfig,
        engine_traits::{EngineAlloc, EngineOperations},
        internal_db::{state_gc_resolver::AllowStateGcSmartResolver, InternalDb, InternalDbConfig},
        network::{
            control::{encrypt_for, ControlServer, DataSource},
            node_network::NodeNetwork,
        },
        shard_state::ShardStateStuff,
        shard_states_keeper::PinnedShardStateGuard,
        validator::validator_manager::ValidationStatus,
    };
    #[cfg(feature = "telemetry")]
    use rtos::{collator_test_bundle::create_engine_telemetry, engine_traits::EngineTelemetry};
    use rtos_block::{
        base64_decode as std_base64_decode, error, fail, write_boc, Account, AccountId,
        AccountIdPrefixFull, AccountStorage, Block, BlockIdExt, BlockInfo, Cell,
        CurrencyCollection, Deserializable, HashmapAugType, IBitstring, Message, MsgAddressInt,
        Result, Serializable, ShardAccount, ShardAccounts, ShardIdent, ShardStateUnsplit,
        SliceData, StateInit, StorageInfo, TickTock,
    };
    use std::{
        collections::HashMap,
        fs,
        path::Path,
        sync::atomic::{AtomicU16, AtomicU64, AtomicU8, Ordering},
        thread,
    };
    use storage::block_handle_db::BlockHandle;

    include!("../../block/src/tests/test_utils.rs");

    const CFG_DIR: &str = "../target";
    const CFG_NODE_FILE: &str = "light_node.json";
    const CFG_GLOB_FILE: &str = "light_global.json";
    const DB_PATH: &str = "../target/console_test";

    struct TestEngine {
        counter: Option<Arc<AtomicU64>>,
        db: InternalDb,
        index: u16,
        states: HashMap<BlockIdExt, Arc<ShardStateStuff>>,
        blocks: HashMap<BlockIdExt, Vec<u8>>,
        last_mc_state: Arc<ShardStateStuff>,
        last_validation_time: lockfree::map::Map<ShardIdent, u64>,
        #[cfg(feature = "telemetry")]
        telemetry: Arc<EngineTelemetry>,
        allocated: Arc<EngineAlloc>,
    }

    impl TestEngine {
        async fn new(
            index: u16,
            counter: Option<Arc<AtomicU64>>,
            #[cfg(feature = "telemetry")] telemetry: Arc<EngineTelemetry>,
            allocated: Arc<EngineAlloc>,
        ) -> Self {
            let mut db = Err(error!("Unreachable"));
            let db_path = format!("{}{}", DB_PATH, index);
            for _ in 0..10 {
                fs::remove_dir_all(&db_path).ok();
                let db_config =
                    InternalDbConfig { db_directory: db_path.clone(), ..Default::default() };
                db = InternalDb::with_update(
                    db_config,
                    false,
                    false,
                    false,
                    None,
                    &|| Ok(()),
                    None,
                    Arc::new(AtomicU8::new(0)),
                    None,
                    #[cfg(feature = "telemetry")]
                    telemetry.clone(),
                    allocated.clone(),
                )
                .await;
                if db.is_ok() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(1000)).await;
            }
            let db = db.unwrap_or_else(|err| panic!("Can't create db: {}", err));

            let mut states = HashMap::new();

            let mut ss = ShardStateUnsplit::with_ident(ShardIdent::full(0));
            let account = generate_test_account(true, AccountTestOptions::with_default_setup(true));
            let account_id = account.get_id().unwrap();
            ss.insert_account(
                &account_id,
                &ShardAccount::with_params(&account, UInt256::default(), 0).unwrap(),
            )
            .unwrap();
            let cell = ss.serialize().unwrap();
            let bytes = write_boc(&cell).unwrap();
            let block_id = BlockIdExt::with_params(
                ShardIdent::full(0),
                0,
                cell.repr_hash().clone(),
                UInt256::calc_file_hash(&bytes),
            );
            let shard_state = ShardStateStuff::deserialize_zerostate(
                block_id.clone(),
                &bytes,
                #[cfg(feature = "telemetry")]
                &telemetry,
                &allocated,
            )
            .unwrap();
            states.insert(block_id, shard_state.clone());

            let ss = Self::prepare_zero_state(shard_state.block_id()).unwrap();
            let cell = ss.serialize().unwrap();
            let bytes = write_boc(&cell).unwrap();
            let block_id = BlockIdExt::with_params(
                ShardIdent::masterchain(),
                ss.seq_no(),
                cell.repr_hash().clone(),
                UInt256::calc_file_hash(&bytes),
            );

            let last_mc_state = ShardStateStuff::deserialize_zerostate(
                block_id,
                &bytes,
                #[cfg(feature = "telemetry")]
                &telemetry,
                &allocated,
            )
            .unwrap();

            states.insert(last_mc_state.block_id().clone(), last_mc_state.clone());
            db.create_or_load_block_handle(last_mc_state.block_id(), None, Some(1), None)
                .unwrap()
                ._to_created()
                .unwrap();

            Self {
                counter,
                db,
                index,
                states,
                blocks: HashMap::new(),
                last_mc_state,
                last_validation_time: lockfree::map::Map::new(),
                telemetry,
                allocated,
            }
        }

        fn prepare_zero_state(wc_zero_state_id: &BlockIdExt) -> Result<ShardStateUnsplit> {
            let config_addr = AccountId::from([0x55; 32]);

            let json = serde_json::from_str(SAMPLE_ZERO_STATE)?;
            let mut ss = rtos_block_json::parse_state(&json)?;
            //  ShardStateUnsplit::with_ident(ShardIdent::masterchain());
            let mut ms = ss.read_custom()?.unwrap();
            ms.shards.add_workchain(
                0,
                0,
                wc_zero_state_id.root_hash().clone(),
                wc_zero_state_id.file_hash().clone(),
            )?;
            ss.write_custom(Some(&ms))?;
            let address = MsgAddressInt::standard(-1, config_addr.clone());
            let public_key = std_base64_decode(PUBLIC_CONFIG_KEY).unwrap();
            let mut builder = 7u32.write_to_new_cell()?; // seqno
            builder.append_raw(&public_key, 256)?;
            builder.append_bit_zero()?;
            builder.checked_append_reference(Default::default())?;
            let code = Default::default(); // empty code
            let data = builder.into_cell()?;
            let mut state_init = StateInit::with_code_and_data(code, data);
            state_init.special = Some(TickTock::with_values(true, true));
            let balance = CurrencyCollection::with_coins(1_000_000_000);
            let mut config_smc = Account::active(
                address,
                balance,
                0,
                0,
                state_init,
                ms.config().size_limits_config()?.acc_state_cells_for_storage_dict,
            )?;
            config_smc.update_config_smc(ms.config())?;
            // let cell = config_smc.serialize()?;
            // panic!("{cell:#.10}");
            let mut shard_accounts = ShardAccounts::new();
            let account = ShardAccount::with_params(&config_smc, UInt256::default(), 0)?;
            shard_accounts.set_augmentable(&config_addr, &account)?;
            // panic!("{:#.10}", shard_accounts.serialize()?);
            ss.write_accounts(&shard_accounts)?;

            Ok(ss)
        }

        fn init_internal(&mut self) -> Result<()> {
            let mut ss = self.last_mc_state.state()?.clone();
            self.update_mc_state(&mut ss, 17).unwrap();
            self.last_mc_state = self.update_mc_state(&mut ss, 19).unwrap();
            Ok(())
        }

        fn update_mc_state(
            &mut self,
            ss: &mut ShardStateUnsplit,
            seq_no: u32,
        ) -> Result<Arc<ShardStateStuff>> {
            assert!(seq_no < 100);
            let config_addr = AccountId::from([0x55; 32]);
            let mut shard_accounts = ss.read_accounts()?;
            let mut account = shard_accounts.get(&config_addr)?.unwrap_or_default();
            let mut config_smc = account.read_account()?;
            config_smc.set_balance(CurrencyCollection::with_coins(seq_no as u64 * 1_000_000_000));
            config_smc.set_code(((seq_no * 100 + seq_no) * 100 + seq_no).serialize()?);
            account.write_account(&config_smc)?;
            let account = ShardAccount::with_params(&config_smc, UInt256::default(), 0).unwrap();
            shard_accounts.set_augmentable(&config_addr, &account).unwrap();
            ss.write_accounts(&shard_accounts).unwrap();

            ss.set_seq_no(seq_no);
            let mut block = Block::default();
            let mut info = BlockInfo::new();
            info.set_seq_no(seq_no)?;
            info.set_gen_utime(seq_no.into());
            block.write_info(&info)?;
            block.global_id = 42;
            let bytes = block.write_to_bytes()?;
            let file_hash = UInt256::calc_file_hash(&bytes);
            let block_id = BlockIdExt::with_params(
                ShardIdent::masterchain(),
                ss.seq_no(),
                [seq_no as u8; 32].into(),
                file_hash,
            );
            self.blocks.insert(block_id.clone(), bytes);
            let state = ShardStateStuff::from_state(
                block_id.clone(),
                ss.clone(),
                #[cfg(feature = "telemetry")]
                &self.telemetry,
                &self.allocated,
            )?;
            self.states.insert(block_id, state.clone());
            let handle = self
                .db
                .create_or_load_block_handle(state.block_id(), Some(&block), Some(seq_no), None)
                .unwrap()
                ._to_created()
                .unwrap();
            handle.set_data();
            handle.set_state();
            handle.set_block_applied();
            Ok(state)
        }

        async fn stop(&self) {
            self.db.stop_states_db().await.expect("console test state owners failed to stop")
        }
    }

    impl Drop for TestEngine {
        fn drop(&mut self) {
            let cfg_glob_file = format!("{}{}", CFG_GLOB_FILE, self.index);
            let cfg_node_file = format!("{}{}", CFG_NODE_FILE, self.index);
            fs::remove_file(Path::new(CFG_DIR).join(cfg_node_file)).ok();
            fs::remove_file(Path::new(CFG_DIR).join(cfg_glob_file)).ok();
        }
    }

    #[async_trait::async_trait]
    impl EngineOperations for TestEngine {
        // The control port's lite-server path accounts its work here.
        fn engine_allocated(&self) -> &Arc<EngineAlloc> {
            &self.allocated
        }
        #[cfg(feature = "telemetry")]
        fn engine_telemetry(&self) -> &Arc<EngineTelemetry> {
            &self.telemetry
        }
        fn calc_tps(&self, _period: u64) -> Result<u32> {
            Ok(0)
        }
        fn validation_status(&self) -> ValidationStatus {
            ValidationStatus::Active
        }
        fn last_validation_time(&self) -> &lockfree::map::Map<ShardIdent, u64> {
            &self.last_validation_time
        }
        fn last_collation_time(&self) -> &lockfree::map::Map<ShardIdent, u64> {
            &self.last_validation_time
        }
        fn get_sync_status(&self) -> u32 {
            0
        }
        fn load_block_handle(&self, id: &BlockIdExt) -> Result<Option<Arc<BlockHandle>>> {
            self.db.load_block_handle(id)
        }
        fn load_last_applied_mc_block_id(&self) -> Result<Option<Arc<BlockIdExt>>> {
            Ok(Some(Arc::new(self.last_mc_state.block_id().clone())))
        }
        async fn load_last_applied_mc_state(&self) -> Result<Arc<ShardStateStuff>> {
            Ok(self.last_mc_state.clone())
        }
        fn load_shard_client_mc_block_id(&self) -> Result<Option<Arc<BlockIdExt>>> {
            Ok(Some(Arc::new(self.last_mc_state.block_id().clone())))
        }
        async fn load_state(&self, block_id: &BlockIdExt) -> Result<Arc<ShardStateStuff>> {
            self.states
                .get(block_id)
                .cloned()
                .ok_or_else(|| error!("Can't find state {}", block_id))
        }
        async fn load_and_pin_state(&self, block_id: &BlockIdExt) -> Result<PinnedShardStateGuard> {
            let state = self
                .states
                .get(block_id)
                .cloned()
                .ok_or_else(|| error!("Wrong block ID {}", block_id))?;
            PinnedShardStateGuard::new(state, Arc::new(AllowStateGcSmartResolver::new(10)))
        }
        async fn load_block_raw(&self, handle: &Arc<BlockHandle>) -> Result<Vec<u8>> {
            if handle.has_data() {
                if let Some(data) = self.blocks.get(handle.id()) {
                    return Ok(data.clone());
                }
            }
            fail!("no block with id {}", handle.id())
        }
        fn find_full_block_id(&self, root_hash: &UInt256) -> Result<Option<BlockIdExt>> {
            Ok(self.states.iter().find_map(|(id, _)| {
                if id.root_hash() == root_hash {
                    Some(id.clone())
                } else {
                    None
                }
            }))
        }
        async fn lookup_block_by_seqno(
            &self,
            prefix: &AccountIdPrefixFull,
            seqno: u32,
        ) -> Result<Option<(BlockIdExt, Vec<u8>)>> {
            if !prefix.is_masterchain() {
                fail!("Only masterchain is supported");
            }
            for (id, data) in self.blocks.iter() {
                if id.shard().is_masterchain() && id.seq_no() == seqno {
                    return Ok(Some((id.clone(), data.clone())));
                }
            }
            fail!("Wrong seqno {}", seqno)
        }
        async fn redirect_external_message(&self, _message: &[u8]) -> Result<()> {
            if let Some(counter) = &self.counter {
                counter.fetch_add(1, Ordering::Relaxed);
            }
            Ok(())
        }
    }

    const ADNL_SERVER_CONFIG: &str = r#"{
        "ton_global_config_name": "light_global.json",
        "adnl_node": {
            "ip_address": "127.0.0.1:node_port",
            "keys": [
                {
                    "tag": 1,
                    "data": {
                        "type_id": 1209251014,
                        "pvt_key": "x3osWUUfcdybRLcmH7mJer4S0NM7TDpEw4SCftKD7bY="
                    }
                },
                {
                    "tag": 2,
                    "data": {
                        "type_id": 1209251014,
                        "pvt_key": "K56upUuRmuZrXhuExmmgr3DQt5Ae12XXQDXUXeGCQxg="
                    }
                }
            ]
        },
        "control_server": {
            "address": "127.0.0.1:control_port",
            "server_key": {
                "type_id": 1209251014,
                "pvt_key": "cJIxGZviebMQWL726DRejqVzRTSXPv/1sO/ab6XOZXk="
            },
            "clients": {
                "list": [
                    {
                        "type_id": 1209251014,
                        "pub_key": "RYokIiD5AFkzfTBgC6NhtAGFKm0+gwhN4suTzaW0Sjw=",
                        "permissions": 7
                    }
                ]
            }
        }
    }"#;

    const ADNL_CLIENT_CONFIG: &str = r#"{
        "config": {
            "server_address": "127.0.0.1:control_port",
            "server_key": {
                "type_id": 1209251014,
                "pub_key": "cujCRU4rQbSw48yHVHxQtRPhUlbo+BuZggFTQSu04Y8="
            },
            "client_key": {
                "type_id": 1209251014,
                "pvt_key": "oEivbTDjSOSCgooUM0DAS2z2hIdnLw/PT82A/OFLDmA="
            }
        },
        "wallet_id": "-1:af17db43f40b6aa24e7203a9f8c8652310c88c125062d1129fe883eaa1bd6763",
        "max_factor": 2.7
    }"#;

    const BASE_CONTROL_PORT: u16 = 4291;
    const BASE_NODE_PORT: u16 = 4191;

    const GLOBAL_CONFIG: &str = r#"{
        "validator": {
            "zero_state": {
                "workchain": -1,
                "shard": -9223372036854775808,
                "seqno": 0,
                "root_hash": "6Jb3GskUbO+HxaCnKQPEDPSxCkck7zHL//xPwAmBql0=",
                "file_hash": "Ti5G+UTHu6MTe2IVmMZ7VcQz+dBpET+NApZm+0B4kfc="
            }
        }
    }"#;

    const SAMPLE_ZERO_STATE: &str = r#"{
        "id": "-1:8000000000000000",
        "workchain_id": -1,
        "boc": "",
        "global_id": 42,
        "shard": "8000000000000000",
        "seq_no": 0,
        "vert_seq_no": 0,
        "gen_utime": 1600000000,
        "gen_lt": "0",
        "min_ref_mc_seqno": 4294967295,
        "before_split": false,
        "overload_history": "0",
        "underload_history": "0",
        "total_balance": "4993357197000000000",
        "total_validator_fees": "0",
        "master": {
            "config_addr": "5555555555555555555555555555555555555555555555555555555555555555",
            "config": {
            "p0": "5555555555555555555555555555555555555555555555555555555555555555",
            "p1": "3333333333333333333333333333333333333333333333333333333333333333",
            "p2": "0000000000000000000000000000000000000000000000000000000000000000",
            "p7": [],
            "p8": {
                "version": 11,
                "capabilities": "46"
            },
            "p9": [ 0 ],
            "p10": [ 0 ],
            "p11": {
                "normal_params": {
                    "min_tot_rounds": 2,
                    "max_tot_rounds": 3,
                    "min_wins": 2,
                    "max_losses": 2,
                    "min_store_sec": 1000000,
                    "max_store_sec": 10000000,
                    "bit_price": 1,
                    "cell_price": 500
                },
                "critical_params": {
                    "min_tot_rounds": 4,
                    "max_tot_rounds": 7,
                    "min_wins": 4,
                    "max_losses": 2,
                    "min_store_sec": 5000000,
                    "max_store_sec": 20000000,
                    "bit_price": 2,
                    "cell_price": 1000
                }
            },
            "p12": [],
            "p13": {
                "boc": "te6ccgEBAQEADQAAFRpRdIdugAEBIB9I"
            },
            "p14": {
                "masterchain_block_fee": "1700000000",
                "basechain_block_fee": "1000000000"
            },
            "p15": {
                "validators_elected_for": 65536,
                "elections_start_before": 32768,
                "elections_end_before": 8192,
                "stake_held_for": 32768
            },
            "p16": {
                "max_validators": 1000,
                "max_main_validators": 100,
                "min_validators": 5
            },
            "p17": {
                "min_stake": "10000000000000",
                "max_stake": "10000000000000000",
                "min_total_stake": "100000000000000",
                "max_stake_factor": 196608
            },
            "p18": [
                {
                "utime_since": 0,
                "bit_price_ps": "1",
                "cell_price_ps": "500",
                "mc_bit_price_ps": "1000",
                "mc_cell_price_ps": "500000"
                }
            ],
            "p20": {
                "flat_gas_limit": "1000",
                "flat_gas_price": "10000000",
                "gas_price": "655360000",
                "gas_limit": "1000000",
                "special_gas_limit": "100000000",
                "gas_credit": "10000",
                "block_gas_limit": "10000000",
                "freeze_due_limit": "100000000",
                "delete_due_limit": "1000000000"
            },
            "p21": {
                "flat_gas_limit": "1000",
                "flat_gas_price": "1000000",
                "gas_price": "65536000",
                "gas_limit": "1000000",
                "special_gas_limit": "1000000",
                "gas_credit": "10000",
                "block_gas_limit": "10000000",
                "freeze_due_limit": "100000000",
                "delete_due_limit": "1000000000"
            },
            "p22": {
                "bytes": {
                    "underload": 131072,
                    "soft_limit": 524288,
                    "hard_limit": 1048576
                },
                "gas": {
                    "underload": 900000,
                    "soft_limit": 1200000,
                    "hard_limit": 2000000
                },
                "lt_delta": {
                    "underload": 1000,
                    "soft_limit": 5000,
                    "hard_limit": 10000
                }
            },
            "p23": {
                "bytes": {
                    "underload": 131072,
                    "soft_limit": 524288,
                    "hard_limit": 1048576
                },
                "gas": {
                    "underload": 900000,
                    "soft_limit": 1200000,
                    "hard_limit": 2000000
                },
                "lt_delta": {
                    "underload": 1000,
                    "soft_limit": 5000,
                    "hard_limit": 10000
                }
            },
            "p24": {
                "lump_price": "10000000",
                "bit_price": "655360000",
                "cell_price": "65536000000",
                "ihr_price_factor": 98304,
                "first_frac": 21845,
                "next_frac": 21845
            },
            "p25": {
                "lump_price": "1000000",
                "bit_price": "65536000",
                "cell_price": "6553600000",
                "ihr_price_factor": 98304,
                "first_frac": 21845,
                "next_frac": 21845
            },
            "p28": {
                "shuffle_mc_validators": true,
                "mc_catchain_lifetime": 250,
                "shard_catchain_lifetime": 250,
                "shard_validators_lifetime": 1000,
                "shard_validators_num": 7
            },
            "p29": {
                "new_catchain_ids": true,
                "round_candidates": 3,
                "next_candidate_delay_ms": 2000,
                "consensus_timeout_ms": 16000,
                "fast_attempts": 3,
                "attempt_duration": 8,
                "catchain_max_deps": 4,
                "max_block_bytes": 2097152,
                "max_collated_bytes": 2097152
            },
            "p31": [
                "0000000000000000000000000000000000000000000000000000000000000000"
            ],
            "p34": {
                "utime_since": 1600000000,
                "utime_until": 1610000000,
                "total": 1,
                "main": 1,
                "total_weight": "17",
                "list": [
                    {
                        "public_key": "2e7eb5a711ed946605a91e36037c4cb927181eff4bb277b175d891a588d03536",
                        "weight": "17"
                    }
                ]
            }
            },
            "validator_list_hash_short": 871956759,
            "catchain_seqno": 0,
            "nx_cc_updated": true,
            "after_key_block": true,
            "global_balance": "4993357197000000000"
        },
        "accounts": [],
        "libraries": [],
        "out_msg_queue_info": {
            "out_queue": [],
            "proc_info": []
        }
    }"#;

    async fn init_test(
        counter: Option<Arc<AtomicU64>>,
    ) -> (ControlServer, ControlPort, Arc<TestEngine>, String) {
        // init_test_log();
        static INDEX: AtomicU16 = AtomicU16::new(0);
        let index = INDEX.fetch_add(1, Ordering::Relaxed);
        let cfg_glob_file = format!("{}{}", CFG_GLOB_FILE, index);
        let cfg_node_file = format!("{}{}", CFG_NODE_FILE, index);
        let node_port = format!(":{}", BASE_NODE_PORT + index);
        let control_port = format!(":{}", BASE_CONTROL_PORT + index);
        let adnl_server_config = ADNL_SERVER_CONFIG
            .replace(":node_port", &node_port)
            .replace(":control_port", &control_port)
            .replace(CFG_GLOB_FILE, &cfg_glob_file);
        fs::write(Path::new(CFG_DIR).join(&cfg_node_file), &adnl_server_config).unwrap();
        fs::write(Path::new(CFG_DIR).join(&cfg_glob_file), GLOBAL_CONFIG).unwrap();
        let node_config =
            TonNodeConfig::from_file(CFG_DIR, &cfg_node_file, None, "", None).await.unwrap();
        let control_server_config = node_config.control_server().unwrap();
        let config = control_server_config.expect("must have control server setting");
        #[cfg(feature = "telemetry")]
        let telemetry = create_engine_telemetry();
        let allocated = create_engine_allocated();
        let network = NodeNetwork::new(
            node_config,
            tokio_util::sync::CancellationToken::new(),
            #[cfg(feature = "telemetry")]
            telemetry.clone(),
            allocated.clone(),
        )
        .await
        .unwrap();
        let mut engine = TestEngine::new(
            index,
            counter,
            #[cfg(feature = "telemetry")]
            telemetry,
            allocated,
        )
        .await;
        engine.init_internal().unwrap();
        let engine = Arc::new(engine);
        let server = ControlServer::with_params(
            config,
            DataSource::Engine(engine.clone()),
            network.config_handler(),
            network.config_handler(),
            Some(&network),
        )
        .await
        .unwrap();
        let adnl_client_config = ADNL_CLIENT_CONFIG.replace(":control_port", &control_port);
        let connection = connection_from_json(adnl_client_config.as_bytes()).unwrap();
        let client = ControlPort { adnl: connect(&connection).await };
        (server, client, engine, connection.address.to_string())
    }

    async fn done_test(server: ControlServer, client: ControlPort, engine: Arc<TestEngine>) {
        server.shutdown().await;
        client.adnl.shutdown().await.ok();
        engine.stop().await;
        let db_path = format!("{}{}", DB_PATH, engine.index);
        drop(engine);
        loop {
            let ok = fs::remove_dir_all(&db_path).is_ok();
            thread::sleep(Duration::from_millis(10));
            if ok {
                break;
            }
        }
    }

    const PUBLIC_CONFIG_KEY: &str = "y+54dF9ZIQoIRQuH2+wE10fF5SV4GWrEv9m0lXHEmLU=";

    /// Reference console runs: command, exit code, output.
    const REFERENCE: &str = include_str!("../src/tests/data/control-surface/cpp-console.tsv");
    /// The files those runs read, as the reference console read them.
    const CASES: &str = "src/tests/data/control-surface/console";
    const CASE_PREFIX: &str = "cases/console2/";

    fn unescape(text: &str) -> String {
        let mut out = String::new();
        let mut chars = text.chars();
        while let Some(c) = chars.next() {
            if c != '\\' {
                out.push(c);
                continue;
            }
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some(other) => out.push(other),
                None => {}
            }
        }
        out
    }

    fn reference_rows() -> Vec<(String, i32, String)> {
        REFERENCE
            .lines()
            .filter(|line| !line.starts_with('#') && !line.is_empty())
            .map(|line| {
                let mut fields = line.splitn(3, '\t');
                let command = unescape(fields.next().unwrap());
                let exit = fields.next().unwrap().parse().unwrap();
                let output = unescape(fields.next().unwrap_or(""));
                (command, exit, output)
            })
            .collect()
    }

    fn exit_code(outcome: &Outcome) -> i32 {
        match outcome {
            Outcome::Failed => 2,
            _ => 0,
        }
    }

    /// The status a reference failure line reports.
    fn reported_status(output: &str) -> Status {
        let inner = output
            .split_once(" query: [Error : ")
            .map(|(_, rest)| rest.trim_end_matches("]\n"))
            .unwrap();
        let (code, message) = inner.split_once(" : ").unwrap();
        Status::with_code(code.parse().unwrap(), message)
    }

    /// Rows whose failure the reference server reported.
    const SERVER_FAILURES: &[&str] = &[
        "export-pub 3333",
        "export-pub 9UmV",
        "del-temp-key ",
        "set-verbosity 11",
        "add-custom-overlay cases/console2/ov1.json",
        "add-custom-overlay cases/console2/ov2.json",
        "del-custom-overlay ",
    ];

    /// Rows where this console's answer differs, with the reason.
    const KNOWN_DIFFERENCES: &[(&str, &str)] = &[(
        "add-custom-overlay cases/console2/malformed.json",
        "the JSON parser's own message for a malformed file",
    )];

    /// Answers each query as the reference server answered it in the
    /// recorded run, and keeps the query.
    struct Replay {
        command: String,
        output: String,
        cases: std::path::PathBuf,
        sent: Vec<TLObject>,
        overlay: Option<ton::engine::validator::customoverlay::CustomOverlay>,
    }

    impl Replay {
        fn answer(&self, function: &TLObject) -> Res<Vec<u8>> {
            let command = self.command.as_str();
            if SERVER_FAILURES.iter().any(|prefix| command.starts_with(prefix)) {
                if let Some(path) = self.output.split("keyring/").nth(1) {
                    // The key the reference server looked for is the one sent.
                    let sent = function.clone().downcast::<ExportPublicKey>().unwrap();
                    assert_eq!(hex_upper(sent.key_hash.as_slice()), path[..64], "{command}");
                }
                return Err(reported_status(&self.output));
            }
            if command == "new-key" {
                let hash = self.output.trim_end().rsplit(' ').next().unwrap();
                let key_hash = UInt256::from_slice(&hex::decode(hash).unwrap());
                return Ok(serialize_boxed(
                    &ton::engine::validator::keyhash::KeyHash { key_hash }.into_boxed(),
                )
                .unwrap());
            }
            if command.starts_with("export-pub ") {
                let text = self.output.trim_end().rsplit(' ').next().unwrap();
                return Ok(base64_decode(text).unwrap());
            }
            if command.starts_with("export-pubf ") {
                return Ok(fs::read(self.cases.join("pub.out")).unwrap());
            }
            if command.starts_with("sign ") || command.starts_with("sign-f ") {
                let signature = if command.starts_with("sign ") {
                    base64_decode(self.output.trim_end().rsplit(' ').next().unwrap()).unwrap()
                } else {
                    fs::read(self.cases.join("sig.out")).unwrap()
                };
                return Ok(serialize_boxed(
                    &ton::engine::validator::signature::Signature { signature }.into_boxed(),
                )
                .unwrap());
            }
            if command == "get-time" {
                let time = self.output.trim_end().rsplit('=').next().unwrap().parse().unwrap();
                return Ok(serialize_boxed(
                    &ton::engine::validator::time::Time { time }.into_boxed(),
                )
                .unwrap());
            }
            if command == "show-custom-overlays" {
                let overlays = self.overlay.clone().into_iter().collect::<Vec<_>>();
                return Ok(serialize_boxed(
                    &ton::engine::validator::customoverlaysconfig::CustomOverlaysConfig {
                        overlays: overlays.into(),
                    }
                    .into_boxed(),
                )
                .unwrap());
            }
            if command.starts_with("export-all-private-keys ") {
                let query = function.clone().downcast::<ExportAllPrivateKeys>().unwrap();
                let ton::PublicKey::Pub_Ed25519(key) = query.encryption_key else {
                    panic!("an Ed25519 encryption key");
                };
                let mut plain = Vec::new();
                for key in exported_keys() {
                    let bytes = serialize_boxed(&key).unwrap();
                    plain.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
                    plain.extend_from_slice(&bytes);
                }
                plain.extend_from_slice(&[0x5a; 32]);
                let encrypted_data = encrypt_for(key.key.as_slice(), &plain).unwrap();
                return Ok(serialize_boxed(
                    &ton::engine::validator::exportedprivatekeys::ExportedPrivateKeys {
                        encrypted_data,
                    }
                    .into_boxed(),
                )
                .unwrap());
            }
            // Everything else the reference server answered with success.
            Ok(serialize_boxed(&ton::engine::validator::Success::Engine_Validator_Success).unwrap())
        }
    }

    /// Keys for the export run, ordered by hash as the server orders them.
    fn exported_keys() -> Vec<ton::PrivateKey> {
        let mut keys: Vec<ton::PrivateKey> = (1u8..=4)
            .map(|seed| {
                ton::PrivateKey::Pk_Ed25519(ton::pk::privatekey::Ed25519 {
                    key: UInt256::from([seed; 32]),
                })
            })
            .collect();
        keys.sort_by_key(|key| private_key_hash(key).unwrap());
        keys
    }

    #[async_trait::async_trait]
    impl Transport for Replay {
        async fn send(&mut self, function: &TLObject) -> Res<Vec<u8>> {
            if let Ok(query) = function.clone().downcast::<AddCustomOverlay>() {
                if self.overlay.is_none() {
                    self.overlay = Some(query.overlay.clone());
                }
            }
            self.sent.push(function.clone());
            self.answer(function)
        }
    }

    /// Copies the cases; a binary case is kept as `NAME.hex` and becomes
    /// `NAME` again.
    fn copy_dir(from: &Path, to: &Path) {
        fs::create_dir_all(to).unwrap();
        for entry in fs::read_dir(from).unwrap() {
            let entry = entry.unwrap();
            if !entry.file_type().unwrap().is_file() {
                continue;
            }
            let name = entry.file_name().into_string().unwrap();
            match name.strip_suffix(".hex") {
                Some(binary) => {
                    let text = fs::read_to_string(entry.path()).unwrap();
                    fs::write(to.join(binary), hex::decode(text.trim()).unwrap()).unwrap();
                }
                None => {
                    fs::copy(entry.path(), to.join(&name)).unwrap();
                }
            }
        }
    }

    /// Every recorded reference command line gives the reference output and
    /// exit code here, and reaches the server exactly when the reference
    /// console did.
    #[tokio::test]
    async fn console_lines_answer_as_the_reference_console() {
        let dir = tempfile::tempdir().unwrap();
        let cases = dir.path().join("cases");
        copy_dir(&Path::new(env!("CARGO_MANIFEST_DIR")).join(CASES), &cases);
        let prefix = format!("{}/", cases.display());
        let mut overlay = None;
        let mut checked = 0;
        for (command, exit, expected) in reference_rows() {
            let line = command.replace(CASE_PREFIX, &prefix);
            let expected_here = expected.replace(CASE_PREFIX, &prefix);
            let mut replay = Replay {
                command: command.clone(),
                output: expected.clone(),
                cases: cases.clone(),
                sent: Vec::new(),
                overlay: overlay.clone(),
            };
            let (output, outcome) = run_line(&line, &mut replay).await;
            if replay.overlay.is_some() {
                overlay = replay.overlay.clone();
            }
            if let Some((_, why)) = KNOWN_DIFFERENCES.iter().find(|(c, _)| *c == command) {
                assert!(
                    output.starts_with("Failed add-custom-overlay query: [Error : 0 : "),
                    "{why}"
                );
                assert_eq!(exit_code(&outcome), exit, "{command}");
                continue;
            }
            if command.starts_with("export-all-private-keys ") {
                let mut lines = format!("exported {} private keys\n", exported_keys().len());
                for key in exported_keys() {
                    lines.push_str(&format!(
                        "pubkey_hash {}\n",
                        hex_upper(&private_key_hash(&key).unwrap())
                    ));
                }
                lines.push_str(&format!("written all files to {}exported\n", prefix));
                assert_eq!(output, lines, "{command}");
                // The reference output has the same shape.
                assert_eq!(expected.lines().count(), 6);
                for key in exported_keys() {
                    let hash = hex_upper(&private_key_hash(&key).unwrap());
                    let path = cases.join("exported").join(&hash);
                    assert_eq!(fs::read(&path).unwrap(), serialize_boxed(&key).unwrap());
                    let mode = fs::metadata(&path).unwrap().permissions();
                    assert_eq!(std::os::unix::fs::PermissionsExt::mode(&mode) & 0o777, 0o600);
                }
                checked += 1;
                continue;
            }
            assert_eq!(output, expected_here, "{command}");
            assert_eq!(exit_code(&outcome), exit, "{command}");
            let reaches_server = !expected.starts_with("Failed ")
                || SERVER_FAILURES.iter().any(|p| command.starts_with(p))
                || command.contains("/nonexistent-dir/");
            let local = ["help", "license", "quit", "bogus-cmd"];
            let reaches_server = reaches_server
                && !local.iter().any(|name| command.split(' ').next() == Some(*name));
            assert_eq!(!replay.sent.is_empty(), reaches_server, "{command}");
            checked += 1;
        }
        assert!(checked >= 50, "{checked} rows checked");
    }

    /// The listing the reference console printed for two overlays, one with
    /// sender shards and flags and one with neither.
    #[test]
    fn custom_overlays_list_as_the_reference_console_lists_them() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join(CASES);
        let overlays = ["ov1.json", "ov3.json"]
            .iter()
            .map(|name| {
                let json: serde_json::Value =
                    serde_json::from_slice(&fs::read(dir.join(name)).unwrap()).unwrap();
                tl_json::custom_overlay(json.as_object().unwrap()).unwrap()
            })
            .collect::<Vec<_>>();
        let config = ton::engine::validator::customoverlaysconfig::CustomOverlaysConfig {
            overlays: overlays.into(),
        };
        let expected =
            include_str!("../src/tests/data/control-surface/cpp-show-custom-overlays.txt");
        assert_eq!(show_custom_overlays(&config), expected);
    }

    #[test]
    fn file_errors_print_as_reference_os_errors() {
        let error = read_file("/nonexistent-dir/x").unwrap_err();
        assert_eq!(
            error.to_string(),
            "[PosixError : No such file or directory : 2 : File \"/nonexistent-dir/x\" can't be \
             opened for reading]"
        );
    }

    #[test]
    fn base64_follows_the_reference_rules() {
        assert_eq!(base64_decode("QUJD").unwrap(), b"ABC");
        assert_eq!(base64_decode("QUI=").unwrap(), b"AB");
        assert_eq!(base64_decode("QQ==").unwrap(), b"A");
        for (text, error) in [
            ("QQ===", "Wrong string padding"),
            ("QUJ", "Wrong padding length"),
            ("QU*D", "Wrong character in the string"),
            ("QR==", "Wrong padding in the string"),
            ("QUN=", "Wrong padding in the string"),
        ] {
            assert_eq!(base64_decode(text).unwrap_err().message, error, "{text}");
        }
    }

    #[test]
    fn integers_must_be_canonical() {
        assert_eq!(integer::<u32>("4294967295").unwrap(), u32::MAX);
        assert_eq!(integer::<i32>("-5").unwrap(), -5);
        for word in ["+5", "05", "-0", "4294967296", "1.0", "x"] {
            assert_eq!(
                integer::<u32>(word).unwrap_err().message,
                format!("Can't parse \"{word}\" as number")
            );
        }
        assert!(integer::<i32>("-0").is_err());
    }

    async fn pending_finishes(commands: &[&str], transport: &mut Replay) -> Option<i32> {
        let commands = commands.iter().map(|c| c.to_string()).collect();
        tokio::time::timeout(Duration::from_millis(300), run_batch(commands, transport)).await.ok()
    }

    fn replay(command: &str, output: &str) -> Replay {
        Replay {
            command: command.to_string(),
            output: output.to_string(),
            cases: std::path::PathBuf::new(),
            sent: Vec::new(),
            overlay: None,
        }
    }

    /// The reference batch rules: a failure exits with 2 at once, quit exits
    /// with 0 at once, and a line that is not a command ends the run with 0
    /// only when nothing follows it.
    #[tokio::test]
    async fn batch_runs_stop_as_the_reference_console_stops() {
        let mut ok = replay("add-adnl", "success\n");
        assert_eq!(
            pending_finishes(&["set-verbosity 3", "set-verbosity 4"], &mut ok).await,
            Some(0)
        );
        assert_eq!(ok.sent.len(), 2);
        let mut ok = replay("add-adnl", "success\n");
        assert_eq!(
            pending_finishes(&["set-verbosity 3", "quit", "set-verbosity 4"], &mut ok).await,
            Some(0)
        );
        assert_eq!(ok.sent.len(), 1);
        let mut ok = replay("add-adnl", "success\n");
        assert_eq!(
            pending_finishes(&["set-verbosity x", "set-verbosity 4"], &mut ok).await,
            Some(2)
        );
        assert!(ok.sent.is_empty());
        let mut ok = replay("add-adnl", "success\n");
        assert_eq!(pending_finishes(&["set-verbosity 3", "bogus"], &mut ok).await, Some(0));
        let mut ok = replay("add-adnl", "success\n");
        assert_eq!(pending_finishes(&["bogus", "set-verbosity 3"], &mut ok).await, None);
        assert!(ok.sent.is_empty());
        let mut ok = replay("add-adnl", "success\n");
        assert_eq!(pending_finishes(&["", "set-verbosity 3"], &mut ok).await, None);
    }

    /// The console against this node's control port: keys, signing, time and
    /// statistics answer in the reference form.
    #[tokio::test(flavor = "multi_thread")]
    async fn console_drives_the_control_port() {
        let (server, mut client, engine, _) = init_test(None).await;
        let (created, outcome) = run_line("new-key", &mut client).await;
        assert_eq!(outcome, Outcome::Done, "{created}");
        let hash = created.strip_prefix("created new key ").unwrap().trim_end().to_string();
        assert_eq!(hash.len(), 64);
        assert_eq!(hash, hash.to_uppercase());
        let (public, _) = run_line(&format!("export-pub {hash}"), &mut client).await;
        let public = public.strip_prefix("got public key: ").unwrap().trim_end();
        let public = base64_decode(public).unwrap();
        let key = deserialize_boxed(&public).unwrap().downcast::<ton::PublicKey>().unwrap();
        let ton::PublicKey::Pub_Ed25519(key) = key else { panic!("an Ed25519 key") };
        let (signed, _) = run_line(&format!("sign {hash} 616263"), &mut client).await;
        let signature =
            base64_decode(signed.strip_prefix("got signature ").unwrap().trim_end()).unwrap();
        get_key_option_factory()
            .from_public_key(key.key.as_array())
            .verify(b"abc", &signature)
            .unwrap();
        let (time, _) = run_line("get-time", &mut client).await;
        assert!(time.starts_with("received validator time: time="), "{time}");
        let (stats, outcome) = run_line("get-stats", &mut client).await;
        assert_eq!(outcome, Outcome::Done, "{stats}");
        assert!(stats.starts_with("unixtime\t\t\t"), "{stats}");
        assert!(stats.contains("\nmasterchainblocktime\t\t\t19\n"), "{stats}");
        let (added, _) =
            run_line(&format!("add-perm-key {hash} 100 2000000000"), &mut client).await;
        assert_eq!(added, "success\n");
        let (missing, outcome) = run_line(
            "export-pub 3333333333333333333333333333333333333333333333333333333333333333",
            &mut client,
        )
        .await;
        assert_eq!(outcome, Outcome::Failed);
        assert!(
            missing.starts_with("Failed export-pub query: [Error : 2 : key not in db"),
            "{missing}"
        );
        // A key file in the reference form imports under its hash.
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("k.pk");
        let key = ton::PrivateKey::Pk_Ed25519(ton::pk::privatekey::Ed25519 {
            key: UInt256::from([9; 32]),
        });
        fs::write(&file, serialize_boxed(&key).unwrap()).unwrap();
        let (imported, _) = run_line(&format!("import-f {}", file.display()), &mut client).await;
        assert_eq!(
            imported,
            format!("imported key {}\n", hex_upper(&private_key_hash(&key).unwrap()))
        );
        done_test(server, client, engine).await;
    }

    /// The reference console against this node's control port gives what
    /// this console gives. Runs when RTOS_REFERENCE_CONSOLE names the
    /// reference console binary. It fails today: the reference console
    /// proves its key through TCP authentication over an ephemeral
    /// handshake key, and the control server still takes the client's
    /// identity from the handshake, so it refuses the console as unlisted.
    #[tokio::test(flavor = "multi_thread")]
    async fn reference_console_reads_this_node_as_this_console_does() {
        let Ok(binary) = std::env::var("RTOS_REFERENCE_CONSOLE") else {
            eprintln!("RTOS_REFERENCE_CONSOLE is not set: skipped");
            return;
        };
        let (server, mut client, engine, address) = init_test(None).await;
        let dir = tempfile::tempdir().unwrap();
        let client_key = dir.path().join("client.pk");
        let server_key = dir.path().join("server.pub");
        let client_secret: [u8; 32] =
            std_base64_decode("oEivbTDjSOSCgooUM0DAS2z2hIdnLw/PT82A/OFLDmA=")
                .unwrap()
                .try_into()
                .unwrap();
        let server_public: [u8; 32] =
            std_base64_decode("cujCRU4rQbSw48yHVHxQtRPhUlbo+BuZggFTQSu04Y8=")
                .unwrap()
                .try_into()
                .unwrap();
        fs::write(
            &client_key,
            serialize_boxed(&ton::PrivateKey::Pk_Ed25519(ton::pk::privatekey::Ed25519 {
                key: UInt256::from(client_secret),
            }))
            .unwrap(),
        )
        .unwrap();
        fs::write(
            &server_key,
            serialize_boxed(&ton::PublicKey::Pub_Ed25519(ton::pub_::publickey::Ed25519 {
                key: UInt256::from(server_public),
            }))
            .unwrap(),
        )
        .unwrap();
        let (created, _) = run_line("new-key", &mut client).await;
        let hash = created.strip_prefix("created new key ").unwrap().trim_end().to_string();
        let lines = [
            format!("export-pub {hash}"),
            format!("sign {hash} 616263"),
            "export-pub 3333333333333333333333333333333333333333333333333333333333333333"
                .to_string(),
            "set-verbosity 11".to_string(),
            "show-custom-overlays".to_string(),
            "help get-time".to_string(),
            "sign x".to_string(),
        ];
        for line in &lines {
            let output = std::process::Command::new(&binary)
                .args(["-a", &address, "-k"])
                .arg(&client_key)
                .arg("-p")
                .arg(&server_key)
                .args(["-r", "-t", "10", "-c", line])
                .output()
                .unwrap();
            let full = String::from_utf8_lossy(&output.stdout);
            let reference = full.split("conn ready\n").nth(1).unwrap_or("").to_string();
            let (ours, outcome) = run_line(line, &mut client).await;
            assert_eq!(reference, ours, "{line}: {full}");
            assert_eq!(output.status.code(), Some(exit_code(&outcome)), "{line}");
        }
        done_test(server, client, engine).await;
    }
}
