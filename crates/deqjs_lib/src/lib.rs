
use std::fmt;

use byteorder::{ByteOrder, LittleEndian};
use serde::{Deserialize, Serialize};
use thiserror::Error;

mod tables {
    include!(concat!(env!("OUT_DIR"), "/quickjs_tables.rs"));
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DecompileMode {
    Pseudo,
    Disasm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DecompileVersion {
    Auto,
    Current,
    Legacy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecompileOptions {
    pub mode: DecompileMode,
    pub version: DecompileVersion,
    pub deobfuscate: bool,
    pub optimize: bool,
}

impl Default for DecompileOptions {
    fn default() -> Self {
        Self {
            mode: DecompileMode::Pseudo,
            version: DecompileVersion::Auto,
            deobfuscate: false,
            optimize: false,
        }
    }
}

#[derive(Debug, Error)]
pub enum DeqjsError {
    #[error("unexpected end of input")]
    Eof,

    #[error("invalid QuickJS bytecode version: {0}")]
    InvalidVersion(u8),

    #[error("unsupported tag: {0}")]
    UnsupportedTag(u8),

    #[error("invalid sleb128")]
    InvalidSleb128,

    #[error("invalid opcode: 0x{0:02x}")]
    InvalidOpcode(u8),

    #[error("truncated opcode at pc={pc} (opcode size={size}, remaining={remaining})")]
    TruncatedOpcode { pc: usize, size: usize, remaining: usize },

    #[error("invalid atom index: {0}")]
    InvalidAtomIndex(u32),

    #[error("invalid constant pool index: {0}")]
    InvalidConstIndex(u32),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AtomRepr {
    Null,
    Builtin(u32),
    String(String),
    Symbol { typ: u8, desc: String },
    TaggedInt(u32),
    Raw(u32),
}

impl fmt::Display for AtomRepr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AtomRepr::Null => write!(f, "<null>"),
            AtomRepr::Builtin(id) => {
                let idx = (*id as usize).saturating_sub(1);
                if *id != 0 && idx < tables::BUILTIN_ATOMS.len() {
                    write!(f, "{}", tables::BUILTIN_ATOMS[idx])
                } else {
                    write!(f, "<atom:{}>", id)
                }
            }
            AtomRepr::String(s) => write!(f, "{s}"),
            AtomRepr::Symbol { typ, desc } => write!(f, "<sym:{}:{desc}>", typ),
            AtomRepr::TaggedInt(v) => write!(f, "<int:{}>", v),
            AtomRepr::Raw(v) => write!(f, "<atom:{}>", v),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Value {
    Null,
    Undefined,
    Bool(bool),
    Int32(i32),
    Float64(f64),
    String(String),
    Array(Vec<Value>),
    Object(Vec<(AtomRepr, Value)>),
    Module { name: AtomRepr, func_obj: Box<Value> },
    RegExp { pattern: String, bytecode: String },
    BigInt { bytes: Vec<u8> },
    Symbol { atom: AtomRepr },
    ArrayBuffer { bytes: Vec<u8> },
    TypedArray { kind: u8, len: u32, offset: u32, buffer: Box<Value> },
    Date { value: Box<Value> },
    Function(FunctionBytecode),
    Unsupported { tag: u8 },
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Null => write!(f, "null"),
            Value::Undefined => write!(f, "undefined"),
            Value::Bool(b) => write!(f, "{b}"),
            Value::Int32(v) => write!(f, "{v}"),
            Value::Float64(v) => write!(f, "{v}"),
            Value::String(s) => write!(f, "\"{}\"", s),
            Value::Array(v) => write!(f, "<array:{}>", v.len()),
            Value::Object(v) => write!(f, "<object:{}>", v.len()),
            Value::Module { name, .. } => write!(f, "<module:{}>", name),
            Value::RegExp { pattern, .. } => write!(f, "<regexp:{pattern}>") ,
            Value::BigInt { bytes } => write!(f, "<bigint:{} bytes>", bytes.len()),
            Value::Symbol { atom } => write!(f, "<symbol:{atom}>"),
            Value::ArrayBuffer { bytes } => write!(f, "<arraybuffer:{} bytes>", bytes.len()),
            Value::TypedArray { kind, len, .. } => write!(f, "<typedarray:{kind} len={len}>") ,
            Value::Date { .. } => write!(f, "<date>"),
            Value::Function(bc) => write!(f, "<function:{}>", bc.func_name),
            Value::Unsupported { tag } => write!(f, "<tag:{}>", tag),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VarDef {
    pub name: AtomRepr,
    pub scope_level: u32,
    pub scope_next: u32,
    pub flags: u8,
    pub var_ref_idx: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClosureVar {
    pub name: AtomRepr,
    pub var_idx: u32,
    pub flags: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionBytecode {
    pub func_name: AtomRepr,
    pub is_strict_mode: bool,
    pub arg_count: u16,
    pub var_count: u16,
    pub defined_arg_count: u16,
    pub stack_size: u16,
    pub var_ref_count: u16,
    pub closure_var_count: u16,
    pub cpool_count: u32,
    pub byte_code_len: u32,
    pub locals: Vec<VarDef>,
    pub closure_vars: Vec<ClosureVar>,
    pub cpool: Vec<Value>,
    pub bytecode: Vec<u8>,
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn peek_u8(&self) -> Option<u8> {
        self.buf.get(self.pos).copied()
    }

    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    fn get_u8(&mut self) -> Result<u8, DeqjsError> {
        if self.remaining() < 1 {
            return Err(DeqjsError::Eof);
        }
        let v = self.buf[self.pos];
        self.pos += 1;
        Ok(v)
    }

    fn get_u16(&mut self) -> Result<u16, DeqjsError> {
        if self.remaining() < 2 {
            return Err(DeqjsError::Eof);
        }
        let v = LittleEndian::read_u16(&self.buf[self.pos..self.pos + 2]);
        self.pos += 2;
        Ok(v)
    }

    fn get_u32(&mut self) -> Result<u32, DeqjsError> {
        if self.remaining() < 4 {
            return Err(DeqjsError::Eof);
        }
        let v = LittleEndian::read_u32(&self.buf[self.pos..self.pos + 4]);
        self.pos += 4;
        Ok(v)
    }

    fn get_u64(&mut self) -> Result<u64, DeqjsError> {
        if self.remaining() < 8 {
            return Err(DeqjsError::Eof);
        }
        let v = LittleEndian::read_u64(&self.buf[self.pos..self.pos + 8]);
        self.pos += 8;
        Ok(v)
    }

    fn get_f64(&mut self) -> Result<f64, DeqjsError> {
        if self.remaining() < 8 {
            return Err(DeqjsError::Eof);
        }
        let v = LittleEndian::read_f64(&self.buf[self.pos..self.pos + 8]);
        self.pos += 8;
        Ok(v)
    }

    fn get_bytes(&mut self, n: usize) -> Result<&'a [u8], DeqjsError> {
        if self.remaining() < n {
            return Err(DeqjsError::Eof);
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn get_leb128_u32(&mut self) -> Result<u32, DeqjsError> {
        let mut result: u32 = 0;
        let mut shift: u32 = 0;
        loop {
            let b = self.get_u8()?;
            result |= ((b & 0x7f) as u32) << shift;
            if (b & 0x80) == 0 {
                return Ok(result);
            }
            shift += 7;
            if shift >= 32 {
                return Err(DeqjsError::Eof);
            }
        }
    }

    fn get_sleb128_i32(&mut self) -> Result<i32, DeqjsError> {
        let mut result: i64 = 0;
        let mut shift: u32 = 0;
        let mut byte: u8;
        loop {
            byte = self.get_u8()?;
            result |= ((byte & 0x7f) as i64) << shift;
            shift += 7;
            if (byte & 0x80) == 0 {
                break;
            }
            if shift >= 64 {
                return Err(DeqjsError::InvalidSleb128);
            }
        }
        if shift < 64 && (byte & 0x40) != 0 {
            result |= (!0i64) << shift;
        }
        Ok(result as i32)
    }
}

#[derive(Debug, Clone)]
struct AtomTable {
    first_atom: u32,
    idx_to_atom: Vec<AtomRepr>,
}

impl AtomTable {
    fn builtin_end_atom_id() -> u32 {
        (tables::BUILTIN_ATOMS.len() as u32) + 1
    }

    fn resolve_idx(&self, idx: u32) -> Result<AtomRepr, DeqjsError> {
        if idx == 0 {
            return Ok(AtomRepr::Null);
        }
        if idx < self.first_atom {
            return Ok(AtomRepr::Builtin(idx));
        }
        let off = idx - self.first_atom;
        let off = off as usize;
        if off >= self.idx_to_atom.len() {
            return Err(DeqjsError::InvalidAtomIndex(idx));
        }
        Ok(self.idx_to_atom[off].clone())
    }

    fn read_atom(&self, r: &mut Reader<'_>) -> Result<AtomRepr, DeqjsError> {
        let v = r.get_leb128_u32()?;
        if (v & 1) == 1 {
            return Ok(AtomRepr::TaggedInt(v >> 1));
        }
        self.resolve_idx(v >> 1)
    }
}

const BC_TAG_NULL: u8 = 1;
const BC_TAG_UNDEFINED: u8 = 2;
const BC_TAG_BOOL_FALSE: u8 = 3;
const BC_TAG_BOOL_TRUE: u8 = 4;
const BC_TAG_INT32: u8 = 5;
const BC_TAG_FLOAT64: u8 = 6;
const BC_TAG_STRING: u8 = 7;
const BC_TAG_OBJECT: u8 = 8;
const BC_TAG_ARRAY: u8 = 9;
const BC_TAG_BIG_INT: u8 = 10;
const BC_TAG_TEMPLATE_OBJECT: u8 = 11;
const BC_TAG_FUNCTION_BYTECODE: u8 = 12;
const BC_TAG_MODULE: u8 = 13;
const BC_TAG_TYPED_ARRAY: u8 = 14;
const BC_TAG_ARRAY_BUFFER: u8 = 15;
const BC_TAG_SHARED_ARRAY_BUFFER: u8 = 16;
const BC_TAG_REGEXP: u8 = 17;
const BC_TAG_DATE: u8 = 18;
const BC_TAG_OBJECT_VALUE: u8 = 19;
const BC_TAG_OBJECT_REFERENCE: u8 = 20;
const BC_TAG_MAP: u8 = 21;
const BC_TAG_SET: u8 = 22;
const BC_TAG_SYMBOL: u8 = 23;

// Legacy v1 tags follow EvilDecompiler's ObjectTag enum.
// v1 includes BC_TAG_BIG_FLOAT and BC_TAG_BIG_DECIMAL, which shift the tags after BIG_INT.
const BC_TAG_TEMPLATE_OBJECT_V1: u8 = 13;
const BC_TAG_FUNCTION_BYTECODE_V1: u8 = 14;
const BC_TAG_MODULE_V1: u8 = 15;
const BC_TAG_TYPED_ARRAY_V1: u8 = 16;
const BC_TAG_ARRAY_BUFFER_V1: u8 = 17;
const BC_TAG_SHARED_ARRAY_BUFFER_V1: u8 = 18;
const BC_TAG_DATE_V1: u8 = 19;
const BC_TAG_OBJECT_VALUE_V1: u8 = 20;
const BC_TAG_OBJECT_REFERENCE_V1: u8 = 21;

const BC_VERSION: u8 = 23;
const BC_VERSION_V1: u8 = 1;

const LEGACY_V1_ATOMS: &[&str] = &[
    "null",
    "false",
    "true",
    "if",
    "else",
    "return",
    "var",
    "this",
    "delete",
    "void",
    "typeof",
    "new",
    "in",
    "instanceof",
    "do",
    "while",
    "for",
    "break",
    "continue",
    "switch",
    "case",
    "default",
    "throw",
    "try",
    "catch",
    "finally",
    "function",
    "debugger",
    "with",
    "__FILE__",
    "__DIR__",
    "class",
    "const",
    "enum",
    "export",
    "extends",
    "import",
    "super",
    "implements",
    "interface",
    "let",
    "package",
    "private",
    "protected",
    "public",
    "static",
    "yield",
    "await",
    "",
    "length",
    "fileName",
    "lineNumber",
    "message",
    "errors",
    "stack",
    "name",
    "toString",
    "toLocaleString",
    "valueOf",
    "eval",
    "prototype",
    "constructor",
    "configurable",
    "writable",
    "enumerable",
    "value",
    "get",
    "set",
    "of",
    "__proto__",
    "undefined",
    "number",
    "boolean",
    "string",
    "object",
    "symbol",
    "integer",
    "unknown",
    "arguments",
    "callee",
    "caller",
    "<eval>",
    "<ret>",
    "<var>",
    "<arg_var>",
    "<with>",
    "lastIndex",
    "target",
    "index",
    "input",
    "defineProperties",
    "apply",
    "join",
    "concat",
    "split",
    "construct",
    "getPrototypeOf",
    "setPrototypeOf",
    "isExtensible",
    "preventExtensions",
    "has",
    "deleteProperty",
    "defineProperty",
    "getOwnPropertyDescriptor",
    "ownKeys",
    "add",
    "done",
    "next",
    "values",
    "source",
    "flags",
    "global",
    "unicode",
    "raw",
    "new.target",
    "this.active_func",
    "<home_object>",
    "<computed_field>",
    "<static_computed_field>",
    "<class_fields_init>",
    "<brand>",
    "#constructor",
    "as",
    "from",
    "meta",
    "*default*",
    "*",
    "Module",
    "then",
    "resolve",
    "reject",
    "promise",
    "proxy",
    "revoke",
    "async",
    "exec",
    "groups",
    "status",
    "reason",
    "globalThis",
    "not-equal",
    "timed-out",
    "ok",
    "toJSON",
    "Object",
    "Array",
    "Error",
    "Number",
    "String",
    "Boolean",
    "Symbol",
    "Arguments",
    "Math",
    "JSON",
    "Date",
    "Function",
    "GeneratorFunction",
    "ForInIterator",
    "RegExp",
    "ArrayBuffer",
    "SharedArrayBuffer",
    "Uint8ClampedArray",
    "Int8Array",
    "Uint8Array",
    "Int16Array",
    "Uint16Array",
    "Int32Array",
    "Uint32Array",
    "Float32Array",
    "Float64Array",
    "DataView",
    "Map",
    "Set",
    "WeakMap",
    "WeakSet",
    "Map Iterator",
    "Set Iterator",
    "Array Iterator",
    "String Iterator",
    "RegExp String Iterator",
    "Generator",
    "Proxy",
    "Promise",
    "PromiseResolveFunction",
    "PromiseRejectFunction",
    "AsyncFunction",
    "AsyncFunctionResolve",
    "AsyncFunctionReject",
    "AsyncGeneratorFunction",
    "AsyncGenerator",
    "EvalError",
    "RangeError",
    "ReferenceError",
    "SyntaxError",
    "TypeError",
    "URIError",
    "InternalError",
    "<brand>",
    "Symbol.toPrimitive",
    "Symbol.iterator",
    "Symbol.match",
    "Symbol.matchAll",
    "Symbol.replace",
    "Symbol.search",
    "Symbol.split",
    "Symbol.toStringTag",
    "Symbol.isConcatSpreadable",
    "Symbol.hasInstance",
    "Symbol.species",
    "Symbol.unscopables",
    "Symbol.asyncIterator",
];

fn read_qjs_string(r: &mut Reader<'_>) -> Result<String, DeqjsError> {
    let len_flags = r.get_leb128_u32()?;
    let is_wide = (len_flags & 1) == 1;
    let len = (len_flags >> 1) as usize;
    if is_wide {
        let bytes = r.get_bytes(len * 2)?;
        let mut out = String::new();
        for i in 0..len {
            let c = LittleEndian::read_u16(&bytes[i * 2..i * 2 + 2]);
            out.push(char::from_u32(c as u32).unwrap_or('\u{FFFD}'));
        }
        Ok(out)
    } else {
        let bytes = r.get_bytes(len)?;
        Ok(String::from_utf8_lossy(bytes).to_string())
    }
}

fn read_atom_table(r: &mut Reader<'_>) -> Result<AtomTable, DeqjsError> {
    let version = r.get_u8()?;
    if version != BC_VERSION {
        return Err(DeqjsError::InvalidVersion(version));
    }

    let count = r.get_leb128_u32()? as usize;
    let first_atom = AtomTable::builtin_end_atom_id();

    let mut idx_to_atom = Vec::with_capacity(count);
    for _ in 0..count {
        let typ = r.get_u8()?;
        if typ == 0 {
            let atom = r.get_u32()?;
            idx_to_atom.push(AtomRepr::Raw(atom));
        } else {
            let desc = read_qjs_string(r)?;
            if typ == 1 {
                idx_to_atom.push(AtomRepr::String(desc));
            } else {
                idx_to_atom.push(AtomRepr::Symbol { typ, desc });
            }
        }
    }

    Ok(AtomTable { first_atom, idx_to_atom })
}

#[derive(Debug, Clone)]
struct AtomTableV1 {
    atoms: Vec<String>,
}

impl AtomTableV1 {
    fn to_atom_table(&self) -> AtomTable {
        // Legacy v1 atom IDs are direct JSAtom IDs.
        // EvilDecompiler's AtomSet stores builtins at the start and expects:
        //   id == 0 => null
        //   id >= 1 => atoms[id-1]
        AtomTable {
            first_atom: 1,
            idx_to_atom: self.atoms.iter().cloned().map(AtomRepr::String).collect(),
        }
    }

    fn read_atom_id(&self, r: &mut Reader<'_>) -> Result<AtomRepr, DeqjsError> {
        let id = r.get_leb128_u32()?;
        if id == 0 {
            return Ok(AtomRepr::Null);
        }
        let idx = (id as usize).saturating_sub(1);
        if idx < self.atoms.len() {
            Ok(AtomRepr::String(self.atoms[idx].clone()))
        } else {
            Ok(AtomRepr::Raw(id))
        }
    }
}

fn read_atom_table_v1(r: &mut Reader<'_>) -> Result<AtomTableV1, DeqjsError> {
    let version = r.get_u8()?;
    if version != BC_VERSION_V1 {
        return Err(DeqjsError::InvalidVersion(version));
    }

    let count = r.get_leb128_u32()? as usize;
    let mut atoms: Vec<String> = Vec::with_capacity(LEGACY_V1_ATOMS.len() + count);
    for &s in LEGACY_V1_ATOMS {
        atoms.push(s.to_string());
    }
    for _ in 0..count {
        atoms.push(read_qjs_string(r)?);
    }
    Ok(AtomTableV1 { atoms })
}

fn read_value_v1(r: &mut Reader<'_>, atoms: &AtomTableV1) -> Result<Value, DeqjsError> {
    let tag = r.get_u8()?;
    match tag {
        BC_TAG_NULL => Ok(Value::Null),
        BC_TAG_UNDEFINED => Ok(Value::Undefined),
        BC_TAG_BOOL_FALSE => Ok(Value::Bool(false)),
        BC_TAG_BOOL_TRUE => Ok(Value::Bool(true)),
        BC_TAG_INT32 => Ok(Value::Int32(r.get_sleb128_i32()?)),
        BC_TAG_FLOAT64 => Ok(Value::Float64(r.get_f64()?)),
        BC_TAG_STRING => Ok(Value::String(read_qjs_string(r)?)),
        BC_TAG_OBJECT => {
            let prop_count = r.get_leb128_u32()? as usize;
            let mut props = Vec::with_capacity(prop_count);
            for _ in 0..prop_count {
                let name = atoms.read_atom_id(r)?;
                let val = read_value_v1(r, atoms)?;
                props.push((name, val));
            }
            Ok(Value::Object(props))
        }
        BC_TAG_ARRAY | BC_TAG_TEMPLATE_OBJECT_V1 => {
            let len = r.get_leb128_u32()? as usize;
            let mut items = Vec::with_capacity(len);
            for _ in 0..len {
                items.push(read_value_v1(r, atoms)?);
            }
            if tag == BC_TAG_TEMPLATE_OBJECT_V1 {
                let _template = read_value_v1(r, atoms)?;
            }
            Ok(Value::Array(items))
        }
        BC_TAG_FUNCTION_BYTECODE_V1 => Ok(Value::Function(read_function_bytecode_v1(r, atoms)?)),
        BC_TAG_MODULE_V1 => {
            let name = atoms.read_atom_id(r)?;

            let req_count = r.get_leb128_u32()? as usize;
            for _ in 0..req_count {
                let _ = atoms.read_atom_id(r)?;
            }

            let export_count = r.get_leb128_u32()? as usize;
            for _ in 0..export_count {
                let export_type = r.get_u8()?;
                if export_type == 0 {
                    let _ = r.get_leb128_u32()?;
                } else {
                    let _ = r.get_leb128_u32()?;
                    let _ = atoms.read_atom_id(r)?;
                }
                let _ = atoms.read_atom_id(r)?;
            }

            let star_count = r.get_leb128_u32()? as usize;
            for _ in 0..star_count {
                let _ = r.get_leb128_u32()?;
            }

            let import_count = r.get_leb128_u32()? as usize;
            for _ in 0..import_count {
                let _ = r.get_leb128_u32()?;
                let _ = atoms.read_atom_id(r)?;
                let _ = r.get_leb128_u32()?;
            }

            let func_obj = read_value_v1(r, atoms)?;
            Ok(Value::Module { name, func_obj: Box::new(func_obj) })
        }
        BC_TAG_TYPED_ARRAY_V1 => {
            let kind = r.get_u8()?;
            let len = r.get_leb128_u32()?;
            let offset = r.get_leb128_u32()?;
            let buffer = read_value_v1(r, atoms)?;
            Ok(Value::TypedArray { kind, len, offset, buffer: Box::new(buffer) })
        }
        BC_TAG_ARRAY_BUFFER_V1 => {
            let byte_length = r.get_leb128_u32()? as usize;
            let bytes = r.get_bytes(byte_length)?.to_vec();
            Ok(Value::ArrayBuffer { bytes })
        }
        BC_TAG_SHARED_ARRAY_BUFFER_V1 => {
            // EvilDecompiler reads: leb128 len + u64 ptr. We skip it.
            let _len = r.get_leb128_u32()?;
            let _ptr = r.get_u64()?;
            Ok(Value::Unsupported { tag })
        }
        BC_TAG_DATE_V1 => {
            let v = read_value_v1(r, atoms)?;
            Ok(Value::Date { value: Box::new(v) })
        }
        BC_TAG_OBJECT_VALUE_V1 => {
            // Wrapped value
            read_value_v1(r, atoms)
        }
        BC_TAG_OBJECT_REFERENCE_V1 => {
            let _idx = r.get_leb128_u32()?;
            Ok(Value::Unsupported { tag })
        }
        other => Err(DeqjsError::UnsupportedTag(other)),
    }
}

fn read_function_bytecode_v1(r: &mut Reader<'_>, atoms: &AtomTableV1) -> Result<FunctionBytecode, DeqjsError> {
    // Matches EvilDecompiler.JsObjectReader.ReadJsFunction.
    let flags = r.get_u16()?;
    let _js_mode = r.get_u8()?;
    let func_name = atoms.read_atom_id(r)?;

    let arg_count = r.get_leb128_u32()? as u16;
    let var_count = r.get_leb128_u32()? as u16;
    let defined_arg_count = r.get_leb128_u32()? as u16;
    let stack_size = r.get_leb128_u32()? as u16;

    let closure_var_count = r.get_leb128_u32()? as u16;
    let cpool_count = r.get_leb128_u32()?;
    let byte_code_len = r.get_leb128_u32()?;
    let local_count = r.get_leb128_u32()?;

    let mut locals = Vec::with_capacity(local_count as usize);
    for _ in 0..local_count {
        let name = atoms.read_atom_id(r)?;
        let scope_level = r.get_leb128_u32()?;
        let scope_next = r.get_leb128_u32()?;
        let flags = r.get_u8()?;
        locals.push(VarDef {
            name,
            scope_level,
            scope_next,
            flags,
            var_ref_idx: None,
        });
    }

    let mut closure_vars = Vec::with_capacity(closure_var_count as usize);
    for _ in 0..closure_var_count {
        let name = atoms.read_atom_id(r)?;
        let var_idx = r.get_leb128_u32()?;
        let flags = r.get_u8()? as u32;
        closure_vars.push(ClosureVar { name, var_idx, flags });
    }

    let bytecode = r.get_bytes(byte_code_len as usize)?.to_vec();

    // Debug info is present when flag.HasDebug != 0.
    // EvilDecompiler uses a bitfield type; we approximate with high bit check.
    let has_debug = (flags & 0x8000) != 0;
    if has_debug {
        let _file = atoms.read_atom_id(r)?;
        let _line = r.get_leb128_u32()?;
        let map_len = r.get_leb128_u32()? as usize;
        let _map = r.get_bytes(map_len)?;
    }

    let mut cpool = Vec::with_capacity(cpool_count as usize);
    for _ in 0..cpool_count {
        cpool.push(read_value_v1(r, atoms)?);
    }

    Ok(FunctionBytecode {
        func_name,
        is_strict_mode: false,
        arg_count,
        var_count,
        defined_arg_count,
        stack_size,
        var_ref_count: 0,
        closure_var_count,
        cpool_count,
        byte_code_len,
        locals,
        closure_vars,
        cpool,
        bytecode,
    })
}

fn read_value(r: &mut Reader<'_>, atoms: &AtomTable) -> Result<Value, DeqjsError> {
    let tag = r.get_u8()?;
    match tag {
        BC_TAG_NULL => Ok(Value::Null),
        BC_TAG_UNDEFINED => Ok(Value::Undefined),
        BC_TAG_BOOL_FALSE => Ok(Value::Bool(false)),
        BC_TAG_BOOL_TRUE => Ok(Value::Bool(true)),
        BC_TAG_INT32 => Ok(Value::Int32(r.get_sleb128_i32()?)),
        BC_TAG_FLOAT64 => Ok(Value::Float64(r.get_f64()?)),
        BC_TAG_STRING => Ok(Value::String(read_qjs_string(r)?)),
        BC_TAG_OBJECT => {
            let prop_count = r.get_leb128_u32()? as usize;
            let mut props = Vec::with_capacity(prop_count);
            for _ in 0..prop_count {
                let name = atoms.read_atom(r)?;
                let val = read_value(r, atoms)?;
                props.push((name, val));
            }
            Ok(Value::Object(props))
        }
        BC_TAG_ARRAY | BC_TAG_TEMPLATE_OBJECT => {
            let len = r.get_leb128_u32()? as usize;
            let mut items = Vec::with_capacity(len);
            for _ in 0..len {
                items.push(read_value(r, atoms)?);
            }
            if tag == BC_TAG_TEMPLATE_OBJECT {
                let _raw = read_value(r, atoms)?;
            }
            Ok(Value::Array(items))
        }
        BC_TAG_REGEXP => {
            let pattern = read_qjs_string(r)?;
            let bc = read_qjs_string(r)?;
            Ok(Value::RegExp { pattern, bytecode: bc })
        }
        BC_TAG_BIG_INT => {
            let len = r.get_leb128_u32()? as usize;
            let bytes = r.get_bytes(len)?.to_vec();
            Ok(Value::BigInt { bytes })
        }
        BC_TAG_SYMBOL => {
            let a = atoms.read_atom(r)?;
            Ok(Value::Symbol { atom: a })
        }
        BC_TAG_ARRAY_BUFFER => {
            let byte_length = r.get_leb128_u32()? as usize;
            let _max_byte_length = r.get_leb128_u32()?;
            let bytes = r.get_bytes(byte_length)?.to_vec();
            Ok(Value::ArrayBuffer { bytes })
        }
        BC_TAG_TYPED_ARRAY => {
            let kind = r.get_u8()?;
            let len = r.get_leb128_u32()?;
            let offset = r.get_leb128_u32()?;
            let buffer = read_value(r, atoms)?;
            Ok(Value::TypedArray { kind, len, offset, buffer: Box::new(buffer) })
        }
        BC_TAG_DATE => {
            let v = read_value(r, atoms)?;
            Ok(Value::Date { value: Box::new(v) })
        }
        BC_TAG_MODULE => {
            let name = atoms.read_atom(r)?;
            let req_count = r.get_leb128_u32()? as usize;
            for _ in 0..req_count {
                let _ = atoms.read_atom(r)?;
            }
            let export_count = r.get_leb128_u32()? as usize;
            for _ in 0..export_count {
                let _export_type = r.get_u8()?;
                if _export_type == 0 {
                    let _ = r.get_leb128_u32()?;
                } else {
                    let _ = r.get_leb128_u32()?;
                    let _ = atoms.read_atom(r)?;
                }
                let _ = atoms.read_atom(r)?;
            }
            let star_count = r.get_leb128_u32()? as usize;
            for _ in 0..star_count {
                let _ = r.get_leb128_u32()?;
            }
            let import_count = r.get_leb128_u32()? as usize;
            for _ in 0..import_count {
                let _ = r.get_leb128_u32()?;
                let _ = atoms.read_atom(r)?;
                let _ = r.get_leb128_u32()?;
            }
            let _has_tla = r.get_u8()?;
            let func_obj = read_value(r, atoms)?;
            Ok(Value::Module { name, func_obj: Box::new(func_obj) })
        }
        BC_TAG_FUNCTION_BYTECODE => Ok(Value::Function(read_function_bytecode(r, atoms)?)),
        other => {
            if matches!(
                other,
                BC_TAG_SHARED_ARRAY_BUFFER
                    | BC_TAG_OBJECT_VALUE
                    | BC_TAG_OBJECT_REFERENCE
                    | BC_TAG_MAP
                    | BC_TAG_SET
            ) {
                return Err(DeqjsError::UnsupportedTag(other));
            }
            Ok(Value::Unsupported { tag: other })
        }
    }
}

fn read_function_bytecode(r: &mut Reader<'_>, atoms: &AtomTable) -> Result<FunctionBytecode, DeqjsError> {
    let _flags = r.get_u16()?;
    let is_strict_mode = r.get_u8()? != 0;
    let func_name = atoms.read_atom(r)?;
    let arg_count = r.get_leb128_u32()? as u16;
    let var_count = r.get_leb128_u32()? as u16;
    let defined_arg_count = r.get_leb128_u32()? as u16;
    let stack_size = r.get_leb128_u32()? as u16;
    let var_ref_count = r.get_leb128_u32()? as u16;
    let closure_var_count = r.get_leb128_u32()? as u16;
    let cpool_count = r.get_leb128_u32()?;
    let byte_code_len = r.get_leb128_u32()?;
    let local_count = r.get_leb128_u32()?;

    let mut locals = Vec::with_capacity(local_count as usize);
    for _ in 0..local_count {
        let name = atoms.read_atom(r)?;
        let scope_level = r.get_leb128_u32()?;
        let scope_next = r.get_leb128_u32()?.saturating_sub(1);
        let flags = r.get_u8()?;
        let is_captured = (flags & 0x40) != 0;
        let var_ref_idx = if is_captured { Some(r.get_leb128_u32()?) } else { None };
        locals.push(VarDef {
            name,
            scope_level,
            scope_next,
            flags,
            var_ref_idx,
        });
    }

    let mut closure_vars = Vec::with_capacity(closure_var_count as usize);
    for _ in 0..closure_var_count {
        let name = atoms.read_atom(r)?;
        let var_idx = r.get_leb128_u32()?;
        let flags = r.get_leb128_u32()?;
        closure_vars.push(ClosureVar { name, var_idx, flags });
    }

    let mut cpool = Vec::with_capacity(cpool_count as usize);
    for _ in 0..cpool_count {
        cpool.push(read_value(r, atoms)?);
    }

    let bytecode = r.get_bytes(byte_code_len as usize)?.to_vec();

    Ok(FunctionBytecode {
        func_name,
        is_strict_mode,
        arg_count,
        var_count,
        defined_arg_count,
        stack_size,
        var_ref_count,
        closure_var_count,
        cpool_count,
        byte_code_len,
        locals,
        closure_vars,
        cpool,
        bytecode,
    })
}

fn opcode_info(op: u8) -> Option<&'static tables::OpInfo> {
    let op_usize = op as usize;
    let idx = if op_usize >= tables::OP_TEMP_START {
        op_usize.checked_add(tables::OP_TEMP_COUNT)?
    } else {
        op_usize
    };
    tables::OPCODE_INFO.get(idx)
}

fn opcode_stack_effect(op: u8) -> Option<(u8, u8)> {
    let i = opcode_info(op)?;
    Some((i.n_pop, i.n_push))
}

fn fmt_name(fmt: tables::OpFmt) -> &'static str {
    match fmt {
        tables::OpFmt::NONE => "none",
        tables::OpFmt::NONE_INT => "none_int",
        tables::OpFmt::NONE_LOC => "none_loc",
        tables::OpFmt::NONE_ARG => "none_arg",
        tables::OpFmt::NONE_VAR_REF => "none_var_ref",
        tables::OpFmt::U8 => "u8",
        tables::OpFmt::I8 => "i8",
        tables::OpFmt::LOC8 => "loc8",
        tables::OpFmt::CONST8 => "const8",
        tables::OpFmt::LABEL8 => "label8",
        tables::OpFmt::U16 => "u16",
        tables::OpFmt::I16 => "i16",
        tables::OpFmt::LABEL16 => "label16",
        tables::OpFmt::NPOP => "npop",
        tables::OpFmt::NPOPX => "npopx",
        tables::OpFmt::NPOP_U16 => "npop_u16",
        tables::OpFmt::LOC => "loc",
        tables::OpFmt::ARG => "arg",
        tables::OpFmt::VAR_REF => "var_ref",
        tables::OpFmt::U32 => "u32",
        tables::OpFmt::U32X2 => "u32x2",
        tables::OpFmt::I32 => "i32",
        tables::OpFmt::CONST => "const",
        tables::OpFmt::LABEL => "label",
        tables::OpFmt::ATOM => "atom",
        tables::OpFmt::ATOM_U8 => "atom_u8",
        tables::OpFmt::ATOM_U16 => "atom_u16",
        tables::OpFmt::ATOM_LABEL_U8 => "atom_label_u8",
        tables::OpFmt::ATOM_LABEL_U16 => "atom_label_u16",
        tables::OpFmt::LABEL_U16 => "label_u16",
    }
}

fn disassemble_function_with_atoms_and_instrs(
    b: &FunctionBytecode,
    atoms: &AtomTable,
    instrs: &[Instr],
    func_name: &str,
) -> Result<String, DeqjsError> {
    let mut out = String::new();
    out.push_str(&format!(
        "function {} (args={}, vars={}, strict={})\n",
        func_name, b.arg_count, b.var_count, b.is_strict_mode
    ));
    out.push_str("bytecode:\n");

    for ins in instrs {
        out.push_str(&format!("{:05} {:<18}", ins.pc, ins.name));
        match &ins.operand {
            None => {}
            Some(Operand::U8(v)) => out.push_str(&format!("       {}", v)),
            Some(Operand::I8(v)) => out.push_str(&format!("       {}", v)),
            Some(Operand::U16(v)) => out.push_str(&format!("       {}", v)),
            Some(Operand::I16(v)) => out.push_str(&format!("       {}", v)),
            Some(Operand::U32(v)) => out.push_str(&format!("       {}", v)),
            Some(Operand::I32(v)) => out.push_str(&format!("       {}", v)),
            Some(Operand::U32x2(a, b)) => out.push_str(&format!("       {}, {}", a, b)),
            Some(Operand::Label(rel)) => out.push_str(&format!("       {}", rel)),
            Some(Operand::LabelAbs(v)) => out.push_str(&format!("       {}", v)),
            Some(Operand::LabelU16(a, b)) => out.push_str(&format!("       {}, {}", a, b)),
            Some(Operand::Const(idx)) => out.push_str(&format!("       {}", idx)),
            Some(Operand::Atom(idx)) => {
                let a = atoms.resolve_idx(*idx).unwrap_or(AtomRepr::Raw(*idx));
                out.push_str(&format!("       {} ; {}", idx, a));
            }
            Some(Operand::AtomU8(idx, v)) => {
                let a = atoms.resolve_idx(*idx).unwrap_or(AtomRepr::Raw(*idx));
                out.push_str(&format!("       {}, {} ; {}", idx, v, a));
            }
            Some(Operand::AtomU16(idx, v)) => {
                let a = atoms.resolve_idx(*idx).unwrap_or(AtomRepr::Raw(*idx));
                out.push_str(&format!("       {}, {} ; {}", idx, v, a));
            }
            Some(Operand::AtomLabelU8(idx, rel, v)) => {
                let a = atoms.resolve_idx(*idx).unwrap_or(AtomRepr::Raw(*idx));
                out.push_str(&format!("       {}, {}, {} ; {}", idx, rel, v, a));
            }
            Some(Operand::AtomLabelU16(idx, rel, v)) => {
                let a = atoms.resolve_idx(*idx).unwrap_or(AtomRepr::Raw(*idx));
                out.push_str(&format!("       {}, {}, {} ; {}", idx, rel, v, a));
            }
            Some(Operand::NPop(v)) => out.push_str(&format!("       {}", v)),
            Some(Operand::NPopU16(a, b)) => out.push_str(&format!("       {}, {}", a, b)),
        }

        if matches!(
            ins.fmt,
            tables::OpFmt::NONE_INT | tables::OpFmt::NONE_LOC | tables::OpFmt::NONE_ARG | tables::OpFmt::NONE_VAR_REF | tables::OpFmt::NPOPX
        ) {
            out.push_str(&format!("       <fmt:{}>", fmt_name(ins.fmt)));
        }

        out.push('\n');
    }

    Ok(out)
}

fn decode_instructions_v1(b: &FunctionBytecode) -> Result<Vec<Instr>, DeqjsError> {
    let mut out = Vec::new();
    let mut pc: usize = 0;
    while pc < b.bytecode.len() {
        let op = b.bytecode[pc];
        let info = opcode_info_v1(op).ok_or(DeqjsError::InvalidOpcode(op))?;
        let size = info.size as usize;
        if b.bytecode.len() - pc < size {
            return Err(DeqjsError::TruncatedOpcode { pc, size, remaining: b.bytecode.len() - pc });
        }
        let args = &b.bytecode[pc + 1..pc + size];

        let operand = match info.fmt {
            OpFmtV1::None | OpFmtV1::NoneInt | OpFmtV1::NoneLoc | OpFmtV1::NoneArg | OpFmtV1::NoneVarRef | OpFmtV1::NPopX => None,
            OpFmtV1::U8 => Some(Operand::U8(args[0])),
            OpFmtV1::I8 => Some(Operand::I8(args[0] as i8)),
            OpFmtV1::U16 | OpFmtV1::Loc | OpFmtV1::Arg | OpFmtV1::VarRef => Some(Operand::U16(LittleEndian::read_u16(args))),
            OpFmtV1::NPop => Some(Operand::NPop(LittleEndian::read_u16(args))),
            OpFmtV1::NPopU16 => Some(Operand::NPopU16(LittleEndian::read_u16(args), LittleEndian::read_u16(&args[2..]))),
            OpFmtV1::I16 => Some(Operand::I16(LittleEndian::read_u16(args) as i16)),
            OpFmtV1::Label8 => Some(Operand::Label(args[0] as i8 as i32)),
            OpFmtV1::Label16 => Some(Operand::Label(LittleEndian::read_u16(args) as i16 as i32)),
            OpFmtV1::I32 => Some(Operand::I32(LittleEndian::read_i32(args))),
            OpFmtV1::U32 => Some(Operand::U32(LittleEndian::read_u32(args))),
            OpFmtV1::Label => Some(Operand::LabelAbs(LittleEndian::read_u32(args))),
            OpFmtV1::LabelU16 => Some(Operand::LabelU16(LittleEndian::read_u32(args), LittleEndian::read_u16(&args[4..]))),
            OpFmtV1::Const8 => Some(Operand::Const(args[0] as u32)),
            OpFmtV1::Const => Some(Operand::Const(LittleEndian::read_u32(args))),
            OpFmtV1::Atom => Some(Operand::Atom(LittleEndian::read_u32(args))),
            OpFmtV1::AtomU8 => Some(Operand::AtomU8(LittleEndian::read_u32(args), args[4])),
            OpFmtV1::AtomU16 => Some(Operand::AtomU16(LittleEndian::read_u32(args), LittleEndian::read_u16(&args[4..]))),
            OpFmtV1::AtomLabelU8 => Some(Operand::AtomLabelU8(LittleEndian::read_u32(args), LittleEndian::read_u32(&args[4..]), args[8])),
            OpFmtV1::AtomLabelU16 => Some(Operand::AtomLabelU16(LittleEndian::read_u32(args), LittleEndian::read_u32(&args[4..]), LittleEndian::read_u16(&args[8..]))),
            OpFmtV1::Loc8 => Some(Operand::U8(args[0])),
        };

        out.push(Instr {
            pc,
            op,
            name: info.name,
            size: info.size,
            fmt: v1_fmt_to_current(info.fmt),
            operand,
            n_pop: info.n_pop,
            n_push: info.n_push,
        });

        pc += size;
    }
    Ok(out)
}

fn collect_functions<'a>(v: &'a Value, out: &mut Vec<&'a FunctionBytecode>) {
    match v {
        Value::Function(b) => {
            out.push(b);
            for c in &b.cpool {
                collect_functions(c, out);
            }
        }
        Value::Array(items) => {
            for it in items {
                collect_functions(it, out);
            }
        }
        Value::Object(props) => {
            for (_k, val) in props {
                collect_functions(val, out);
            }
        }
        Value::Module { func_obj, .. } => collect_functions(func_obj, out),
        Value::TypedArray { buffer, .. } => collect_functions(buffer, out),
        Value::Date { value } => collect_functions(value, out),
        _ => {}
    }
}

fn module_entry_function<'a>(v: &'a Value) -> Option<&'a FunctionBytecode> {
    match v {
        Value::Module { func_obj, .. } => match func_obj.as_ref() {
            Value::Function(b) => Some(b),
            _ => None,
        },
        _ => None,
    }
}

fn collect_functions_entry_first<'a>(v: &'a Value) -> Vec<&'a FunctionBytecode> {
    let mut funcs = Vec::new();
    collect_functions(v, &mut funcs);
    if let Some(entry) = module_entry_function(v) {
        funcs.retain(|f| !std::ptr::eq(*f, entry));
        funcs.insert(0, entry);
    }
    funcs
}

fn display_func_name(options: DecompileOptions, b: &FunctionBytecode, idx: usize) -> String {
    if options.deobfuscate && matches!(b.func_name, AtomRepr::Null) {
        format!("closure_{idx}")
    } else {
        let name = b.func_name.to_string();
        if name.starts_with("<atom:") && name.ends_with(">") {
            if let Some(num_str) = name.strip_prefix("<atom:").and_then(|s| s.strip_suffix(">")) {
                if let Ok(num) = num_str.parse::<u32>() {
                    return format!("atom_{}", num);
                }
            }
        }
        name
    }
}

fn decompile_functions_with(
    funcs: &[&FunctionBytecode],
    options: DecompileOptions,
    atoms: &AtomTable,
    mut decode: impl FnMut(&FunctionBytecode) -> Result<Vec<Instr>, DeqjsError>,
) -> Result<String, DeqjsError> {
    let mut out = String::new();
    for (idx, b) in funcs.iter().copied().enumerate() {
        let instrs = decode(b)?;
        let func_name = display_func_name(options, b, idx);
        let s = match options.mode {
            DecompileMode::Pseudo => match pseudo_decompile_from_instrs(b, atoms, &instrs, &func_name, options.optimize, options.deobfuscate) {
                Ok(s) => s,
                Err(e) => format!("// Pseudo decompilation error: {}\n", e),
            },
            DecompileMode::Disasm => disassemble_function_with_atoms_and_instrs(b, atoms, &instrs, &func_name)?,
        };
        if s.trim().is_empty() {
            continue;
        }
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(&s);
    }
    Ok(out)
}

#[derive(Debug, Clone)]
pub enum Operand {
    U8(u8),
    I8(i8),
    U16(u16),
    I16(i16),
    U32(u32),
    I32(i32),
    U32x2(u32, u32),
    Label(i32),
    LabelAbs(u32),
    LabelU16(u32, u16),
    Const(u32),
    Atom(u32),
    AtomU8(u32, u8),
    AtomU16(u32, u16),
    AtomLabelU8(u32, u32, u8),
    AtomLabelU16(u32, u32, u16),
    NPop(u16),
    NPopU16(u16, u16),
}

#[derive(Debug, Clone)]
pub struct Instr {
    pub pc: usize,
    pub op: u8,
    pub name: &'static str,
    pub size: u8,
    pub fmt: tables::OpFmt,
    pub operand: Option<Operand>,
    pub n_pop: u8,
    pub n_push: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
enum OpFmtV1 {
    None,
    NoneInt,
    NoneLoc,
    NoneArg,
    NoneVarRef,
    U8,
    I8,
    Loc8,
    Const8,
    Label8,
    U16,
    I16,
    Label16,
    NPop,
    NPopX,
    NPopU16,
    Loc,
    Arg,
    VarRef,
    U32,
    I32,
    Const,
    Label,
    Atom,
    AtomU8,
    AtomU16,
    AtomLabelU8,
    AtomLabelU16,
    LabelU16,
}

#[derive(Debug, Clone, Copy)]
struct OpInfoV1 {
    name: &'static str,
    size: u8,
    n_pop: u8,
    n_push: u8,
    fmt: OpFmtV1,
}

// Sourced from EvilDecompiler.ByteCode.Type.QuickJsOPCodeInfo.Info
static OPCODE_INFO_V1: &[OpInfoV1] = &[
    OpInfoV1 { name: "invalid", size: 1, n_pop: 0, n_push: 0, fmt: OpFmtV1::None },
    OpInfoV1 { name: "push_i32", size: 5, n_pop: 0, n_push: 1, fmt: OpFmtV1::I32 },
    OpInfoV1 { name: "push_const", size: 5, n_pop: 0, n_push: 1, fmt: OpFmtV1::Const },
    OpInfoV1 { name: "fclosure", size: 5, n_pop: 0, n_push: 1, fmt: OpFmtV1::Const },
    OpInfoV1 { name: "push_atom_value", size: 5, n_pop: 0, n_push: 1, fmt: OpFmtV1::Atom },
    OpInfoV1 { name: "private_symbol", size: 5, n_pop: 0, n_push: 1, fmt: OpFmtV1::Atom },
    OpInfoV1 { name: "undefined", size: 1, n_pop: 0, n_push: 1, fmt: OpFmtV1::None },
    OpInfoV1 { name: "null", size: 1, n_pop: 0, n_push: 1, fmt: OpFmtV1::None },
    OpInfoV1 { name: "push_this", size: 1, n_pop: 0, n_push: 1, fmt: OpFmtV1::None },
    OpInfoV1 { name: "push_false", size: 1, n_pop: 0, n_push: 1, fmt: OpFmtV1::None },
    OpInfoV1 { name: "push_true", size: 1, n_pop: 0, n_push: 1, fmt: OpFmtV1::None },
    OpInfoV1 { name: "object", size: 1, n_pop: 0, n_push: 1, fmt: OpFmtV1::None },
    OpInfoV1 { name: "special_object", size: 2, n_pop: 0, n_push: 1, fmt: OpFmtV1::U8 },
    OpInfoV1 { name: "rest", size: 3, n_pop: 0, n_push: 1, fmt: OpFmtV1::U16 },
    OpInfoV1 { name: "drop", size: 1, n_pop: 1, n_push: 0, fmt: OpFmtV1::None },
    OpInfoV1 { name: "nip", size: 1, n_pop: 2, n_push: 1, fmt: OpFmtV1::None },
    OpInfoV1 { name: "nip1", size: 1, n_pop: 3, n_push: 2, fmt: OpFmtV1::None },
    OpInfoV1 { name: "dup", size: 1, n_pop: 1, n_push: 2, fmt: OpFmtV1::None },
    OpInfoV1 { name: "dup1", size: 1, n_pop: 2, n_push: 3, fmt: OpFmtV1::None },
    OpInfoV1 { name: "dup2", size: 1, n_pop: 2, n_push: 4, fmt: OpFmtV1::None },
    OpInfoV1 { name: "dup3", size: 1, n_pop: 3, n_push: 6, fmt: OpFmtV1::None },
    OpInfoV1 { name: "insert2", size: 1, n_pop: 2, n_push: 3, fmt: OpFmtV1::None },
    OpInfoV1 { name: "insert3", size: 1, n_pop: 3, n_push: 4, fmt: OpFmtV1::None },
    OpInfoV1 { name: "insert4", size: 1, n_pop: 4, n_push: 5, fmt: OpFmtV1::None },
    OpInfoV1 { name: "perm3", size: 1, n_pop: 3, n_push: 3, fmt: OpFmtV1::None },
    OpInfoV1 { name: "perm4", size: 1, n_pop: 4, n_push: 4, fmt: OpFmtV1::None },
    OpInfoV1 { name: "perm5", size: 1, n_pop: 5, n_push: 5, fmt: OpFmtV1::None },
    OpInfoV1 { name: "swap", size: 1, n_pop: 2, n_push: 2, fmt: OpFmtV1::None },
    OpInfoV1 { name: "swap2", size: 1, n_pop: 4, n_push: 4, fmt: OpFmtV1::None },
    OpInfoV1 { name: "rot3l", size: 1, n_pop: 3, n_push: 3, fmt: OpFmtV1::None },
    OpInfoV1 { name: "rot3r", size: 1, n_pop: 3, n_push: 3, fmt: OpFmtV1::None },
    OpInfoV1 { name: "rot4l", size: 1, n_pop: 4, n_push: 4, fmt: OpFmtV1::None },
    OpInfoV1 { name: "rot5l", size: 1, n_pop: 5, n_push: 5, fmt: OpFmtV1::None },
    OpInfoV1 { name: "call_constructor", size: 3, n_pop: 2, n_push: 1, fmt: OpFmtV1::NPop },
    OpInfoV1 { name: "call", size: 3, n_pop: 1, n_push: 1, fmt: OpFmtV1::NPop },
    OpInfoV1 { name: "tail_call", size: 3, n_pop: 1, n_push: 0, fmt: OpFmtV1::NPop },
    OpInfoV1 { name: "call_method", size: 3, n_pop: 2, n_push: 1, fmt: OpFmtV1::NPop },
    OpInfoV1 { name: "tail_call_method", size: 3, n_pop: 2, n_push: 0, fmt: OpFmtV1::NPop },
    OpInfoV1 { name: "array_from", size: 3, n_pop: 0, n_push: 1, fmt: OpFmtV1::NPop },
    OpInfoV1 { name: "apply", size: 3, n_pop: 3, n_push: 1, fmt: OpFmtV1::U16 },
    OpInfoV1 { name: "return", size: 1, n_pop: 1, n_push: 0, fmt: OpFmtV1::None },
    OpInfoV1 { name: "return_undef", size: 1, n_pop: 0, n_push: 0, fmt: OpFmtV1::None },
    OpInfoV1 { name: "check_ctor_return", size: 1, n_pop: 1, n_push: 2, fmt: OpFmtV1::None },
    OpInfoV1 { name: "check_ctor", size: 1, n_pop: 0, n_push: 0, fmt: OpFmtV1::None },
    OpInfoV1 { name: "check_brand", size: 1, n_pop: 2, n_push: 2, fmt: OpFmtV1::None },
    OpInfoV1 { name: "add_brand", size: 1, n_pop: 2, n_push: 0, fmt: OpFmtV1::None },
    OpInfoV1 { name: "return_async", size: 1, n_pop: 1, n_push: 0, fmt: OpFmtV1::None },
    OpInfoV1 { name: "throw", size: 1, n_pop: 1, n_push: 0, fmt: OpFmtV1::None },
    OpInfoV1 { name: "throw_error", size: 6, n_pop: 0, n_push: 0, fmt: OpFmtV1::AtomU8 },
    OpInfoV1 { name: "eval", size: 5, n_pop: 1, n_push: 1, fmt: OpFmtV1::NPopU16 },
    OpInfoV1 { name: "apply_eval", size: 3, n_pop: 2, n_push: 1, fmt: OpFmtV1::U16 },
    OpInfoV1 { name: "regexp", size: 1, n_pop: 2, n_push: 1, fmt: OpFmtV1::None },
    OpInfoV1 { name: "get_super", size: 1, n_pop: 1, n_push: 1, fmt: OpFmtV1::None },
    OpInfoV1 { name: "import", size: 1, n_pop: 1, n_push: 1, fmt: OpFmtV1::None },
    OpInfoV1 { name: "check_var", size: 5, n_pop: 0, n_push: 1, fmt: OpFmtV1::Atom },
    OpInfoV1 { name: "get_var_undef", size: 5, n_pop: 0, n_push: 1, fmt: OpFmtV1::Atom },
    OpInfoV1 { name: "get_var", size: 5, n_pop: 0, n_push: 1, fmt: OpFmtV1::Atom },
    OpInfoV1 { name: "put_var", size: 5, n_pop: 1, n_push: 0, fmt: OpFmtV1::Atom },
    OpInfoV1 { name: "put_var_init", size: 5, n_pop: 1, n_push: 0, fmt: OpFmtV1::Atom },
    OpInfoV1 { name: "put_var_strict", size: 5, n_pop: 2, n_push: 0, fmt: OpFmtV1::Atom },
    OpInfoV1 { name: "get_ref_value", size: 1, n_pop: 2, n_push: 3, fmt: OpFmtV1::None },
    OpInfoV1 { name: "put_ref_value", size: 1, n_pop: 3, n_push: 0, fmt: OpFmtV1::None },
    OpInfoV1 { name: "define_var", size: 6, n_pop: 0, n_push: 0, fmt: OpFmtV1::AtomU8 },
    OpInfoV1 { name: "check_define_var", size: 6, n_pop: 0, n_push: 0, fmt: OpFmtV1::AtomU8 },
    OpInfoV1 { name: "define_func", size: 6, n_pop: 1, n_push: 0, fmt: OpFmtV1::AtomU8 },
    OpInfoV1 { name: "get_field", size: 5, n_pop: 1, n_push: 1, fmt: OpFmtV1::Atom },
    OpInfoV1 { name: "get_field2", size: 5, n_pop: 1, n_push: 2, fmt: OpFmtV1::Atom },
    OpInfoV1 { name: "put_field", size: 5, n_pop: 2, n_push: 0, fmt: OpFmtV1::Atom },
    OpInfoV1 { name: "get_private_field", size: 1, n_pop: 2, n_push: 1, fmt: OpFmtV1::None },
    OpInfoV1 { name: "put_private_field", size: 1, n_pop: 3, n_push: 0, fmt: OpFmtV1::None },
    OpInfoV1 { name: "define_private_field", size: 1, n_pop: 3, n_push: 1, fmt: OpFmtV1::None },
    OpInfoV1 { name: "get_array_el", size: 1, n_pop: 2, n_push: 1, fmt: OpFmtV1::None },
    OpInfoV1 { name: "get_array_el2", size: 1, n_pop: 2, n_push: 2, fmt: OpFmtV1::None },
    OpInfoV1 { name: "put_array_el", size: 1, n_pop: 3, n_push: 0, fmt: OpFmtV1::None },
    OpInfoV1 { name: "get_super_value", size: 1, n_pop: 3, n_push: 1, fmt: OpFmtV1::None },
    OpInfoV1 { name: "put_super_value", size: 1, n_pop: 4, n_push: 0, fmt: OpFmtV1::None },
    OpInfoV1 { name: "define_field", size: 5, n_pop: 2, n_push: 1, fmt: OpFmtV1::Atom },
    OpInfoV1 { name: "set_name", size: 5, n_pop: 1, n_push: 1, fmt: OpFmtV1::Atom },
    OpInfoV1 { name: "set_name_computed", size: 1, n_pop: 2, n_push: 2, fmt: OpFmtV1::None },
    OpInfoV1 { name: "set_proto", size: 1, n_pop: 2, n_push: 1, fmt: OpFmtV1::None },
    OpInfoV1 { name: "set_home_object", size: 1, n_pop: 2, n_push: 2, fmt: OpFmtV1::None },
    OpInfoV1 { name: "define_array_el", size: 1, n_pop: 3, n_push: 2, fmt: OpFmtV1::None },
    OpInfoV1 { name: "append", size: 1, n_pop: 3, n_push: 2, fmt: OpFmtV1::None },
    OpInfoV1 { name: "copy_data_properties", size: 2, n_pop: 3, n_push: 3, fmt: OpFmtV1::U8 },
    OpInfoV1 { name: "define_method", size: 6, n_pop: 2, n_push: 1, fmt: OpFmtV1::AtomU8 },
    OpInfoV1 { name: "define_method_computed", size: 2, n_pop: 3, n_push: 1, fmt: OpFmtV1::U8 },
    OpInfoV1 { name: "define_class", size: 6, n_pop: 2, n_push: 2, fmt: OpFmtV1::AtomU8 },
    OpInfoV1 { name: "define_class_computed", size: 6, n_pop: 3, n_push: 3, fmt: OpFmtV1::AtomU8 },
    OpInfoV1 { name: "get_loc", size: 3, n_pop: 0, n_push: 1, fmt: OpFmtV1::Loc },
    OpInfoV1 { name: "put_loc", size: 3, n_pop: 1, n_push: 0, fmt: OpFmtV1::Loc },
    OpInfoV1 { name: "set_loc", size: 3, n_pop: 1, n_push: 1, fmt: OpFmtV1::Loc },
    OpInfoV1 { name: "get_arg", size: 3, n_pop: 0, n_push: 1, fmt: OpFmtV1::Arg },
    OpInfoV1 { name: "put_arg", size: 3, n_pop: 1, n_push: 0, fmt: OpFmtV1::Arg },
    OpInfoV1 { name: "set_arg", size: 3, n_pop: 1, n_push: 1, fmt: OpFmtV1::Arg },
    OpInfoV1 { name: "get_var_ref", size: 3, n_pop: 0, n_push: 1, fmt: OpFmtV1::VarRef },
    OpInfoV1 { name: "put_var_ref", size: 3, n_pop: 1, n_push: 0, fmt: OpFmtV1::VarRef },
    OpInfoV1 { name: "set_var_ref", size: 3, n_pop: 1, n_push: 1, fmt: OpFmtV1::VarRef },
    OpInfoV1 { name: "set_loc_uninitialized", size: 3, n_pop: 0, n_push: 0, fmt: OpFmtV1::Loc },
    OpInfoV1 { name: "get_loc_check", size: 3, n_pop: 0, n_push: 1, fmt: OpFmtV1::Loc },
    OpInfoV1 { name: "put_loc_check", size: 3, n_pop: 1, n_push: 0, fmt: OpFmtV1::Loc },
    OpInfoV1 { name: "put_loc_check_init", size: 3, n_pop: 1, n_push: 0, fmt: OpFmtV1::Loc },
    OpInfoV1 { name: "get_var_ref_check", size: 3, n_pop: 0, n_push: 1, fmt: OpFmtV1::VarRef },
    OpInfoV1 { name: "put_var_ref_check", size: 3, n_pop: 1, n_push: 0, fmt: OpFmtV1::VarRef },
    OpInfoV1 { name: "put_var_ref_check_init", size: 3, n_pop: 1, n_push: 0, fmt: OpFmtV1::VarRef },
    OpInfoV1 { name: "close_loc", size: 3, n_pop: 0, n_push: 0, fmt: OpFmtV1::Loc },
    OpInfoV1 { name: "if_false", size: 5, n_pop: 1, n_push: 0, fmt: OpFmtV1::Label },
    OpInfoV1 { name: "if_true", size: 5, n_pop: 1, n_push: 0, fmt: OpFmtV1::Label },
    OpInfoV1 { name: "goto", size: 5, n_pop: 0, n_push: 0, fmt: OpFmtV1::Label },
    OpInfoV1 { name: "catch", size: 5, n_pop: 0, n_push: 1, fmt: OpFmtV1::Label },
    OpInfoV1 { name: "gosub", size: 5, n_pop: 0, n_push: 0, fmt: OpFmtV1::Label },
    OpInfoV1 { name: "ret", size: 1, n_pop: 1, n_push: 0, fmt: OpFmtV1::None },
    OpInfoV1 { name: "to_object", size: 1, n_pop: 1, n_push: 1, fmt: OpFmtV1::None },
    OpInfoV1 { name: "to_propkey", size: 1, n_pop: 1, n_push: 1, fmt: OpFmtV1::None },
    OpInfoV1 { name: "to_propkey2", size: 1, n_pop: 2, n_push: 2, fmt: OpFmtV1::None },
    OpInfoV1 { name: "with_get_var", size: 10, n_pop: 1, n_push: 0, fmt: OpFmtV1::AtomLabelU8 },
    OpInfoV1 { name: "with_put_var", size: 10, n_pop: 2, n_push: 1, fmt: OpFmtV1::AtomLabelU8 },
    OpInfoV1 { name: "with_delete_var", size: 10, n_pop: 1, n_push: 0, fmt: OpFmtV1::AtomLabelU8 },
    OpInfoV1 { name: "with_make_ref", size: 10, n_pop: 1, n_push: 0, fmt: OpFmtV1::AtomLabelU8 },
    OpInfoV1 { name: "with_get_ref", size: 10, n_pop: 1, n_push: 0, fmt: OpFmtV1::AtomLabelU8 },
    OpInfoV1 { name: "with_get_ref_undef", size: 10, n_pop: 1, n_push: 0, fmt: OpFmtV1::AtomLabelU8 },
    OpInfoV1 { name: "make_loc_ref", size: 7, n_pop: 0, n_push: 2, fmt: OpFmtV1::AtomU16 },
    OpInfoV1 { name: "make_arg_ref", size: 7, n_pop: 0, n_push: 2, fmt: OpFmtV1::AtomU16 },
    OpInfoV1 { name: "make_var_ref_ref", size: 7, n_pop: 0, n_push: 2, fmt: OpFmtV1::AtomU16 },
    OpInfoV1 { name: "make_var_ref", size: 5, n_pop: 0, n_push: 2, fmt: OpFmtV1::Atom },
    OpInfoV1 { name: "for_in_start", size: 1, n_pop: 1, n_push: 1, fmt: OpFmtV1::None },
    OpInfoV1 { name: "for_of_start", size: 1, n_pop: 1, n_push: 3, fmt: OpFmtV1::None },
    OpInfoV1 { name: "for_await_of_start", size: 1, n_pop: 1, n_push: 3, fmt: OpFmtV1::None },
    OpInfoV1 { name: "for_in_next", size: 1, n_pop: 1, n_push: 3, fmt: OpFmtV1::None },
    OpInfoV1 { name: "for_of_next", size: 2, n_pop: 3, n_push: 5, fmt: OpFmtV1::U8 },
    OpInfoV1 { name: "iterator_check_object", size: 1, n_pop: 1, n_push: 1, fmt: OpFmtV1::None },
    OpInfoV1 { name: "iterator_get_value_done", size: 1, n_pop: 1, n_push: 2, fmt: OpFmtV1::None },
    OpInfoV1 { name: "iterator_close", size: 1, n_pop: 3, n_push: 0, fmt: OpFmtV1::None },
    OpInfoV1 { name: "iterator_close_return", size: 1, n_pop: 4, n_push: 4, fmt: OpFmtV1::None },
    OpInfoV1 { name: "iterator_next", size: 1, n_pop: 4, n_push: 4, fmt: OpFmtV1::None },
    OpInfoV1 { name: "iterator_call", size: 2, n_pop: 4, n_push: 5, fmt: OpFmtV1::U8 },
    OpInfoV1 { name: "initial_yield", size: 1, n_pop: 0, n_push: 0, fmt: OpFmtV1::None },
    OpInfoV1 { name: "yield", size: 1, n_pop: 1, n_push: 2, fmt: OpFmtV1::None },
    OpInfoV1 { name: "yield_star", size: 1, n_pop: 1, n_push: 2, fmt: OpFmtV1::None },
    OpInfoV1 { name: "async_yield_star", size: 1, n_pop: 1, n_push: 2, fmt: OpFmtV1::None },
    OpInfoV1 { name: "await", size: 1, n_pop: 1, n_push: 1, fmt: OpFmtV1::None },
    OpInfoV1 { name: "neg", size: 1, n_pop: 1, n_push: 1, fmt: OpFmtV1::None },
    OpInfoV1 { name: "plus", size: 1, n_pop: 1, n_push: 1, fmt: OpFmtV1::None },
    OpInfoV1 { name: "dec", size: 1, n_pop: 1, n_push: 1, fmt: OpFmtV1::None },
    OpInfoV1 { name: "inc", size: 1, n_pop: 1, n_push: 1, fmt: OpFmtV1::None },
    OpInfoV1 { name: "post_dec", size: 1, n_pop: 1, n_push: 2, fmt: OpFmtV1::None },
    OpInfoV1 { name: "post_inc", size: 1, n_pop: 1, n_push: 2, fmt: OpFmtV1::None },
    OpInfoV1 { name: "dec_loc", size: 2, n_pop: 0, n_push: 0, fmt: OpFmtV1::Loc8 },
    OpInfoV1 { name: "inc_loc", size: 2, n_pop: 0, n_push: 0, fmt: OpFmtV1::Loc8 },
    OpInfoV1 { name: "add_loc", size: 2, n_pop: 1, n_push: 0, fmt: OpFmtV1::Loc8 },
    OpInfoV1 { name: "not", size: 1, n_pop: 1, n_push: 1, fmt: OpFmtV1::None },
    OpInfoV1 { name: "lnot", size: 1, n_pop: 1, n_push: 1, fmt: OpFmtV1::None },
    OpInfoV1 { name: "typeof", size: 1, n_pop: 1, n_push: 1, fmt: OpFmtV1::None },
    OpInfoV1 { name: "delete", size: 1, n_pop: 2, n_push: 1, fmt: OpFmtV1::None },
    OpInfoV1 { name: "delete_var", size: 5, n_pop: 0, n_push: 1, fmt: OpFmtV1::Atom },
    OpInfoV1 { name: "mul", size: 1, n_pop: 2, n_push: 1, fmt: OpFmtV1::None },
    OpInfoV1 { name: "div", size: 1, n_pop: 2, n_push: 1, fmt: OpFmtV1::None },
    OpInfoV1 { name: "mod", size: 1, n_pop: 2, n_push: 1, fmt: OpFmtV1::None },
    OpInfoV1 { name: "add", size: 1, n_pop: 2, n_push: 1, fmt: OpFmtV1::None },
    OpInfoV1 { name: "sub", size: 1, n_pop: 2, n_push: 1, fmt: OpFmtV1::None },
    OpInfoV1 { name: "pow", size: 1, n_pop: 2, n_push: 1, fmt: OpFmtV1::None },
    OpInfoV1 { name: "shl", size: 1, n_pop: 2, n_push: 1, fmt: OpFmtV1::None },
    OpInfoV1 { name: "sar", size: 1, n_pop: 2, n_push: 1, fmt: OpFmtV1::None },
    OpInfoV1 { name: "shr", size: 1, n_pop: 2, n_push: 1, fmt: OpFmtV1::None },
    OpInfoV1 { name: "lt", size: 1, n_pop: 2, n_push: 1, fmt: OpFmtV1::None },
    OpInfoV1 { name: "lte", size: 1, n_pop: 2, n_push: 1, fmt: OpFmtV1::None },
    OpInfoV1 { name: "gt", size: 1, n_pop: 2, n_push: 1, fmt: OpFmtV1::None },
    OpInfoV1 { name: "gte", size: 1, n_pop: 2, n_push: 1, fmt: OpFmtV1::None },
    OpInfoV1 { name: "instanceof", size: 1, n_pop: 2, n_push: 1, fmt: OpFmtV1::None },
    OpInfoV1 { name: "in", size: 1, n_pop: 2, n_push: 1, fmt: OpFmtV1::None },
    OpInfoV1 { name: "eq", size: 1, n_pop: 2, n_push: 1, fmt: OpFmtV1::None },
    OpInfoV1 { name: "neq", size: 1, n_pop: 2, n_push: 1, fmt: OpFmtV1::None },
    OpInfoV1 { name: "strict_eq", size: 1, n_pop: 2, n_push: 1, fmt: OpFmtV1::None },
    OpInfoV1 { name: "strict_neq", size: 1, n_pop: 2, n_push: 1, fmt: OpFmtV1::None },
    OpInfoV1 { name: "and", size: 1, n_pop: 2, n_push: 1, fmt: OpFmtV1::None },
    OpInfoV1 { name: "xor", size: 1, n_pop: 2, n_push: 1, fmt: OpFmtV1::None },
    OpInfoV1 { name: "or", size: 1, n_pop: 2, n_push: 1, fmt: OpFmtV1::None },
    OpInfoV1 { name: "is_undefined_or_null", size: 1, n_pop: 1, n_push: 1, fmt: OpFmtV1::None },
    OpInfoV1 { name: "nop", size: 1, n_pop: 0, n_push: 0, fmt: OpFmtV1::None },
    OpInfoV1 { name: "push_minus1", size: 1, n_pop: 0, n_push: 1, fmt: OpFmtV1::NoneInt },
    OpInfoV1 { name: "push_0", size: 1, n_pop: 0, n_push: 1, fmt: OpFmtV1::NoneInt },
    OpInfoV1 { name: "push_1", size: 1, n_pop: 0, n_push: 1, fmt: OpFmtV1::NoneInt },
    OpInfoV1 { name: "push_2", size: 1, n_pop: 0, n_push: 1, fmt: OpFmtV1::NoneInt },
    OpInfoV1 { name: "push_3", size: 1, n_pop: 0, n_push: 1, fmt: OpFmtV1::NoneInt },
    OpInfoV1 { name: "push_4", size: 1, n_pop: 0, n_push: 1, fmt: OpFmtV1::NoneInt },
    OpInfoV1 { name: "push_5", size: 1, n_pop: 0, n_push: 1, fmt: OpFmtV1::NoneInt },
    OpInfoV1 { name: "push_6", size: 1, n_pop: 0, n_push: 1, fmt: OpFmtV1::NoneInt },
    OpInfoV1 { name: "push_7", size: 1, n_pop: 0, n_push: 1, fmt: OpFmtV1::NoneInt },
    OpInfoV1 { name: "push_i8", size: 2, n_pop: 0, n_push: 1, fmt: OpFmtV1::I8 },
    OpInfoV1 { name: "push_i16", size: 3, n_pop: 0, n_push: 1, fmt: OpFmtV1::I16 },
    OpInfoV1 { name: "push_const8", size: 2, n_pop: 0, n_push: 1, fmt: OpFmtV1::Const8 },
    OpInfoV1 { name: "fclosure8", size: 2, n_pop: 0, n_push: 1, fmt: OpFmtV1::Const8 },
    OpInfoV1 { name: "push_empty_string", size: 1, n_pop: 0, n_push: 1, fmt: OpFmtV1::None },
    OpInfoV1 { name: "get_loc8", size: 2, n_pop: 0, n_push: 1, fmt: OpFmtV1::Loc8 },
    OpInfoV1 { name: "put_loc8", size: 2, n_pop: 1, n_push: 0, fmt: OpFmtV1::Loc8 },
    OpInfoV1 { name: "set_loc8", size: 2, n_pop: 1, n_push: 1, fmt: OpFmtV1::Loc8 },
    OpInfoV1 { name: "get_loc0", size: 1, n_pop: 0, n_push: 1, fmt: OpFmtV1::NoneLoc },
    OpInfoV1 { name: "get_loc1", size: 1, n_pop: 0, n_push: 1, fmt: OpFmtV1::NoneLoc },
    OpInfoV1 { name: "get_loc2", size: 1, n_pop: 0, n_push: 1, fmt: OpFmtV1::NoneLoc },
    OpInfoV1 { name: "get_loc3", size: 1, n_pop: 0, n_push: 1, fmt: OpFmtV1::NoneLoc },
    OpInfoV1 { name: "put_loc0", size: 1, n_pop: 1, n_push: 0, fmt: OpFmtV1::NoneLoc },
    OpInfoV1 { name: "put_loc1", size: 1, n_pop: 1, n_push: 0, fmt: OpFmtV1::NoneLoc },
    OpInfoV1 { name: "put_loc2", size: 1, n_pop: 1, n_push: 0, fmt: OpFmtV1::NoneLoc },
    OpInfoV1 { name: "put_loc3", size: 1, n_pop: 1, n_push: 0, fmt: OpFmtV1::NoneLoc },
    OpInfoV1 { name: "set_loc0", size: 1, n_pop: 1, n_push: 1, fmt: OpFmtV1::NoneLoc },
    OpInfoV1 { name: "set_loc1", size: 1, n_pop: 1, n_push: 1, fmt: OpFmtV1::NoneLoc },
    OpInfoV1 { name: "set_loc2", size: 1, n_pop: 1, n_push: 1, fmt: OpFmtV1::NoneLoc },
    OpInfoV1 { name: "set_loc3", size: 1, n_pop: 1, n_push: 1, fmt: OpFmtV1::NoneLoc },
    OpInfoV1 { name: "get_arg0", size: 1, n_pop: 0, n_push: 1, fmt: OpFmtV1::NoneArg },
    OpInfoV1 { name: "get_arg1", size: 1, n_pop: 0, n_push: 1, fmt: OpFmtV1::NoneArg },
    OpInfoV1 { name: "get_arg2", size: 1, n_pop: 0, n_push: 1, fmt: OpFmtV1::NoneArg },
    OpInfoV1 { name: "get_arg3", size: 1, n_pop: 0, n_push: 1, fmt: OpFmtV1::NoneArg },
    OpInfoV1 { name: "put_arg0", size: 1, n_pop: 1, n_push: 0, fmt: OpFmtV1::NoneArg },
    OpInfoV1 { name: "put_arg1", size: 1, n_pop: 1, n_push: 0, fmt: OpFmtV1::NoneArg },
    OpInfoV1 { name: "put_arg2", size: 1, n_pop: 1, n_push: 0, fmt: OpFmtV1::NoneArg },
    OpInfoV1 { name: "put_arg3", size: 1, n_pop: 1, n_push: 0, fmt: OpFmtV1::NoneArg },
    OpInfoV1 { name: "set_arg0", size: 1, n_pop: 1, n_push: 1, fmt: OpFmtV1::NoneArg },
    OpInfoV1 { name: "set_arg1", size: 1, n_pop: 1, n_push: 1, fmt: OpFmtV1::NoneArg },
    OpInfoV1 { name: "set_arg2", size: 1, n_pop: 1, n_push: 1, fmt: OpFmtV1::NoneArg },
    OpInfoV1 { name: "set_arg3", size: 1, n_pop: 1, n_push: 1, fmt: OpFmtV1::NoneArg },
    OpInfoV1 { name: "get_var_ref0", size: 1, n_pop: 0, n_push: 1, fmt: OpFmtV1::NoneVarRef },
    OpInfoV1 { name: "get_var_ref1", size: 1, n_pop: 0, n_push: 1, fmt: OpFmtV1::NoneVarRef },
    OpInfoV1 { name: "get_var_ref2", size: 1, n_pop: 0, n_push: 1, fmt: OpFmtV1::NoneVarRef },
    OpInfoV1 { name: "get_var_ref3", size: 1, n_pop: 0, n_push: 1, fmt: OpFmtV1::NoneVarRef },
    OpInfoV1 { name: "put_var_ref0", size: 1, n_pop: 1, n_push: 0, fmt: OpFmtV1::NoneVarRef },
    OpInfoV1 { name: "put_var_ref1", size: 1, n_pop: 1, n_push: 0, fmt: OpFmtV1::NoneVarRef },
    OpInfoV1 { name: "put_var_ref2", size: 1, n_pop: 1, n_push: 0, fmt: OpFmtV1::NoneVarRef },
    OpInfoV1 { name: "put_var_ref3", size: 1, n_pop: 1, n_push: 0, fmt: OpFmtV1::NoneVarRef },
    OpInfoV1 { name: "set_var_ref0", size: 1, n_pop: 1, n_push: 1, fmt: OpFmtV1::NoneVarRef },
    OpInfoV1 { name: "set_var_ref1", size: 1, n_pop: 1, n_push: 1, fmt: OpFmtV1::NoneVarRef },
    OpInfoV1 { name: "set_var_ref2", size: 1, n_pop: 1, n_push: 1, fmt: OpFmtV1::NoneVarRef },
    OpInfoV1 { name: "set_var_ref3", size: 1, n_pop: 1, n_push: 1, fmt: OpFmtV1::NoneVarRef },
    OpInfoV1 { name: "get_length", size: 1, n_pop: 1, n_push: 1, fmt: OpFmtV1::None },
    OpInfoV1 { name: "if_false8", size: 2, n_pop: 1, n_push: 0, fmt: OpFmtV1::Label8 },
    OpInfoV1 { name: "if_true8", size: 2, n_pop: 1, n_push: 0, fmt: OpFmtV1::Label8 },
    OpInfoV1 { name: "goto8", size: 2, n_pop: 0, n_push: 0, fmt: OpFmtV1::Label8 },
    OpInfoV1 { name: "goto16", size: 3, n_pop: 0, n_push: 0, fmt: OpFmtV1::Label16 },
    OpInfoV1 { name: "call0", size: 1, n_pop: 1, n_push: 1, fmt: OpFmtV1::NPopX },
    OpInfoV1 { name: "call1", size: 1, n_pop: 1, n_push: 1, fmt: OpFmtV1::NPopX },
    OpInfoV1 { name: "call2", size: 1, n_pop: 1, n_push: 1, fmt: OpFmtV1::NPopX },
    OpInfoV1 { name: "call3", size: 1, n_pop: 1, n_push: 1, fmt: OpFmtV1::NPopX },
    OpInfoV1 { name: "is_undefined", size: 1, n_pop: 1, n_push: 1, fmt: OpFmtV1::None },
    OpInfoV1 { name: "is_null", size: 1, n_pop: 1, n_push: 1, fmt: OpFmtV1::None },
    OpInfoV1 { name: "typeof_is_undefined", size: 1, n_pop: 1, n_push: 1, fmt: OpFmtV1::None },
    OpInfoV1 { name: "typeof_is_function", size: 1, n_pop: 1, n_push: 1, fmt: OpFmtV1::None },
];

fn opcode_info_v1(op: u8) -> Option<&'static OpInfoV1> {
    OPCODE_INFO_V1.get(op as usize)
}

fn v1_fmt_to_current(fmt: OpFmtV1) -> tables::OpFmt {
    match fmt {
        OpFmtV1::None => tables::OpFmt::NONE,
        OpFmtV1::NoneInt => tables::OpFmt::NONE_INT,
        OpFmtV1::NoneLoc => tables::OpFmt::NONE_LOC,
        OpFmtV1::NoneArg => tables::OpFmt::NONE_ARG,
        OpFmtV1::NoneVarRef => tables::OpFmt::NONE_VAR_REF,
        OpFmtV1::U8 => tables::OpFmt::U8,
        OpFmtV1::I8 => tables::OpFmt::I8,
        OpFmtV1::Loc8 => tables::OpFmt::LOC8,
        OpFmtV1::Const8 => tables::OpFmt::CONST8,
        OpFmtV1::Label8 => tables::OpFmt::LABEL8,
        OpFmtV1::U16 => tables::OpFmt::U16,
        OpFmtV1::I16 => tables::OpFmt::I16,
        OpFmtV1::Label16 => tables::OpFmt::LABEL16,
        OpFmtV1::NPop => tables::OpFmt::NPOP,
        OpFmtV1::NPopX => tables::OpFmt::NPOPX,
        OpFmtV1::NPopU16 => tables::OpFmt::NPOP_U16,
        OpFmtV1::Loc => tables::OpFmt::LOC,
        OpFmtV1::Arg => tables::OpFmt::ARG,
        OpFmtV1::VarRef => tables::OpFmt::VAR_REF,
        OpFmtV1::U32 => tables::OpFmt::U32,
        OpFmtV1::I32 => tables::OpFmt::I32,
        OpFmtV1::Const => tables::OpFmt::CONST,
        OpFmtV1::Label => tables::OpFmt::LABEL,
        OpFmtV1::Atom => tables::OpFmt::ATOM,
        OpFmtV1::AtomU8 => tables::OpFmt::ATOM_U8,
        OpFmtV1::AtomU16 => tables::OpFmt::ATOM_U16,
        OpFmtV1::AtomLabelU8 => tables::OpFmt::ATOM_LABEL_U8,
        OpFmtV1::AtomLabelU16 => tables::OpFmt::ATOM_LABEL_U16,
        OpFmtV1::LabelU16 => tables::OpFmt::LABEL_U16,
    }
}

fn decode_instructions(b: &FunctionBytecode) -> Result<Vec<Instr>, DeqjsError> {
    let mut out = Vec::new();
    let mut pc: usize = 0;
    while pc < b.bytecode.len() {
        let op = b.bytecode[pc];
        let info = opcode_info(op).ok_or(DeqjsError::InvalidOpcode(op))?;
        let size = info.size as usize;
        if b.bytecode.len() - pc < size {
            return Err(DeqjsError::TruncatedOpcode { pc, size, remaining: b.bytecode.len() - pc });
        }
        let args = &b.bytecode[pc + 1..pc + size];
        let operand = match info.fmt {
            tables::OpFmt::NONE | tables::OpFmt::NONE_INT | tables::OpFmt::NONE_LOC | tables::OpFmt::NONE_ARG | tables::OpFmt::NONE_VAR_REF => None,
            tables::OpFmt::U8 => Some(Operand::U8(args[0])),
            tables::OpFmt::I8 => Some(Operand::I8(args[0] as i8)),
            tables::OpFmt::U16 | tables::OpFmt::LOC | tables::OpFmt::ARG | tables::OpFmt::VAR_REF => Some(Operand::U16(LittleEndian::read_u16(args))),
            tables::OpFmt::NPOP => Some(Operand::NPop(LittleEndian::read_u16(args))),
            tables::OpFmt::NPOP_U16 => Some(Operand::NPopU16(LittleEndian::read_u16(args), LittleEndian::read_u16(&args[2..]))),
            tables::OpFmt::I16 => Some(Operand::I16(LittleEndian::read_u16(args) as i16)),
            tables::OpFmt::LABEL8 => Some(Operand::Label(args[0] as i8 as i32)),
            tables::OpFmt::LABEL16 => Some(Operand::Label(LittleEndian::read_u16(args) as i16 as i32)),
            tables::OpFmt::I32 => Some(Operand::I32(LittleEndian::read_i32(args))),
            tables::OpFmt::U32 => Some(Operand::U32(LittleEndian::read_u32(args))),
            tables::OpFmt::U32X2 => Some(Operand::U32x2(LittleEndian::read_u32(args), LittleEndian::read_u32(&args[4..]))),
            tables::OpFmt::LABEL => Some(Operand::LabelAbs(LittleEndian::read_u32(args))),
            tables::OpFmt::LABEL_U16 => Some(Operand::LabelU16(LittleEndian::read_u32(args), LittleEndian::read_u16(&args[4..]))),
            tables::OpFmt::CONST8 => Some(Operand::Const(args[0] as u32)),
            tables::OpFmt::CONST => Some(Operand::Const(LittleEndian::read_u32(args))),
            tables::OpFmt::ATOM => Some(Operand::Atom(LittleEndian::read_u32(args))),
            tables::OpFmt::ATOM_U8 => Some(Operand::AtomU8(LittleEndian::read_u32(args), args[4])),
            tables::OpFmt::ATOM_U16 => Some(Operand::AtomU16(LittleEndian::read_u32(args), LittleEndian::read_u16(&args[4..]))),
            tables::OpFmt::ATOM_LABEL_U8 => Some(Operand::AtomLabelU8(LittleEndian::read_u32(args), LittleEndian::read_u32(&args[4..]), args[8])),
            tables::OpFmt::ATOM_LABEL_U16 => Some(Operand::AtomLabelU16(LittleEndian::read_u32(args), LittleEndian::read_u32(&args[4..]), LittleEndian::read_u16(&args[8..]))),
            tables::OpFmt::LOC8 => Some(Operand::U8(args[0])),
            tables::OpFmt::NPOPX => None,
        };

        out.push(Instr {
            pc,
            op,
            name: info.name,
            size: info.size,
            fmt: info.fmt,
            operand,
            n_pop: info.n_pop,
            n_push: info.n_push,
        });

        pc += size;
    }
    Ok(out)
}

fn label_target(i: &Instr) -> Option<usize> {
    match &i.operand {
        Some(Operand::Label(rel)) => {
            let base = (i.pc + 1) as i32;
            let t = base + *rel;
            if t < 0 {
                None
            } else {
                Some(t as usize)
            }
        }
        Some(Operand::LabelAbs(rel)) => {
            let base = (i.pc + 1) as u32;
            base.checked_add(*rel).map(|t| t as usize)
        }
        Some(Operand::AtomLabelU8(_, rel, _)) | Some(Operand::AtomLabelU16(_, rel, _)) => {
            let base = (i.pc + 5) as u32;
            base.checked_add(*rel).map(|t| t as usize)
        }
        Some(Operand::LabelU16(rel, _)) => {
            let base = (i.pc + 1) as u32;
            base.checked_add(*rel).map(|t| t as usize)
        }
        _ => None,
    }
}

#[derive(Debug, Clone)]
pub struct BasicBlock {
    pub start_pc: usize,
    pub instrs: Vec<Instr>,
    pub succs: Vec<usize>,
}

fn build_cfg(instrs: &[Instr]) -> Vec<BasicBlock> {
    use std::collections::{BTreeSet, HashMap};

    let mut leaders: BTreeSet<usize> = BTreeSet::new();
    if let Some(first) = instrs.first() {
        leaders.insert(first.pc);
    }
    for (idx, ins) in instrs.iter().enumerate() {
        if let Some(t) = label_target(ins) {
            leaders.insert(t);
            if let Some(next) = instrs.get(idx + 1) {
                leaders.insert(next.pc);
            }
        }
        if ins.name == "return" || ins.name == "return_undef" || ins.name == "throw" {
            if let Some(next) = instrs.get(idx + 1) {
                leaders.insert(next.pc);
            }
        }
    }

    let mut leader_to_block: HashMap<usize, usize> = HashMap::new();
    let mut blocks: Vec<BasicBlock> = Vec::new();
    let leader_list: Vec<usize> = leaders.into_iter().collect();
    for (bi, &pc) in leader_list.iter().enumerate() {
        leader_to_block.insert(pc, bi);
        blocks.push(BasicBlock { start_pc: pc, instrs: Vec::new(), succs: Vec::new() });
    }

    let mut pc_to_block: HashMap<usize, usize> = HashMap::new();
    for (bi, b) in blocks.iter().enumerate() {
        pc_to_block.insert(b.start_pc, bi);
    }
    let mut current_block = 0usize;
    let mut next_leader_idx = 1usize;
    let mut next_leader = leader_list.get(next_leader_idx).copied();

    for ins in instrs.iter().cloned() {
        if Some(ins.pc) == next_leader {
            current_block = pc_to_block[&ins.pc];
            next_leader_idx += 1;
            next_leader = leader_list.get(next_leader_idx).copied();
        }
        blocks[current_block].instrs.push(ins);
    }

    for bi in 0..blocks.len() {
        let last = blocks[bi].instrs.last().cloned();
        let mut succs = Vec::new();
        if let Some(last) = last {
            if last.name == "goto" || last.name == "goto8" || last.name == "goto16" {
                if let Some(t) = label_target(&last) {
                    if let Some(&bti) = leader_to_block.get(&t) {
                        succs.push(blocks[bti].start_pc);
                    }
                }
            } else if last.name == "if_false" || last.name == "if_true" || last.name == "if_false8" || last.name == "if_true8" {
                if let Some(t) = label_target(&last) {
                    if let Some(&bti) = leader_to_block.get(&t) {
                        succs.push(blocks[bti].start_pc);
                    }
                }
                if let Some(next_block) = blocks.get(bi + 1) {
                    succs.push(next_block.start_pc);
                }
            } else if last.name == "return" || last.name == "return_undef" || last.name == "throw" {
            } else {
                if let Some(next_block) = blocks.get(bi + 1) {
                    succs.push(next_block.start_pc);
                }
            }
        }
        blocks[bi].succs = succs;
    }

    blocks
}

fn arg_name(b: &FunctionBytecode, idx: u16) -> String {
    if (idx as usize) < b.locals.len() {
        b.locals[idx as usize].name.to_string()
    } else {
        format!("arg{}", idx)
    }
}

fn loc_name(_b: &FunctionBytecode, idx: u16) -> String {
    format!("loc{}", idx)
}

fn var_ref_name(b: &FunctionBytecode, idx: u16) -> String {
    let i = idx as usize;
    if i < b.closure_vars.len() {
        let a = &b.closure_vars[i].name;
        let raw: Option<String> = match a {
            AtomRepr::Null => None,
            AtomRepr::String(s) => Some(s.clone()),
            _ => Some(a.to_string()),
        };
        if let Some(raw) = raw {
            let s = sanitize_ident(&raw);
            if s != "_" {
                return s;
            }
        }
        format!("var_ref{}", idx)
    } else {
        format!("var_ref{}", idx)
    }
}

fn closure_name(deobfuscate: bool, b: &FunctionBytecode, idx: u16) -> String {
    if let Some(Value::Function(closure)) = b.cpool.get(idx as usize) {
        display_func_name(DecompileOptions { mode: DecompileMode::Pseudo, version: DecompileVersion::Legacy, deobfuscate, optimize: false }, closure, idx as usize)
    } else {
        format!("<fclosure{}>", idx)
    }
}

fn sanitize_ident(s: &str) -> String {
    if s.is_empty() {
        return "_".into();
    }
    let mut out = String::new();
    for (i, ch) in s.chars().enumerate() {
        let ok = if i == 0 {
            ch == '_' || ch == '$' || ch.is_ascii_alphabetic()
        } else {
            ch == '_' || ch == '$' || ch.is_ascii_alphanumeric()
        };
        if ok {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        "_".into()
    } else {
        out
    }
}

#[derive(Debug, Clone)]
enum Stmt {
    Expr(String),
    Assign(String, String),
    Return(Option<String>),
    CondGoto {
        cond: String,
        if_false: bool,
        target: usize,
    },
    IfElse {
        cond: String,
        then_stmts: Vec<Stmt>,
        else_stmts: Vec<Stmt>,
    },
    While {
        cond: String,
        body: Vec<Stmt>,
    },
    Goto(usize),
    Label(usize),
}

fn stmts_to_string(stmts: &[Stmt], indent: usize) -> String {
    let mut out = String::new();
    let pad = " ".repeat(indent);
    for s in stmts {
        match s {
            Stmt::Expr(e) => out.push_str(&format!("{pad}{e};\n")),
            Stmt::Assign(lhs, rhs) => out.push_str(&format!("{pad}{lhs} = {rhs};\n")),
            Stmt::Return(Some(v)) => out.push_str(&format!("{pad}return {v};\n")),
            Stmt::Return(None) => out.push_str(&format!("{pad}return;\n")),
            Stmt::CondGoto {
                cond,
                if_false,
                target,
            } => {
                if *if_false {
                    out.push_str(&format!("{pad}if (!{cond}) goto L{target};\n"));
                } else {
                    out.push_str(&format!("{pad}if ({cond}) goto L{target};\n"));
                }
            }
            Stmt::Goto(t) => out.push_str(&format!("{pad}goto L{t};\n")),
            Stmt::Label(pc) => out.push_str(&format!("{pad}L{pc}:\n")),
            Stmt::IfElse {
                cond,
                then_stmts,
                else_stmts,
            } => {
                out.push_str(&format!("{pad}if ({cond}) {{\n"));
                out.push_str(&stmts_to_string(then_stmts, indent + 2));
                if else_stmts.is_empty() {
                    out.push_str(&format!("{pad}}}\n"));
                } else {
                    out.push_str(&format!("{pad}}} else {{\n"));
                    out.push_str(&stmts_to_string(else_stmts, indent + 2));
                    out.push_str(&format!("{pad}}}\n"));
                }
            }
            Stmt::While { cond, body } => {
                out.push_str(&format!("{pad}while ({cond}) {{\n"));
                out.push_str(&stmts_to_string(body, indent + 2));
                out.push_str(&format!("{pad}}}\n"));
            }
        }
    }
    out
}

fn optimize_stmts(stmts: &[Stmt]) -> Vec<Stmt> {
    let mut out: Vec<Stmt> = Vec::new();
    let mut i = 0usize;
    while i < stmts.len() {
        if let Some(Stmt::Goto(t)) = stmts.get(i) {
            if let (Some(Stmt::Label(lpc)), Some(Stmt::Return(ret))) = (stmts.get(i + 1), stmts.get(i + 2)) {
                if lpc == t {
                    out.push(Stmt::Return(ret.clone()));
                    i += 3;
                    continue;
                }
            }
        }
        out.push(stmts[i].clone());
        i += 1;
    }

    let mut out2: Vec<Stmt> = Vec::new();
    let mut j = 0usize;
    while j < out.len() {
        if let (Some(Stmt::Label(a)), Some(Stmt::Label(b))) = (out.get(j), out.get(j + 1)) {
            if a == b {
                j += 1;
                continue;
            }
        }
        out2.push(out[j].clone());
        j += 1;
    }
    out2
}

fn try_structure_while(stmts: &[Stmt]) -> Vec<Stmt> {
    // Pattern:
    //   Label(loop)
    //   CondGoto(if_false=true, target=end)
    //   ...body...
    //   Goto(loop)
    //   Label(end)
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < stmts.len() {
        if let (Some(Stmt::Label(loop_pc)), Some(Stmt::CondGoto { cond, if_false, target: end_pc })) =
            (stmts.get(i), stmts.get(i + 1))
        {
            if *if_false {
                    let mut body = Vec::new();
                    let mut j = i + 2;
                    while j < stmts.len() {
                        if let Stmt::Goto(t) = &stmts[j] {
                            if *t == *loop_pc {
                                break;
                            }
                        }
                        body.push(stmts[j].clone());
                        j += 1;
                    }
                    if let (Some(Stmt::Goto(t)), Some(Stmt::Label(pc2))) = (stmts.get(j), stmts.get(j + 1)) {
                        if *t == *loop_pc && *pc2 == *end_pc {
                            out.push(Stmt::While {
                                cond: cond.clone(),
                                body,
                            });
                            i = j + 2;
                            continue;
                        }
                    }
            }
        }
        out.push(stmts[i].clone());
        i += 1;
    }
    out
}

fn try_structure_if_else(stmts: &[Stmt]) -> Vec<Stmt> {
    // Pattern:
    //   CondGoto(if_false=true, target=else)
    //   ...then...
    //   Goto(end)
    //   Label(else)
    //   ...else...
    //   Label(end)
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < stmts.len() {
        if let (
            Some(Stmt::CondGoto {
                cond,
                if_false,
                target: else_pc,
            }),
            Some(Stmt::Goto(_end_from_then)),
        ) = (stmts.get(i), stmts.get(i + 1))
        {
            if *if_false {
                let mut then_stmts = Vec::new();
                let mut j = i + 2;
                while j < stmts.len() {
                    if matches!(stmts[j], Stmt::Goto(_)) {
                        break;
                    }
                    if let Stmt::Label(pc) = stmts[j] {
                        if pc == *else_pc {
                            break;
                        }
                    }
                    then_stmts.push(stmts[j].clone());
                    j += 1;
                }
                if let Some(Stmt::Goto(end_pc)) = stmts.get(j) {
                    if let Some(Stmt::Label(pc)) = stmts.get(j + 1) {
                        if *pc == *else_pc {
                            let mut else_stmts = Vec::new();
                            let mut k = j + 2;
                            while k < stmts.len() {
                                if let Stmt::Label(pc2) = stmts[k] {
                                    if pc2 == *end_pc {
                                        break;
                                    }
                                }
                                else_stmts.push(stmts[k].clone());
                                k += 1;
                            }
                            if let Some(Stmt::Label(pc2)) = stmts.get(k) {
                                if *pc2 == *end_pc {
                                    out.push(Stmt::IfElse {
                                        cond: cond.clone(),
                                        then_stmts,
                                        else_stmts,
                                    });
                                    i = k + 1;
                                    continue;
                                }
                            }
                        }
                    }
                }
            }
        }
        out.push(stmts[i].clone());
        i += 1;
    }
    out
}

fn pseudo_decompile_from_instrs(
    b: &FunctionBytecode,
    atoms: &AtomTable,
    instrs: &[Instr],
    func_name: &str,
    optimize: bool,
    deobfuscate: bool,
) -> Result<String, DeqjsError> {
    let blocks = build_cfg(&instrs);

    let mut stmts: Vec<Stmt> = Vec::new();

    for blk in blocks {
        stmts.push(Stmt::Label(blk.start_pc));
        let mut stack: Vec<String> = Vec::new();

        for ins in &blk.instrs {
            match ins.name {
                "push_i8" => {
                    if let Some(Operand::I8(v)) = ins.operand {
                        stack.push(v.to_string());
                    }
                }
                "push_i16" => {
                    if let Some(Operand::I16(v)) = ins.operand {
                        stack.push(v.to_string());
                    }
                }
                "push_i32" => {
                    if let Some(Operand::I32(v)) = ins.operand {
                        stack.push(v.to_string());
                    }
                }
                "push_u8" => {
                    if let Some(Operand::U8(v)) = ins.operand {
                        stack.push(v.to_string());
                    }
                }
                "push_u16" => {
                    if let Some(Operand::U16(v)) = ins.operand {
                        stack.push(v.to_string());
                    }
                }
                "push_u32" => {
                    if let Some(Operand::U32(v)) = ins.operand {
                        stack.push(v.to_string());
                    }
                }
                n if n == "push_minus1" || (n.starts_with("push_") && n.chars().skip(5).all(|c| c.is_ascii_digit())) => {
                    let n = if n == "push_minus1" { -1 } else {
                        let idx_str = &n[5..];
                        idx_str.parse::<i32>().unwrap()
                    };
                    stack.push(n.to_string());
                }
                "push_true" => stack.push("true".into()),
                "push_false" => stack.push("false".into()),
                "push_this" => stack.push("this".into()),
                "push_empty_string" => stack.push("\"\"".into()),
                "undefined" => stack.push("undefined".into()),
                "null" => stack.push("null".into()),
                "push_const" | "push_const8" => {
                    if let Some(Operand::Const(idx)) = ins.operand {
                        let expr = if (idx as usize) < b.cpool.len() {
                            format!("{}", b.cpool[idx as usize])
                        } else {
                            format!("<const:{}>", idx)
                        };
                        stack.push(expr);
                    }
                }
                "push_atom_value" => {
                    if let Some(Operand::Atom(idx)) = ins.operand {
                        let a = atoms.resolve_idx(idx)?;
                        match a {
                            AtomRepr::String(s) => stack.push(format!("\"{}\"", s)),
                            _ => stack.push(a.to_string()),
                        }
                    }
                }
                "fclosure" | "fclosure8" => {
                    if let Some(Operand::Const(idx)) = ins.operand {
                        stack.push(closure_name(deobfuscate, b, idx as u16));
                    }
                }
                "get_loc0_loc1" => {
                    stack.push(loc_name(b, 0));
                    stack.push(loc_name(b, 1));
                }
                "get_arg" => {
                    if let Some(Operand::U16(idx)) = ins.operand {
                        stack.push(arg_name(b, idx));
                    }
                }
                "get_loc" => {
                    if let Some(Operand::U16(idx)) = ins.operand {
                        stack.push(loc_name(b, idx));
                    }
                }
                "get_loc_check" => {
                    if let Some(Operand::U16(idx)) = ins.operand {
                        stack.push(loc_name(b, idx));
                    }
                }
                n if n.starts_with("get_arg") && n != "get_arg" && n.chars().skip(7).all(|c| c.is_ascii_digit()) => {
                    let idx_str = &n[7..];
                    if let Ok(idx) = idx_str.parse::<u16>() {
                        stack.push(arg_name(b, idx));
                    } else {
                        stack.push(format!("<{}>", n));
                    }
                }
                n if n.starts_with("get_loc") && n != "get_loc" && n != "get_loc0_loc1" && n.chars().skip(7).all(|c| c.is_ascii_digit()) => {
                    let idx_str = &n[7..];
                    if let Ok(idx) = idx_str.parse::<u16>() {
                        stack.push(loc_name(b, idx));
                    } else {
                        stack.push(format!("<{}>", n));
                    }
                }
                "get_var_ref" | "get_var_ref_check" => {
                    if let Some(Operand::U16(idx)) = ins.operand {
                        stack.push(var_ref_name(b, idx));
                    } else {
                        stack.push("<get_var_ref>".into());
                    }
                }
                n if n.starts_with("get_var_ref") && n != "get_var_ref" && n != "get_var_ref_check" && n.chars().skip(11).all(|c| c.is_ascii_digit()) => {
                    let idx_str = &n[11..];
                    if let Ok(idx) = idx_str.parse::<u16>() {
                        stack.push(var_ref_name(b, idx));
                    } else {
                        stack.push(format!("<{}>", n));
                    }
                }
                "set_var_ref" | "set_var_ref_check" => {
                    let rhs = stack.pop().unwrap_or("<rhs>".into());
                    if let Some(Operand::U16(idx)) = ins.operand {
                        let name = var_ref_name(b, idx);
                        stmts.push(Stmt::Expr(format!("{name} = {rhs}")));
                        stack.push(rhs);
                    } else {
                        stmts.push(Stmt::Expr(format!("<set_var_ref> = {rhs}")));
                        stack.push(rhs);
                    }
                }
                n if n.starts_with("set_var_ref") && n != "set_var_ref" && n != "set_var_ref_check" && n.chars().skip(11).all(|c| c.is_ascii_digit()) => {
                    let idx_str = &n[11..];
                    if let Ok(idx) = idx_str.parse::<u16>() {
                        let rhs = stack.pop().unwrap_or("<rhs>".into());
                        let name = var_ref_name(b, idx);
                        stmts.push(Stmt::Expr(format!("{name} = {rhs}")));
                        stack.push(rhs);
                    } else {
                        stack.push(format!("<{}>", n));
                    }
                }
                "put_var_ref" | "put_var_ref_check" | "put_var_ref_check_init" => {
                    let rhs = stack.pop().unwrap_or("<rhs>".into());
                    if let Some(Operand::U16(idx)) = ins.operand {
                        let name = var_ref_name(b, idx);
                        stmts.push(Stmt::Expr(format!("{name} = {rhs}")));
                    } else {
                        stmts.push(Stmt::Expr(format!("<put_var_ref> = {rhs}")));
                    }
                }
                n if n.starts_with("put_var_ref") && n != "put_var_ref" && n != "put_var_ref_check" && n != "put_var_ref_check_init" && n.chars().skip(11).all(|c| c.is_ascii_digit()) => {
                    let idx_str = &n[11..];
                    if let Ok(idx) = idx_str.parse::<u16>() {
                        let rhs = stack.pop().unwrap_or("<rhs>".into());
                        let name = var_ref_name(b, idx);
                        stmts.push(Stmt::Expr(format!("{name} = {rhs}")));
                    } else {
                        stack.push(format!("<{}>", n));
                    }
                }
                "drop" => {
                    let _ = stack.pop();
                }
                "dup" => {
                    if let Some(v) = stack.last().cloned() {
                        stack.push(v);
                    }
                }
                "swap" => {
                    if stack.len() >= 2 {
                        let n = stack.len();
                        stack.swap(n - 1, n - 2);
                    }
                }
                "nip" => {
                    if stack.len() >= 2 {
                        let n = stack.len();
                        stack.remove(n - 2);
                    }
                }
                "add" | "sub" | "mul" | "div" | "mod" | "and" | "or" | "xor" | "shl" | "sar" | "shr" | "eq" | "neq" | "strict_eq" | "strict_neq" | "lt" | "lte" | "gt" | "gte" => {
                    let rhs = stack.pop().unwrap_or("<rhs>".into());
                    let lhs = stack.pop().unwrap_or("<lhs>".into());
                    let op = match ins.name {
                        "add" => "+",
                        "sub" => "-",
                        "mul" => "*",
                        "div" => "/",
                        "mod" => "%",
                        "and" => "&",
                        "or" => "|",
                        "xor" => "^",
                        "shl" => "<<",
                        "sar" => ">>",
                        "shr" => ">>>",
                        "eq" => "==",
                        "neq" => "!=",
                        "strict_eq" => "===",
                        "strict_neq" => "!==",
                        "lt" => "<",
                        "lte" => "<=",
                        "gt" => ">",
                        _ => ">=",
                    };
                    stack.push(format!("({lhs} {op} {rhs})"));
                }
                "post_inc" => {
                    let value = stack.pop().unwrap_or("<value>".into());
                    stack.push(value.clone());
                    stack.push(format!("{} + 1", value));
                }
                "is_undefined" => {
                    let val = stack.pop().unwrap_or("<val>".into());
                    stack.push(format!("{} === undefined", val));
                }
                "to_object" => {
                    let val = stack.pop().unwrap_or("<val>".into());
                    stack.push(format!("Object({})", val));
                }
                "to_propkey2" => {
                    let val2 = stack.pop().unwrap_or("<val2>".into());
                    let val1 = stack.pop().unwrap_or("<val1>".into());
                    stack.push(format!("String({})", val1));
                    stack.push(format!("String({})", val2));
                }
                "inc_loc" => {
                    if let Some(Operand::U8(idx)) = ins.operand {
                        stmts.push(Stmt::Expr(format!("{}++", loc_name(b, idx as u16))));
                    }
                }
                "regexp" => {
                    let flags = stack.pop().unwrap_or("<flags>".into());
                    let pattern = stack.pop().unwrap_or("<pattern>".into());
                    if flags.starts_with('"') && flags.ends_with('"') && flags.len() < 20 && !flags.contains("\\u") {
                        stack.push(format!("new RegExp({}, {})", pattern, flags));
                    } else {
                        stack.push(format!("new RegExp({})", pattern));
                    }
                }
                "in" => {
                    let prop = stack.pop().unwrap_or("<prop>".into());
                    let obj = stack.pop().unwrap_or("<obj>".into());
                    stack.push(format!("({} in {})", prop, obj));
                }
                "object" => stack.push("{}".into()),
                // TODO: find corresponding object kinds
                "special_object" => {
                    if let Some(Operand::U8(kind)) = ins.operand {
                        stack.push(format!("<special_object_{}>", kind));
                    } else {
                        stack.push("<special_object>".into());
                    }
                }
                "instanceof" => {
                    let constructor = stack.pop().unwrap_or("<constructor>".into());
                    let obj = stack.pop().unwrap_or("<obj>".into());
                    stack.push(format!("({} instanceof {})", obj, constructor));
                }
                "typeof" => {
                    let value = stack.pop().unwrap_or("<value>".into());
                    stack.push(format!("typeof {}", value));
                }
                "define_field" => {
                    let value = stack.pop().unwrap_or("<value>".into());
                    let obj = stack.pop().unwrap_or("<obj>".into());
                    if let Some(Operand::Atom(idx)) = ins.operand {
                        let prop: String = match atoms.resolve_idx(idx) {
                            Ok(p) => p.to_string(),
                            Err(e) => {
                                stmts.push(Stmt::Expr(format!("// Atom resolution error: {}", e)));
                                "<invalid_atom>".to_string()
                            }
                        };
                        stmts.push(Stmt::Expr(format!("{obj}.{} = {value}", prop)));
                        stack.push(obj);
                    } else {
                        stmts.push(Stmt::Expr(format!("<define_field> {obj} {value}")));
                        stack.push("<define_field>".into());
                    }
                }
                "set_name" => {
                    let obj = stack.pop().unwrap_or("<obj>".into());
                    if let Some(Operand::Atom(idx)) = ins.operand {
                        let name: String = match atoms.resolve_idx(idx) {
                            Ok(n) => n.to_string(),
                            Err(e) => {
                                stmts.push(Stmt::Expr(format!("// Atom resolution error: {}", e)));
                                "<invalid_atom>".to_string()
                            }
                        };
                        stmts.push(Stmt::Expr(format!("{}.name = \"{}\"", obj, name)));
                        stack.push(obj);
                    } else {
                        stack.push("<set_name>".into());
                    }
                }
                "define_class" => {
                    let parent_ctor = stack.pop().unwrap_or("<parent_ctor>".into());
                    if let Some(Operand::AtomU8(idx, _flags)) = ins.operand {
                        let name: String = match atoms.resolve_idx(idx as u32) {
                            Ok(n) => n.to_string(),
                            Err(e) => {
                                stmts.push(Stmt::Expr(format!("// Atom resolution error: {}", e)));
                                "<invalid_atom>".to_string()
                            }
                        };
                        stmts.push(Stmt::Expr(format!("class {} extends {}", name, parent_ctor)));
                        stack.push("<ctor>".into());
                        stack.push("<proto>".into());
                    } else {
                        stack.push("<define_class>".into());
                    }
                }
                "define_method" => {
                    let method = stack.pop().unwrap_or("<method>".into());
                    let obj = stack.pop().unwrap_or("<obj>".into());
                    if let Some(Operand::AtomU8(idx, _flags)) = ins.operand {
                        let name: String = match atoms.resolve_idx(idx as u32) {
                            Ok(n) => n.to_string(),
                            Err(e) => {
                                stmts.push(Stmt::Expr(format!("// Atom resolution error: {}", e)));
                                "<invalid_atom>".to_string()
                            }
                        };
                        stmts.push(Stmt::Expr(format!("{}.{} = {}", obj, name, method)));
                        stack.push(obj);
                    } else {
                        stack.push("<define_method>".into());
                    }
                }
                "close_loc" => {
                    if let Some(Operand::U16(idx)) = ins.operand {
                        stmts.push(Stmt::Expr(format!("close {}", loc_name(b, idx))));
                    }
                }
                "check_ctor" => {
                    stmts.push(Stmt::Expr("check_ctor".into()));
                }
                "not" | "lnot" => {
                    let v = stack.pop().unwrap_or("<v>".into());
                    let op = if ins.name == "not" { "~" } else { "!" };
                    stack.push(format!("({op}{v})"));
                }
                "call" | "tail_call" | "call_method" | "tail_call_method" | "call_constructor" | "array_from" => {
                    if let Some(Operand::NPop(argc)) = ins.operand {
                        let mut args = Vec::with_capacity(argc as usize);
                        for _ in 0..argc {
                            args.push(stack.pop().unwrap_or("<arg>".into()));
                        }
                        args.reverse();
                        let func = stack.pop().unwrap_or("<func>".into());
                        stack.push(format!("{func}({})", args.join(", ")));
                    }
                }
                n if n.starts_with("call") && n.chars().skip(4).all(|c| c.is_ascii_digit()) => {
                    let idx_str = &n[4..];
                    let argc = idx_str.parse::<usize>().unwrap();
                    let mut args = Vec::with_capacity(argc);
                    for _ in 0..argc {
                        args.push(stack.pop().unwrap_or("<arg>".into()));
                    }
                    args.reverse();
                    let func = stack.pop().unwrap_or("<func>".into());
                    stack.push(format!("{func}({})", args.join(", ")));
                }
                "put_loc" | "put_loc8" => {
                    let rhs = stack.pop().unwrap_or("<rhs>".into());
                    let idx = match ins.operand {
                        Some(Operand::U16(v)) => v,
                        Some(Operand::U8(v)) => v as u16,
                        _ => 0,
                    };
                    let name = loc_name(b, idx);
                    stmts.push(Stmt::Assign(name, rhs));
                }
                n if n.starts_with("put_loc") && n != "put_loc" && n != "put_loc8" && n.chars().skip(7).all(|c| c.is_ascii_digit()) => {
                    let idx_str = &n[7..];
                    if let Ok(idx) = idx_str.parse::<u16>() {
                        let rhs = stack.pop().unwrap_or("<rhs>".into());
                        let name = loc_name(b, idx);
                        stmts.push(Stmt::Assign(name, rhs));
                    } else {
                        stack.push(format!("<{}>", n));
                    }
                }
                "put_loc_check" => {
                    if let Some(Operand::U16(idx)) = ins.operand {
                        let rhs = stack.pop().unwrap_or("<rhs>".into());
                        stmts.push(Stmt::Assign(loc_name(b, idx), rhs));
                    }
                }
                "set_loc" | "set_loc8" => {
                    let rhs = stack.last().cloned().unwrap_or("<rhs>".into());
                    let idx = match ins.operand {
                        Some(Operand::U16(v)) => v,
                        Some(Operand::U8(v)) => v as u16,
                        _ => 0,
                    };
                    stmts.push(Stmt::Assign(loc_name(b, idx), rhs));
                }
                "set_loc_uninitialized" => {
                    if let Some(Operand::U16(idx)) = ins.operand {
                        stmts.push(Stmt::Expr(format!("{} = undefined", loc_name(b, idx))));
                    }
                }
                n if n.starts_with("set_loc") && n != "set_loc" && n != "set_loc8" && n.chars().skip(7).all(|c| c.is_ascii_digit()) => {
                    let idx_str = &n[7..];
                    if let Ok(idx) = idx_str.parse::<u16>() {
                        let rhs = stack.last().cloned().unwrap_or("<rhs>".into());
                        stmts.push(Stmt::Assign(loc_name(b, idx), rhs));
                    } else {
                        stack.push(format!("<{}>", n));
                    }
                }
                "put_arg" => {
                    let rhs = stack.pop().unwrap_or("<rhs>".into());
                    let idx = match ins.operand {
                        Some(Operand::U16(v)) => v,
                        _ => 0,
                    };
                    let name = arg_name(b, idx);
                    stmts.push(Stmt::Assign(name, rhs));
                }
                n if n.starts_with("put_arg") && n != "put_arg" && n.chars().skip(7).all(|c| c.is_ascii_digit()) => {
                    let idx_str = &n[7..];
                    if let Ok(idx) = idx_str.parse::<u16>() {
                        let rhs = stack.pop().unwrap_or("<rhs>".into());
                        let name = arg_name(b, idx);
                        stmts.push(Stmt::Assign(name, rhs));
                    } else {
                        stack.push(format!("<{}>", n));
                    }
                }
                "set_arg" => {
                    let rhs = stack.last().cloned().unwrap_or("<rhs>".into());
                    let idx = match ins.operand {
                        Some(Operand::U16(v)) => v,
                        _ => 0,
                    };
                    stmts.push(Stmt::Assign(arg_name(b, idx), rhs));
                }
                n if n.starts_with("set_arg") && n != "set_arg" && n.chars().skip(7).all(|c| c.is_ascii_digit()) => {
                    let idx_str = &n[7..];
                    if let Ok(idx) = idx_str.parse::<u16>() {
                        let rhs = stack.last().cloned().unwrap_or("<rhs>".into());
                        stmts.push(Stmt::Assign(arg_name(b, idx), rhs));
                    } else {
                        stack.push(format!("<{}>", n));
                    }
                }
                "get_var" | "get_var_undef" => {
                    if let Some(Operand::Atom(idx)) = ins.operand {
                        let a = atoms.resolve_idx(idx)?;
                        stack.push(a.to_string());
                    }
                }
                "put_var" | "put_var_init" => {
                    let rhs = stack.pop().unwrap_or("<rhs>".into());
                    if let Some(Operand::Atom(idx)) = ins.operand {
                        let a = atoms.resolve_idx(idx)?;
                        stmts.push(Stmt::Assign(a.to_string(), rhs));
                    }
                }
                "get_field" | "get_field2" => {
                    if let Some(Operand::Atom(idx)) = ins.operand {
                        let prop = atoms.resolve_idx(idx)?;
                        let obj = stack.pop().unwrap_or("<obj>".into());
                        stack.push(format!("{obj}.{}", prop));
                    }
                }
                "put_field" => {
                    let rhs = stack.pop().unwrap_or("<rhs>".into());
                    let obj = stack.pop().unwrap_or("<obj>".into());
                    if let Some(Operand::Atom(idx)) = ins.operand {
                        let prop = atoms.resolve_idx(idx)?;
                        stmts.push(Stmt::Expr(format!("{obj}.{} = {rhs}", prop)));
                    }
                }
                "get_array_el" | "get_array_el2" => {
                    let prop = stack.pop().unwrap_or("<prop>".into());
                    let obj = stack.pop().unwrap_or("<obj>".into());
                    let value = format!("{obj}[{prop}]");
                    if ins.name == "get_array_el" {
                        stack.push(value);
                    } else {
                        stack.push(obj);
                        stack.push(value);
                    }
                }
                "put_array_el" => {
                    let rhs = stack.pop().unwrap_or("<rhs>".into());
                    let index = stack.pop().unwrap_or("<index>".into());
                    let obj = stack.pop().unwrap_or("<obj>".into());
                    stmts.push(Stmt::Expr(format!("{obj}[{index}] = {rhs}")));
                }
                "get_length" => {
                    let obj = stack.pop().unwrap_or("<obj>".into());
                    stack.push(format!("{obj}.length"));
                }
                "return" => {
                    let v = stack.pop().unwrap_or("undefined".into());
                    stmts.push(Stmt::Return(Some(v)));
                }
                "return_undef" => {
                    stmts.push(Stmt::Return(None));
                }
                "ret" => {
                    let v = stack.pop().unwrap_or("undefined".into());
                    stmts.push(Stmt::Expr(format!("ret {}", v)));
                }
                "throw" => {
                    let v = stack.pop().unwrap_or("<value>".into());
                    stmts.push(Stmt::Expr(format!("throw {}", v)));
                }
                "if_false" | "if_true" | "if_false8" | "if_true8" => {
                    let cond = stack.pop().unwrap_or("<cond>".into());
                    let target = label_target(ins).unwrap_or(0);
                    if ins.name.contains("false") {
                        stmts.push(Stmt::CondGoto {
                            cond,
                            if_false: true,
                            target,
                        });
                    } else {
                        stmts.push(Stmt::CondGoto {
                            cond,
                            if_false: false,
                            target,
                        });
                    }
                }
                "goto" | "goto8" | "goto16" => {
                    let target = label_target(ins).unwrap_or(0);
                    stmts.push(Stmt::Goto(target));
                }
                "gosub" => {
                    let target = label_target(ins).unwrap_or(0);
                    stmts.push(Stmt::Expr(format!("gosub L{}", target)));
                }
                "catch" => {
                    stack.push("<exception>".into());
                }
                "for_of_start" => {
                    let _iterable = stack.pop();
                    stack.push("<iterator>".into());
                    stack.push("<method>".into());
                    stack.push("<done>".into());
                }
                "for_of_next" => {
                    let done = stack.pop().unwrap_or("<done>".into());
                    let method = stack.pop().unwrap_or("<method>".into());
                    let iterator = stack.pop().unwrap_or("<iterator>".into());
                    stack.push(iterator);
                    stack.push(method);
                    stack.push(done);
                    stack.push("<value>".into());
                    stack.push("<done>".into());
                }
                "iterator_close" => {
                    let _done = stack.pop();
                    let _method = stack.pop();
                    let _iterator = stack.pop();
                }
                "insert2" => {
                    let a = stack.pop().unwrap_or("<a>".into());
                    let obj = stack.pop().unwrap_or("<obj>".into());
                    stack.push(a.clone());
                    stack.push(obj);
                    stack.push(a);
                }
                "insert3" => {
                    let a = stack.pop().unwrap_or("<a>".into());
                    let prop = stack.pop().unwrap_or("<prop>".into());
                    let obj = stack.pop().unwrap_or("<obj>".into());
                    stack.push(a.clone());
                    stack.push(obj);
                    stack.push(prop);
                    stack.push(a);
                }
                "insert4" => {
                    let a = stack.pop().unwrap_or("<a>".into());
                    let prop = stack.pop().unwrap_or("<prop>".into());
                    let obj = stack.pop().unwrap_or("<obj>".into());
                    let this = stack.pop().unwrap_or("<this>".into());
                    stack.push(a.clone());
                    stack.push(this);
                    stack.push(obj);
                    stack.push(prop);
                    stack.push(a);
                }
                _ => {
                    // generic stack-effect-based fallback
                    let (npop, npush) = opcode_stack_effect(ins.op).unwrap_or((ins.n_pop, ins.n_push));
                    for _ in 0..npop {
                        let _ = stack.pop();
                    }
                    for _ in 0..npush {
                        stack.push(format!("<{}>", ins.name));
                    }
                    stmts.push(Stmt::Expr(format!("<{}>", ins.name)));
                }
            }
        }
    }

    let stmts = try_structure_while(&stmts);
    let stmts = try_structure_if_else(&stmts);

    let stmts = if optimize {
        optimize_stmts(&stmts)
    } else {
        stmts
    };

    if optimize {
        let has_any_real = stmts.iter().any(|s| !matches!(s, Stmt::Label(_)));
        if !has_any_real {
            return Ok(String::new());
        }
        if let [Stmt::Label(_), Stmt::Return(ret)] = stmts.as_slice() {
            if let Some(expr) = ret {
                return Ok(format!("function {func_name}() {{ return {expr}; }}\n"));
            }
            return Ok(format!("function {func_name}() {{ return; }}\n"));
        }
        if let [Stmt::Return(ret)] = stmts.as_slice() {
            if let Some(expr) = ret {
                return Ok(format!("function {func_name}() {{ return {expr}; }}\n"));
            }
            return Ok(format!("function {func_name}() {{ return; }}\n"));
        }
    }

    let mut out = String::new();
    out.push_str(&format!("function {}() {{\n", func_name));
    out.push_str(&stmts_to_string(&stmts, 2));
    out.push_str("}\n");
    Ok(out)
}

pub fn decompile_with_mode(bytecode: &[u8], mode: DecompileMode) -> Result<String, DeqjsError> {
    decompile_with_options(
        bytecode,
        DecompileOptions {
            mode,
            version: DecompileVersion::Auto,
            deobfuscate: false,
            optimize: false,
        },
    )
}

pub fn decompile_with_options(bytecode: &[u8], options: DecompileOptions) -> Result<String, DeqjsError> {
    let mut r = Reader::new(bytecode);
    let version = match options.version {
        DecompileVersion::Auto => match r.peek_u8() {
            Some(BC_VERSION_V1) => DecompileVersion::Legacy,
            _ => DecompileVersion::Current,
        },
        v => v,
    };

    match version {
        DecompileVersion::Legacy => {
            let atoms = read_atom_table_v1(&mut r)?;
            let atoms_adapted = atoms.to_atom_table();
            let v = read_value_v1(&mut r, &atoms)?;
            let funcs = collect_functions_entry_first(&v);
            if funcs.is_empty() {
                return Ok(format!("{}", v));
            }
            decompile_functions_with(&funcs, options, &atoms_adapted, decode_instructions_v1)
        }
        DecompileVersion::Current => {
            let atoms = read_atom_table(&mut r)?;
            let v = read_value(&mut r, &atoms)?;
            let funcs = collect_functions_entry_first(&v);
            if funcs.is_empty() {
                return Ok(format!("{}", v));
            }
            decompile_functions_with(&funcs, options, &atoms, decode_instructions)
        }
        DecompileVersion::Auto => unreachable!(),
    }
}

pub fn decompile(bytecode: &[u8]) -> Result<String, DeqjsError> {
    decompile_with_options(bytecode, DecompileOptions::default())
}
