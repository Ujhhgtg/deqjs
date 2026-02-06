use std::env;
use std::fs;
use std::path::{Path, PathBuf};

fn workspace_root(crate_dir: &Path) -> PathBuf {
    crate_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("crate directory should be <root>/crates/<name>")
        .to_path_buf()
}

fn take_until_paren_close<'a>(s: &'a str) -> Option<&'a str> {
    let s = s.trim();
    let j = s.find(')')?;
    Some(s[..j].trim())
}

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let root = workspace_root(&manifest_dir);

    let opcode_path = root.join("quickjs").join("quickjs-opcode.h");
    let atom_path = root.join("quickjs").join("quickjs-atom.h");

    println!("cargo:rerun-if-changed={}", opcode_path.display());
    println!("cargo:rerun-if-changed={}", atom_path.display());

    let opcode_src = fs::read_to_string(&opcode_path).expect("read quickjs-opcode.h");
    let atom_src = fs::read_to_string(&atom_path).expect("read quickjs-atom.h");

    let mut fmts: Vec<String> = Vec::new();
    let mut ops: Vec<(String, u8, u8, u8, String, bool)> = Vec::new();
    let mut temp_count: usize = 0;

    for line in opcode_src.lines() {
        let l = line.trim();
        if let Some(rest) = l.strip_prefix("FMT(") {
            let name = match take_until_paren_close(rest) {
                Some(v) => v,
                None => continue,
            };
            if !name.is_empty() {
                fmts.push(name.to_string());
            }
            continue;
        }

        let (is_temp, rest) = if let Some(rest) = l.strip_prefix("def(") {
            (true, rest)
        } else if let Some(rest) = l.strip_prefix("DEF(") {
            (false, rest)
        } else {
            continue;
        };

        let inner = match take_until_paren_close(rest) {
            Some(v) => v,
            None => continue,
        };
        let parts: Vec<&str> = inner.split(',').map(|p| p.trim()).collect();
        if parts.len() != 5 {
            continue;
        }
        let id = parts[0].to_string();
        let size: u8 = parts[1].parse().expect("opcode size");
        let n_pop: u8 = parts[2].parse().expect("opcode n_pop");
        let n_push: u8 = parts[3].parse().expect("opcode n_push");
        let fmt = parts[4].to_string();

        if is_temp {
            temp_count += 1;
        }
        ops.push((id, size, n_pop, n_push, fmt, is_temp));
    }

    let mut atoms: Vec<(String, String)> = Vec::new();
    for line in atom_src.lines() {
        let l = line.trim();
        let rest = match l.strip_prefix("DEF(") {
            Some(v) => v,
            None => continue,
        };
        let inner = match take_until_paren_close(rest) {
            Some(v) => v,
            None => continue,
        };
        let mut parts = inner.splitn(2, ',');
        let name = parts.next().unwrap().trim().to_string();
        let s = parts.next().unwrap_or("").trim();
        let s = s.trim_matches(')');
        let s = s.trim();
        if !s.starts_with('"') {
            continue;
        }
        let s = s.trim_matches('"').to_string();
        atoms.push((name, s));
    }

    let mut nop_index: Option<usize> = None;
    for (i, (id, _, _, _, _, is_temp)) in ops.iter().enumerate() {
        if !*is_temp && id == "nop" {
            nop_index = Some(i);
            break;
        }
    }
    let op_temp_start = nop_index.map(|i| i + 1).expect("OP_nop not found");

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let out_path = out_dir.join("quickjs_tables.rs");

    let mut out = String::new();

    out.push_str("#[allow(non_camel_case_types)]\n");
    out.push_str("#[derive(Debug, Clone, Copy, PartialEq, Eq)]\n");
    out.push_str("pub enum OpFmt {\n");
    for f in &fmts {
        out.push_str(&format!("    {},\n", f.to_ascii_uppercase()));
    }
    out.push_str("}\n\n");

    out.push_str("#[derive(Debug, Clone, Copy)]\n");
    out.push_str("pub struct OpInfo {\n");
    out.push_str("    pub name: &'static str,\n");
    out.push_str("    pub size: u8,\n");
    out.push_str("    pub n_pop: u8,\n");
    out.push_str("    pub n_push: u8,\n");
    out.push_str("    pub fmt: OpFmt,\n");
    out.push_str("}\n\n");

    out.push_str(&format!("pub const OP_TEMP_START: usize = {};\n", op_temp_start));
    out.push_str(&format!("pub const OP_TEMP_COUNT: usize = {};\n\n", temp_count));

    out.push_str("pub const OPCODE_INFO: &[OpInfo] = &[\n");
    for (id, size, n_pop, n_push, fmt, _) in &ops {
        let fmt_ident = fmt.to_ascii_uppercase();
        out.push_str(&format!(
            "    OpInfo {{ name: \"{}\", size: {}, n_pop: {}, n_push: {}, fmt: OpFmt::{} }},\n",
            id, size, n_pop, n_push, fmt_ident
        ));
    }
    out.push_str("];\n\n");

    out.push_str("pub const BUILTIN_ATOMS: &[&str] = &[\n");
    for (_name, s) in &atoms {
        out.push_str(&format!("    \"{}\",\n", s.replace('\\', "\\\\").replace('"', "\\\"")));
    }
    out.push_str("];\n");

    fs::write(out_path, out).expect("write generated quickjs tables");
}
