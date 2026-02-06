# deqjs

a (vibe-coded) decompiler for quickjs bytecode

## building

```bash
cargo build --release
```

artifact at `target/release/deqjs_cli`

## usage

```bash
deqjs_cli decompile file --mode pseudo ./test.jsc --deobfuscate --optimize --output ./result.js
```

## license
gpl 3
