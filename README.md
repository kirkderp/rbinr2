# rbinr2

[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-stable-blue)](rust-toolchain.toml)
[![radare2](https://img.shields.io/badge/radare2-5.9+-orange)](https://rada.re)

MCP server for radare2-based binary analysis.

`rbinr2` manages persistent r2pipe sessions, runs radare2 analysis on binaries,
and exposes 39 tools as named [Model Context Protocol](https://modelcontextprotocol.io)
tools over stdio.

## Tools

**Session Management**
- `r2_open` / `r2_close` / `r2_sessions`  --  open/close/list persistent r2 sessions

**Metadata & Discovery**
- `r2_metadata`  --  mode-driven view: info, headers, version_info, entry_points, sections, relocations, resources, libraries, imports, exports, symbols, strings, or functions (with name filtering and pagination)
- `r2_classes`  --  list classes or inspect one class with methods/fields
- `r2_vtables`  --  bounded native vtable discovery with pagination
- `r2_types`  --  type-system views, function signatures, struct/enum lists, and type casts
- `r2_imports_grouped`  --  imports grouped by semantic usage with calling functions
- `r2_plugins`  --  installed r2 asm, analysis, binary, hash, and decompiler capabilities
- `r2_flags`  --  flags, demangled names, and flagspaces with pagination
- `r2_lookup_address`  --  resolve an address to flags, symbols, enclosing function
- `r2_address_info`  --  r2 address classification metadata from `aij`
- `r2_calculate`  --  evaluate a math expression (?v), returns hex/decimal/binary

**Disassembly & Decompilation**
- `r2_disassemble`  --  bounded instruction window (json or text); function mode available
- `r2_opcodes`  --  structured opcode-analysis rows from `aoj`
- `r2_decompile`  --  pseudocode via an installed r2 decompiler plugin (code or meta mode)
- `r2_function_view`  --  mode-driven: analyze, info, signature, vars, profile, strings, constants, callees, refs, or cfg
- `r2_graph`  --  native r2 graph exports for CFGs, callgraphs, imports, refs, xrefs, and data refs

**Bytes & Extraction**
- `r2_get_bytes`  --  raw hex bytes from an address
- `r2_extract_bytes`  --  bounded byte range with SHA256, previews, section mapping, and optional write-out
- `r2_block_hash`  --  bounded `ph` hash or entropy value at an address
- `r2_pointer_scan`  --  bounded pointer/reference-like memory scan from `pxrj`
- `r2_string_at`  --  decode strings at an address as auto/ascii/utf16/utf32/pascal

**Search**
- `r2_find`  --  unified search across functions (glob), strings, imports, or bytes (hex)
- `r2_semantic_search`  --  opcode-type, disasm-text, wide-string, value, reference, ROP, or hex search
- `r2_find_xrefs`  --  search and immediately resolve cross-references to each hit

**Cross-References & Flow**
- `r2_xrefs`  --  cross-references to or from an address
- `r2_global_xrefs`  --  paginated global xref inventory
- `r2_trace_data_flow`  --  BFS over xrefs (forward/backward) with configurable depth
- `r2_var_xrefs`  --  function variable read/write xrefs

**ESIL Analysis**
- `r2_esil_accesses`  --  register and memory access summaries (instructions, bytes, block, or function scope)

**Advanced Analysis**
- `r2_security`  --  checksec-style hardening fields and per-section entropy
- `r2_value_trace`  --  trace a seeded register value through a disassembly window
- `r2_path_digest`  --  macro path digest over a function or raw address range
- `r2_artifact_summary`  --  decode branch artifacts (strings, callsites, unsupported branches)
- `r2_field_xrefs`  --  map raw memory field references with symbolic tracking
- `r2_jump_table_slices`  --  summarize computed jump-table targets
- `r2_windows_driver_dispatch`  --  recover DRIVER_OBJECT dispatch and notify callback anchors

**Power-User**
- `r2_cmd`  --  run a single radare2 query command with guarded output

## Requirements

- **radare2 5.9+** on PATH
- **Rust stable** toolchain
- Optional for `r2_decompile mode=code`: `r2ghidra` (`r2pm -ci r2ghidra`) or `r2dec` (`r2pm -ci r2dec`). Without a decompiler plugin, use `mode=meta` for compact `pdgj` metadata.

## Quick Start

```bash
cargo build --workspace
cargo test --workspace

# Run the MCP server
RBM_CACHE_DIR=./cache cargo run -p rbm-server
```

The server speaks the MCP protocol over stdio. Configure your MCP client to use it as a stdio subprocess:

```json
{
  "mcpServers": {
    "rbinr2": {
      "command": "/path/to/rbinr2",
      "args": [],
      "env": {
        "RBM_CACHE_DIR": "/path/to/cache"
      }
    }
  }
}
```

## Configuration

| Variable | Default | Description |
| --- | --- | --- |
| `RBM_CACHE_DIR` | `./rbinr2-cache` | Cache root (relative CWD) |
| `RBM_R2_OPEN_TIMEOUT` | 120 | r2 session open timeout (seconds) |

## Architecture

```
MCP Client
  -> stdio JSON-RPC
  -> rbinr2 server
  -> persistent r2pipe session per binary
  -> r2 commands with JSON projection
```

Binaries are opened once and cached in a per-binary r2pipe session. Subsequent
queries reuse the open session, enabling sub-second response times for most
operations after initial analysis.

## Project Structure

```
crates/
  rbm-core/      Cache paths, config, environment, error types
  rbm-r2/        r2pipe session management and r2 command wrappers
  rbm-server/    MCP server binary (rbinr2)
```

## License

MIT  -  see [LICENSE](LICENSE).
