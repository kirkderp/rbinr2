#![allow(
    clippy::unused_self,
    clippy::missing_errors_doc,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::needless_pass_by_value,
    clippy::if_not_else,
    clippy::map_unwrap_or,
    clippy::option_if_let_else
)]

// Manual MCP server for radare2-based binary analysis.
use std::sync::Arc;

use rbm_core::{OutputGuard, ServerConfig, ToolError};
use rbm_r2::SessionManager;
use rmcp::handler::server::ServerHandler;
use rmcp::model::{
    CallToolRequestParams, CallToolResult, Content, ErrorData, Implementation, ListToolsResult,
    PaginatedRequestParams, ServerCapabilities, ServerInfo, Tool,
};
use rmcp::service::{RequestContext, RoleServer};
use serde_json::{Value, json};

use crate::support::{
    apply_name_filter, build_address_mapping, build_extract_bytes_result, guard_r2_cmd_output,
};

#[derive(Clone)]
pub struct RbmServer {
    config: Arc<ServerConfig>,
    r2: Arc<SessionManager>,
    output_guard: Arc<OutputGuard>,
    tools: Vec<Tool>,
}

impl RbmServer {
    #[must_use]
    pub fn new(config: ServerConfig) -> Self {
        let output_guard = Arc::new(OutputGuard::new(config.cache.overflow_dir()));
        let r2_open_timeout = config.r2_open_timeout;
        Self {
            config: Arc::new(config),
            r2: Arc::new(SessionManager::with_open_timeout(r2_open_timeout)),
            output_guard,
            tools: Self::build_tools(),
        }
    }

    #[must_use]
    pub fn config(&self) -> &ServerConfig {
        &self.config
    }

    #[must_use]
    pub fn r2_sessions_manager(&self) -> &SessionManager {
        &self.r2
    }

    /// Serve the MCP server over stdio. Runs until stdin closes.
    pub async fn serve_stdio(self) -> Result<(), String> {
        use rmcp::service::serve_server;
        use rmcp::transport::stdio;
        let service = serve_server(self, stdio())
            .await
            .map_err(|e| format!("{e:?}"))?;
        service.waiting().await.map_err(|e| format!("{e:?}"))?;
        Ok(())
    }

    fn build_tools() -> Vec<Tool> {
        fn t(name: &'static str, desc: &'static str, schema: serde_json::Value) -> Tool {
            let json_obj = match schema {
                serde_json::Value::Object(map) => map,
                _ => rmcp::model::JsonObject::new(),
            };
            Tool::new(name, desc, std::sync::Arc::new(json_obj))
        }
        fn req(name: &str) -> serde_json::Value {
            serde_json::json!({"type": "string", "description": name})
        }
        fn opt_s(desc: &str) -> serde_json::Value {
            serde_json::json!({"type": "string", "description": desc})
        }
        fn enum_s(desc: &str, values: &[&str]) -> serde_json::Value {
            serde_json::json!({"type": "string", "description": desc, "enum": values})
        }
        #[allow(dead_code)]
        fn opt_u32(desc: &str, def: u32) -> serde_json::Value {
            serde_json::json!({"type": "integer", "description": desc, "default": def})
        }
        fn schema(props: Vec<(&str, serde_json::Value)>, required: Vec<&str>) -> serde_json::Value {
            let mut p = serde_json::Map::new();
            for (k, v) in props {
                p.insert(k.to_string(), v);
            }
            serde_json::json!({
                "type": "object",
                "properties": p,
                "required": required,
                "additionalProperties": false
            })
        }

        vec![
            t(
                "r2_open",
                "Open a binary with radare2 and start a persistent r2pipe session.",
                schema(
                    vec![("binary_path", req("absolute path to the binary"))],
                    vec!["binary_path"],
                ),
            ),
            t(
                "r2_close",
                "Close a radare2 session for a binary.",
                schema(
                    vec![("binary_path", req("binary path"))],
                    vec!["binary_path"],
                ),
            ),
            t(
                "r2_sessions",
                "List all open r2 sessions.",
                schema(vec![], vec![]),
            ),
            t(
                "r2_metadata",
                "Mode-driven r2 metadata view. mode can be info, headers, version_info, entry_points, sections, relocations, resources, libraries, imports, exports, symbols, strings, or functions. Supports filter for imports/exports/symbols/strings/functions and pagination for array modes.",
                schema(
                    vec![
                        ("binary_path", req("absolute path to the binary")),
                        (
                            "mode",
                            enum_s(
                                "metadata mode",
                                &[
                                    "info",
                                    "headers",
                                    "version_info",
                                    "entry_points",
                                    "sections",
                                    "relocations",
                                    "resources",
                                    "libraries",
                                    "imports",
                                    "exports",
                                    "symbols",
                                    "strings",
                                    "functions",
                                ],
                            ),
                        ),
                        ("filter", opt_s("optional regex filter")),
                        (
                            "min_length",
                            json!({"type": "integer", "description": "minimum string length for mode=strings", "default": 5}),
                        ),
                        ("all_sections", json!({"type": "boolean", "default": true})),
                        ("offset", json!({"type": "integer", "default": 0})),
                        ("limit", json!({"type": "integer", "default": 0})),
                    ],
                    vec!["binary_path"],
                ),
            ),
            t(
                "r2_classes",
                "List classes or inspect one class. Without classname, returns class list with optional regex filter. With classname, format=json (default) returns sorted methods/fields; format=text returns raw ic output.",
                schema(
                    vec![
                        ("binary_path", req("absolute path to the binary")),
                        ("classname", opt_s("specific class to inspect")),
                        ("filter", opt_s("regex filter for class names")),
                        ("format", enum_s("output format", &["json", "text"])),
                    ],
                    vec!["binary_path"],
                ),
            ),
            t(
                "r2_vtables",
                "Return bounded r2 native vtable discovery from avj with offset/limit pagination. Default limit 50; max 500.",
                schema(
                    vec![
                        ("binary_path", req("absolute path to the binary")),
                        ("offset", json!({"type": "integer", "default": 0})),
                        ("limit", json!({"type": "integer", "default": 50})),
                    ],
                    vec!["binary_path"],
                ),
            ),
            t(
                "r2_types",
                "Read r2 type-system data. mode can be list, functions, structs, enums, unions, typedefs, c, view, format, or cast. Use type_name for type-specific views and addr for cast.",
                schema(
                    vec![
                        ("binary_path", req("absolute path to the binary")),
                        (
                            "mode",
                            enum_s(
                                "type-system mode",
                                &[
                                    "list",
                                    "functions",
                                    "structs",
                                    "enums",
                                    "unions",
                                    "typedefs",
                                    "c",
                                    "view",
                                    "format",
                                    "cast",
                                    "type_xrefs",
                                    "function_type_xrefs",
                                    "type_links",
                                    "calling_conventions",
                                ],
                            ),
                        ),
                        ("type_name", opt_s("type name for c/view/format/cast modes")),
                        ("addr", opt_s("address, symbol, or r2 flag for cast mode")),
                        ("filter", opt_s("optional regex filter for JSON list modes")),
                        ("offset", json!({"type": "integer", "default": 0})),
                        ("limit", json!({"type": "integer", "default": 50})),
                    ],
                    vec!["binary_path"],
                ),
            ),
            t(
                "r2_imports_grouped",
                "Group imports by semantic usage category with calling functions via iicj. Returns sorted groups and per-import caller lists.",
                schema(
                    vec![("binary_path", req("absolute path to the binary"))],
                    vec!["binary_path"],
                ),
            ),
            t(
                "r2_plugins",
                "List r2 capabilities/plugins. mode can be asm, analysis, bin, hash, or decompile.",
                schema(
                    vec![
                        ("binary_path", req("absolute path to the binary")),
                        (
                            "mode",
                            enum_s(
                                "plugin mode",
                                &["asm", "analysis", "bin", "hash", "decompile"],
                            ),
                        ),
                    ],
                    vec!["binary_path"],
                ),
            ),
            t(
                "r2_get_bytes",
                "Read raw bytes at an address as a raw hex string. count defaults to 64. Use r2_extract_bytes when you need SHA256, ASCII/hex previews, or optional write-out.",
                schema(
                    vec![
                        ("binary_path", req("absolute path to the binary")),
                        ("addr", req("address, symbol, or r2 flag")),
                        (
                            "count",
                            json!({"type": "integer", "description": "number of bytes to read", "default": 64}),
                        ),
                    ],
                    vec!["binary_path", "addr"],
                ),
            ),
            t(
                "r2_extract_bytes",
                "Extract a bounded byte range from an address without requiring function recognition. Returns byte_count, sha256, preview_len, hex/ascii head previews, hex tail preview, r2 lookup metadata, section/file-offset mapping, and optional write metadata.",
                schema(
                    vec![
                        ("binary_path", req("absolute path to the binary")),
                        ("addr", req("address, symbol, or r2 flag")),
                        (
                            "count",
                            json!({"type": "integer", "description": "number of bytes to extract", "default": 64}),
                        ),
                        ("out_path", opt_s("optional output path to write bytes")),
                        ("overwrite", json!({"type": "boolean", "default": true})),
                    ],
                    vec!["binary_path", "addr"],
                ),
            ),
            t(
                "r2_lookup_address",
                "Describe what is at an address: resolves to flag name, symbol, module, and any enclosing function.",
                schema(
                    vec![
                        ("binary_path", req("absolute path to the binary")),
                        ("addr", req("address, symbol, or r2 flag")),
                    ],
                    vec!["binary_path", "addr"],
                ),
            ),
            t(
                "r2_flags",
                "Read r2 flags, demangled/real flag names, or flagspaces. Supports regex filter and pagination for flag rows.",
                schema(
                    vec![
                        ("binary_path", req("absolute path to the binary")),
                        (
                            "mode",
                            enum_s("flags mode", &["flags", "realnames", "flagspaces"]),
                        ),
                        ("filter", opt_s("optional regex filter")),
                        ("offset", json!({"type": "integer", "default": 0})),
                        ("limit", json!({"type": "integer", "default": 50})),
                    ],
                    vec!["binary_path"],
                ),
            ),
            t(
                "r2_address_info",
                "Return r2 address classification metadata from aij: whether an address is executable, readable, flagged, and inside an analyzed function.",
                schema(
                    vec![
                        ("binary_path", req("absolute path to the binary")),
                        ("addr", req("address, symbol, or r2 flag")),
                    ],
                    vec!["binary_path", "addr"],
                ),
            ),
            t(
                "r2_calculate",
                "Evaluate a math expression with radare2 (?v). Supports symbols, flags, and 64-bit math; returns hex/decimal/binary.",
                schema(
                    vec![
                        ("binary_path", req("absolute path to the binary")),
                        ("expression", req("math expression")),
                    ],
                    vec!["binary_path", "expression"],
                ),
            ),
            t(
                "r2_opcodes",
                "Return structured r2 opcode-analysis rows from aoj for a bounded instruction window. Includes mnemonic, pseudo, operands, ESIL, stack effects, refs, and per-op metadata when r2 provides them.",
                schema(
                    vec![
                        ("binary_path", req("absolute path to the binary")),
                        ("addr", req("address, symbol, or r2 flag")),
                        (
                            "count",
                            json!({"type": "integer", "description": "number of opcodes to inspect, clamped to 1..500", "default": 8}),
                        ),
                    ],
                    vec!["binary_path", "addr"],
                ),
            ),
            t(
                "r2_disassemble",
                "Disassemble a bounded instruction window from any address, symbol, or r2 flag; no function recognition is required unless function=true. format=json (default) returns structured pdj/pdfj rows; format=text returns raw pd/pdf text. Default count=32.",
                schema(
                    vec![
                        ("binary_path", req("absolute path to the binary")),
                        ("addr", req("address, symbol, or r2 flag")),
                        (
                            "count",
                            json!({"type": "integer", "description": "number of instructions", "default": 32}),
                        ),
                        ("function", json!({"type": "boolean", "default": false})),
                        ("format", enum_s("output format", &["json", "text"])),
                    ],
                    vec!["binary_path", "addr"],
                ),
            ),
            t(
                "r2_block_hash",
                "Compute a bounded radare2 ph hash or entropy value at an address. algorithm can be sha256, sha1, sha512, md5, crc32, or entropy.",
                schema(
                    vec![
                        ("binary_path", req("absolute path to the binary")),
                        ("addr", req("address, symbol, or r2 flag")),
                        (
                            "count",
                            json!({"type": "integer", "description": "number of bytes to hash, 1..16777216", "default": 64}),
                        ),
                        (
                            "algorithm",
                            enum_s(
                                "hash or entropy algorithm",
                                &["sha256", "sha1", "sha512", "md5", "crc32", "entropy"],
                            ),
                        ),
                    ],
                    vec!["binary_path", "addr"],
                ),
            ),
            t(
                "r2_pointer_scan",
                "Read pointer/reference-like words from a bounded memory range using pxrj. Useful for vtables, dispatch tables, and pointer-rich data.",
                schema(
                    vec![
                        ("binary_path", req("absolute path to the binary")),
                        ("addr", req("address, symbol, or r2 flag")),
                        (
                            "count",
                            json!({"type": "integer", "description": "bytes to scan, 1..1048576", "default": 64}),
                        ),
                    ],
                    vec!["binary_path", "addr"],
                ),
            ),
            t(
                "r2_string_at",
                "Decode a string at an address using r2 string printers. mode can be auto, ascii, utf16, utf32, or pascal.",
                schema(
                    vec![
                        ("binary_path", req("absolute path to the binary")),
                        ("addr", req("address, symbol, or r2 flag")),
                        (
                            "mode",
                            enum_s(
                                "string decode mode",
                                &["auto", "ascii", "utf16", "utf32", "pascal"],
                            ),
                        ),
                    ],
                    vec!["binary_path", "addr"],
                ),
            ),
            t(
                "r2_find",
                "Unified search across functions/strings/imports/bytes. Functions accept glob (*, ?) or substring; strings/imports use substring; bytes use a hex pattern. Default limit 50.",
                schema(
                    vec![
                        ("binary_path", req("absolute path to the binary")),
                        (
                            "search_type",
                            enum_s(
                                "search domain",
                                &["functions", "strings", "imports", "bytes"],
                            ),
                        ),
                        ("pattern", req("search pattern")),
                        (
                            "limit",
                            json!({"type": "integer", "description": "maximum results", "default": 50}),
                        ),
                    ],
                    vec!["binary_path", "search_type", "pattern"],
                ),
            ),
            t(
                "r2_semantic_search",
                "Run bounded read-only r2 semantic searches. mode can be opcode_type, disasm, wide_string, value, refs, rop, or hex.",
                schema(
                    vec![
                        ("binary_path", req("absolute path to the binary")),
                        (
                            "mode",
                            enum_s(
                                "semantic search mode",
                                &[
                                    "opcode_type",
                                    "disasm",
                                    "wide_string",
                                    "value",
                                    "refs",
                                    "rop",
                                    "hex",
                                ],
                            ),
                        ),
                        (
                            "pattern",
                            req("search pattern or address, depending on mode"),
                        ),
                        (
                            "limit",
                            json!({"type": "integer", "description": "maximum results", "default": 50}),
                        ),
                    ],
                    vec!["binary_path", "pattern"],
                ),
            ),
            t(
                "r2_find_xrefs",
                "Search strings, imports, functions, or bytes, then resolve xrefs to each hit in one bounded r2 pass.",
                schema(
                    vec![
                        ("binary_path", req("absolute path to the binary")),
                        (
                            "search_type",
                            enum_s(
                                "search domain",
                                &["strings", "imports", "functions", "bytes"],
                            ),
                        ),
                        ("pattern", req("search pattern")),
                        (
                            "limit",
                            json!({"type": "integer", "description": "maximum search hits", "default": 20}),
                        ),
                        (
                            "max_xrefs_per_hit",
                            json!({"type": "integer", "description": "maximum xrefs per hit", "default": 12}),
                        ),
                    ],
                    vec!["binary_path", "search_type", "pattern"],
                ),
            ),
            t(
                "r2_decompile",
                "Decompile a function. mode=code (default) requires an installed r2 decompiler plugin such as r2ghidra (pdg) or r2dec (pdd); mode=meta returns compact pdgj metadata.",
                schema(
                    vec![
                        ("binary_path", req("absolute path to the binary")),
                        ("addr", req("address, symbol, or r2 flag")),
                        ("mode", enum_s("decompile mode", &["code", "meta"])),
                    ],
                    vec!["binary_path", "addr"],
                ),
            ),
            t(
                "r2_function_view",
                "Mode-driven r2 function view. mode can be analyze, info, signature, vars, profile, strings, constants, callees, refs, or cfg. Default analyze returns compact function triage.",
                schema(
                    vec![
                        ("binary_path", req("absolute path to the binary")),
                        ("addr", req("address, symbol, or r2 flag")),
                        (
                            "mode",
                            enum_s(
                                "function view mode",
                                &[
                                    "analyze",
                                    "info",
                                    "signature",
                                    "vars",
                                    "profile",
                                    "strings",
                                    "constants",
                                    "callees",
                                    "refs",
                                    "cfg",
                                ],
                            ),
                        ),
                        ("include_asm", json!({"type": "boolean", "default": false})),
                    ],
                    vec!["binary_path", "addr"],
                ),
            ),
            t(
                "r2_graph",
                "Export native radare2 analysis graphs from ag. kind can be function, callgraph, global_callgraph, imports, refs, global_refs, xrefs, data_refs, or global_data_refs. format can be json, text, dot, or mermaid.",
                schema(
                    vec![
                        ("binary_path", req("absolute path to the binary")),
                        (
                            "kind",
                            enum_s(
                                "r2 graph kind",
                                &[
                                    "function",
                                    "callgraph",
                                    "global_callgraph",
                                    "imports",
                                    "refs",
                                    "global_refs",
                                    "xrefs",
                                    "data_refs",
                                    "global_data_refs",
                                ],
                            ),
                        ),
                        (
                            "format",
                            enum_s("graph output format", &["json", "text", "dot", "mermaid"]),
                        ),
                        ("addr", opt_s("optional address, symbol, or r2 flag")),
                    ],
                    vec!["binary_path"],
                ),
            ),
            t(
                "r2_security",
                "Return r2-native binary security and entropy views. mode=checksec projects iIj hardening fields; mode=entropy computes per-section entropy with ph entropy.",
                schema(
                    vec![
                        ("binary_path", req("absolute path to the binary")),
                        ("mode", enum_s("security mode", &["checksec", "entropy"])),
                    ],
                    vec!["binary_path"],
                ),
            ),
            t(
                "r2_xrefs",
                "Get cross-references to or from an address. direction='to' (who reaches addr) or 'from' (what addr reaches). Returns compact projected shape with addresses, opcode, function, and ref names. Default 'to'.",
                schema(
                    vec![
                        ("binary_path", req("absolute path to the binary")),
                        ("addr", req("address, symbol, or r2 flag")),
                        ("direction", enum_s("xref direction", &["to", "from"])),
                    ],
                    vec!["binary_path", "addr"],
                ),
            ),
            t(
                "r2_global_xrefs",
                "Return a paginated global xref inventory from axlj.",
                schema(
                    vec![
                        ("binary_path", req("absolute path to the binary")),
                        ("offset", json!({"type": "integer", "default": 0})),
                        ("limit", json!({"type": "integer", "default": 50})),
                    ],
                    vec!["binary_path"],
                ),
            ),
            t(
                "r2_esil_accesses",
                "Summarize ESIL-derived register and memory accesses for an address range, basic block, or function. mode can be instructions, bytes, block, or function.",
                schema(
                    vec![
                        ("binary_path", req("absolute path to the binary")),
                        ("addr", req("address, symbol, or r2 flag")),
                        (
                            "mode",
                            enum_s(
                                "ESIL access mode",
                                &["instructions", "bytes", "block", "function"],
                            ),
                        ),
                        (
                            "count",
                            json!({"type": "integer", "description": "instruction or byte count", "default": 32}),
                        ),
                    ],
                    vec!["binary_path", "addr"],
                ),
            ),
            t(
                "r2_var_xrefs",
                "List r2 function variable read/write xrefs via afvxj. Returns variables with read/write site counts and normalized hex addresses.",
                schema(
                    vec![
                        ("binary_path", req("absolute path to the binary")),
                        ("addr", req("address, symbol, or r2 flag")),
                    ],
                    vec!["binary_path", "addr"],
                ),
            ),
            t(
                "r2_cmd",
                "Run a single radare2 query command and return guarded output. Prefer named rbinr2 tools when available.",
                schema(
                    vec![
                        ("binary_path", req("absolute path to the binary")),
                        ("command", req("raw r2 command")),
                    ],
                    vec!["binary_path", "command"],
                ),
            ),
            t(
                "r2_trace_data_flow",
                "BFS over xrefs (axfj/axtj) from or to an address. 'backward' answers 'who reaches this string/global/import?'; 'forward' answers 'where does data flow next?'. max_depth clamped to 1-15.",
                schema(
                    vec![
                        ("binary_path", req("absolute path to the binary")),
                        ("addr", req("address, symbol, or r2 flag")),
                        ("direction", opt_s("trace direction: forward or backward")),
                        (
                            "max_depth",
                            json!({"type": "integer", "description": "maximum traversal depth", "default": 5}),
                        ),
                    ],
                    vec!["binary_path", "addr"],
                ),
            ),
            t(
                "r2_value_trace",
                "Trace a seeded register value through a bounded radare2 disassembly window. Tracks register aliases, stack slots, memory saves/restores, mutations, and calls/jumps reached by the seed.",
                schema(
                    vec![
                        ("binary_path", req("absolute path to the binary")),
                        ("start_addr", req("start address to scan")),
                        ("seed_register", req("register carrying the value")),
                        ("seed_memory", opt_s("optional memory/stack slot")),
                        ("seed_value", opt_s("optional concrete value")),
                        ("arch", opt_s("r2 architecture override")),
                        ("bits", json!({"type": "integer", "default": 0})),
                        (
                            "max_instructions",
                            json!({"type": "integer", "default": 300}),
                        ),
                        ("max_events", json!({"type": "integer", "default": 100})),
                    ],
                    vec!["binary_path", "start_addr", "seed_register"],
                ),
            ),
            t(
                "r2_windows_driver_dispatch",
                "Recover Windows DRIVER_OBJECT dispatch and notify callback anchors from a driver init routine.",
                schema(
                    vec![
                        ("binary_path", req("absolute path to the binary")),
                        ("init_addr", req("driver initialization address")),
                        ("driver_register", opt_s("register carrying DRIVER_OBJECT*")),
                        (
                            "max_instructions",
                            json!({"type": "integer", "default": 220}),
                        ),
                    ],
                    vec!["binary_path", "init_addr"],
                ),
            ),
            t(
                "r2_jump_table_slices",
                "Summarize computed jump-table targets in one cheap radare2-backed pass.",
                schema(
                    vec![
                        ("binary_path", req("absolute path to the binary")),
                        ("table_addr", req("address of the pointer table")),
                        (
                            "entry_count",
                            json!({"type": "integer", "description": "number of pointer entries"}),
                        ),
                        ("pointer_size", json!({"type": "integer", "default": 4})),
                        ("target_bytes", json!({"type": "integer", "default": 512})),
                        (
                            "max_instructions",
                            json!({"type": "integer", "default": 120}),
                        ),
                    ],
                    vec!["binary_path", "table_addr", "entry_count"],
                ),
            ),
            t(
                "r2_path_digest",
                "Return a cheap radare2-backed macro path digest over a function or raw address range.",
                schema(
                    vec![
                        ("binary_path", req("absolute path to the binary")),
                        ("start_addr", req("start address to scan")),
                        ("arch", opt_s("r2 architecture override")),
                        ("bits", json!({"type": "integer", "default": 0})),
                        ("range_end", opt_s("exclusive end address")),
                        ("stop_addresses", opt_s("stop addresses")),
                        ("state_register", opt_s("state/base register")),
                        ("marker_constants", opt_s("marker constants")),
                        (
                            "max_instructions",
                            json!({"type": "integer", "default": 800}),
                        ),
                        ("max_events", json!({"type": "integer", "default": 80})),
                    ],
                    vec!["binary_path", "start_addr"],
                ),
            ),
            t(
                "r2_artifact_summary",
                "Summarize decoded branch artifacts in one cheap radare2 pass. Emulates x86 stack/local immediate buffers and bytewise decode loops.",
                schema(
                    vec![
                        ("binary_path", req("absolute path to the binary")),
                        ("start_addr", req("start address to scan")),
                        ("arch", opt_s("r2 architecture override")),
                        ("bits", json!({"type": "integer", "default": 0})),
                        ("range_end", opt_s("exclusive end address")),
                        (
                            "max_instructions",
                            json!({"type": "integer", "default": 1200}),
                        ),
                        ("max_steps", json!({"type": "integer", "default": 20000})),
                        ("min_string_len", json!({"type": "integer", "default": 4})),
                    ],
                    vec!["binary_path", "start_addr"],
                ),
            ),
            t(
                "r2_field_xrefs",
                "Map raw memory field references from a radare2 pdj range in one cheap pass.",
                schema(
                    vec![
                        ("binary_path", req("absolute path to the binary")),
                        ("start_addr", req("start address to scan")),
                        ("arch", opt_s("r2 architecture override")),
                        ("bits", json!({"type": "integer", "default": 0})),
                        ("range_end", opt_s("exclusive end address")),
                        ("root_register", opt_s("root register")),
                        ("root_name", opt_s("root register symbol name")),
                        ("arg_names", opt_s("stack argument offset=name pairs")),
                        ("resolver_function", opt_s("resolver call target")),
                        ("marker_constants", opt_s("marker constants")),
                        ("ignore_stack", json!({"type": "boolean", "default": false})),
                        (
                            "max_instructions",
                            json!({"type": "integer", "default": 800}),
                        ),
                        ("max_rows", json!({"type": "integer", "default": 60})),
                    ],
                    vec!["binary_path", "start_addr"],
                ),
            ),
        ]
    }

    fn s(&self, v: &serde_json::Map<String, serde_json::Value>, key: &str) -> String {
        v.get(key)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    }

    fn opt_s<'a>(
        &self,
        v: &'a serde_json::Map<String, serde_json::Value>,
        key: &str,
    ) -> Option<&'a str> {
        v.get(key).and_then(|s| {
            let s = s.as_str()?;
            if s.is_empty() { None } else { Some(s) }
        })
    }

    fn opt_u64(&self, v: &serde_json::Map<String, serde_json::Value>, key: &str) -> Option<u64> {
        v.get(key).and_then(serde_json::Value::as_u64)
    }

    fn opt_u32(&self, v: &serde_json::Map<String, serde_json::Value>, key: &str) -> Option<u32> {
        v.get(key)
            .and_then(serde_json::Value::as_u64)
            .map(|x| x as u32)
    }

    fn opt_bool(&self, v: &serde_json::Map<String, serde_json::Value>, key: &str) -> Option<bool> {
        v.get(key).and_then(serde_json::Value::as_bool)
    }

    fn opt_usize(
        &self,
        v: &serde_json::Map<String, serde_json::Value>,
        key: &str,
    ) -> Option<usize> {
        v.get(key)
            .and_then(serde_json::Value::as_u64)
            .map(|x| x as usize)
    }

    fn ok_json(&self, value: impl serde::Serialize) -> Result<CallToolResult, ErrorData> {
        let text = serde_json::to_string(&value).map_err(|e| err(e.to_string()))?;
        Ok(CallToolResult::success(vec![Content::text(text)]))
    }

    async fn session_for(&self, binary_path: &str) -> Result<Arc<rbm_r2::Session>, ErrorData> {
        self.r2
            .get_or_open(binary_path)
            .await
            .map_err(|e| err(e.to_string()))
    }

    async fn with_session_json<T, F, Fut>(
        &self,
        binary_path: &str,
        f: F,
    ) -> Result<String, ErrorData>
    where
        T: serde::Serialize,
        F: FnOnce(Arc<rbm_r2::Session>) -> Fut,
        Fut: std::future::Future<Output = Result<T, ToolError>>,
    {
        let session = self.session_for(binary_path).await?;
        let value = f(session).await.map_err(|e| err(e.to_string()))?;
        serde_json::to_string(&value).map_err(|e| err(e.to_string()))
    }

    async fn with_session_raw<F, Fut>(&self, binary_path: &str, f: F) -> Result<String, ErrorData>
    where
        F: FnOnce(Arc<rbm_r2::Session>) -> Fut,
        Fut: std::future::Future<Output = Result<String, ToolError>>,
    {
        let session = self.session_for(binary_path).await?;
        f(session).await.map_err(|e| err(e.to_string()))
    }
}

fn err(msg: impl Into<String>) -> ErrorData {
    ErrorData::new(rmcp::model::ErrorCode::INTERNAL_ERROR, msg.into(), None)
}

impl ServerHandler for RbmServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("rbinr2", env!("CARGO_PKG_VERSION")))
            .with_instructions(format!(
                "rbinr2 radare2 MCP server. {} tools available.",
                self.tools.len()
            ))
    }

    async fn list_tools(
        &self,
        _: Option<PaginatedRequestParams>,
        _: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        Ok(ListToolsResult {
            tools: self.tools.clone(),
            meta: None,
            next_cursor: None,
        })
    }

    #[allow(clippy::too_many_lines)]
    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let name = request.name.as_ref();
        let params = request.arguments.unwrap_or_default();

        match name {
            "r2_open" => {
                let outcome = self
                    .r2
                    .open(&self.s(&params, "binary_path"))
                    .await
                    .map_err(|e| err(e.to_string()))?;
                self.ok_json(outcome)
            }

            "r2_close" => {
                let outcome = self
                    .r2
                    .close(self.s(&params, "binary_path"))
                    .map_err(|e| err(e.to_string()))?;
                self.ok_json(outcome)
            }

            "r2_sessions" => {
                let paths = self.r2.list();
                self.ok_json(paths)
            }

            "r2_metadata" => {
                let binary_path = self.s(&params, "binary_path");
                let mode = self.s(&params, "mode");
                let mode = normalize_r2_metadata_mode(&mode)?;
                let session = self.session_for(&binary_path).await?;

                let mut result = match mode {
                    "info" => rbm_r2::meta::info(&session)
                        .await
                        .map_err(|e| err(e.to_string()))?,
                    "headers" => serde_json::json!(
                        rbm_r2::meta::rich_header(&session)
                            .await
                            .map_err(|e| err(e.to_string()))?
                    ),
                    "version_info" => serde_json::json!(
                        rbm_r2::meta::version_info(&session)
                            .await
                            .map_err(|e| err(e.to_string()))?
                    ),
                    "entry_points" => rbm_r2::meta::entry_points(&session)
                        .await
                        .map_err(|e| err(e.to_string()))?,
                    "sections" => rbm_r2::format::sections(&session)
                        .await
                        .map_err(|e| err(e.to_string()))?,
                    "relocations" => rbm_r2::format::relocations(&session)
                        .await
                        .map_err(|e| err(e.to_string()))?,
                    "resources" => rbm_r2::format::resources(&session)
                        .await
                        .map_err(|e| err(e.to_string()))?,
                    "libraries" => serde_json::json!(
                        rbm_r2::format::libraries(&session)
                            .await
                            .map_err(|e| err(e.to_string()))?
                    ),
                    "imports" => {
                        let value = rbm_r2::symbols::imports(&session)
                            .await
                            .map_err(|e| err(e.to_string()))?;
                        apply_name_filter(value, self.opt_s(&params, "filter"))?
                    }
                    "exports" => {
                        let value = rbm_r2::symbols::exports(&session)
                            .await
                            .map_err(|e| err(e.to_string()))?;
                        apply_name_filter(value, self.opt_s(&params, "filter"))?
                    }
                    "symbols" => {
                        let value = rbm_r2::symbols::symbols(&session)
                            .await
                            .map_err(|e| err(e.to_string()))?;
                        apply_name_filter(value, self.opt_s(&params, "filter"))?
                    }
                    "strings" => {
                        let min_length = self.opt_usize(&params, "min_length").unwrap_or(5);
                        let all_sections = self.opt_bool(&params, "all_sections").unwrap_or(true);
                        let value = if all_sections {
                            rbm_r2::symbols::strings_all(&session, min_length).await
                        } else {
                            rbm_r2::symbols::strings(&session, min_length).await
                        }
                        .map_err(|e| err(e.to_string()))?;
                        if let Some(pattern) =
                            self.opt_s(&params, "filter").filter(|s| !s.is_empty())
                        {
                            rbm_r2::symbols::filter_by_string_content(value, pattern)
                                .map_err(|e| err(e.to_string()))?
                        } else {
                            value
                        }
                    }
                    "functions" => {
                        let value = rbm_r2::disasm::functions(&session)
                            .await
                            .map_err(|e| err(e.to_string()))?;
                        apply_name_filter(value, self.opt_s(&params, "filter"))?
                    }
                    _ => unreachable!("mode is normalized before dispatch"),
                };

                if matches!(
                    mode,
                    "entry_points"
                        | "sections"
                        | "relocations"
                        | "resources"
                        | "libraries"
                        | "imports"
                        | "exports"
                        | "symbols"
                        | "strings"
                        | "functions"
                ) {
                    let offset = self.opt_usize(&params, "offset").unwrap_or(0);
                    let limit = self.opt_usize(&params, "limit").unwrap_or(0);
                    result = rbm_r2::filters::paginate(result, offset, limit);
                }

                self.ok_json(serde_json::json!({
                    "schema": "rbm.r2.metadata.v0",
                    "binary_path": binary_path,
                    "mode": mode,
                    "result": result,
                }))
            }

            "r2_classes" => {
                let binary_path = self.s(&params, "binary_path");
                let session = self.session_for(&binary_path).await?;
                let classname = self.opt_s(&params, "classname").filter(|s| !s.is_empty());

                let result = if let Some(name) = classname {
                    let format = self.s(&params, "format").trim().to_ascii_lowercase();
                    match format.as_str() {
                        "" | "json" | "structured" => {
                            let value = rbm_r2::format::class_methods_json(&session, name)
                                .await
                                .map_err(|e| err(e.to_string()))?;
                            serde_json::to_string(&value).map_err(|e| err(e.to_string()))?
                        }
                        "text" | "raw" => rbm_r2::format::class_methods(&session, name)
                            .await
                            .map_err(|e| err(e.to_string()))?,
                        other => {
                            return Err(err(format!(
                                "unknown r2_classes format {other:?}; expected json or text"
                            )));
                        }
                    }
                } else {
                    let mut value = rbm_r2::format::classes(&session)
                        .await
                        .map_err(|e| err(e.to_string()))?;
                    if let Some(pattern) = self.opt_s(&params, "filter").filter(|s| !s.is_empty()) {
                        value = rbm_r2::format::filter_classes(value, pattern)
                            .map_err(|e| err(e.to_string()))?;
                    }
                    serde_json::to_string(&value).map_err(|e| err(e.to_string()))?
                };

                Ok(CallToolResult::success(vec![Content::text(result)]))
            }

            "r2_vtables" => {
                let session = self.session_for(&self.s(&params, "binary_path")).await?;
                let offset = self.opt_usize(&params, "offset").unwrap_or(0);
                let limit = self.opt_usize(&params, "limit").unwrap_or(50);
                let result = rbm_r2::format::vtables(&session, offset, limit)
                    .await
                    .map_err(|e| err(e.to_string()))?;
                self.ok_json(result)
            }

            "r2_types" => {
                let session = self.session_for(&self.s(&params, "binary_path")).await?;
                let offset = self.opt_usize(&params, "offset").unwrap_or(0);
                let limit = self.opt_usize(&params, "limit").unwrap_or(50);
                let result = rbm_r2::types::types_view(
                    &session,
                    self.opt_s(&params, "mode").unwrap_or("list"),
                    self.opt_s(&params, "type_name"),
                    self.opt_s(&params, "addr"),
                    offset,
                    limit,
                    self.opt_s(&params, "filter"),
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                self.ok_json(result)
            }

            "r2_imports_grouped" => self
                .with_session_json(&self.s(&params, "binary_path"), |session| async move {
                    rbm_r2::symbols::imports_grouped(&session).await
                })
                .await
                .map(|s| CallToolResult::success(vec![Content::text(s)])),

            "r2_plugins" => {
                let session = self.session_for(&self.s(&params, "binary_path")).await?;
                let result = rbm_r2::navigation::plugins(
                    &session,
                    self.opt_s(&params, "mode").unwrap_or("asm"),
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                self.ok_json(result)
            }

            "r2_get_bytes" => self
                .with_session_raw(&self.s(&params, "binary_path"), |session| async move {
                    let count = self.opt_u64(&params, "count").unwrap_or(64);
                    rbm_r2::disasm::get_bytes(&session, &self.s(&params, "addr"), count).await
                })
                .await
                .map(|s| CallToolResult::success(vec![Content::text(s)])),

            "r2_extract_bytes" => {
                let binary_path = self.s(&params, "binary_path");
                let addr = self.s(&params, "addr");
                let count = self.opt_u64(&params, "count").unwrap_or(64);
                let out_path = self.opt_s(&params, "out_path").map(String::from);
                let overwrite = self.opt_bool(&params, "overwrite").unwrap_or(true);
                let result_binary_path = binary_path.clone();

                let session = self.session_for(&binary_path).await?;

                if count == 0 || count > 16 * 1024 * 1024 {
                    return Err(err(format!(
                        "count must be between 1 and {} bytes",
                        16 * 1024 * 1024
                    )));
                }

                let hex = rbm_r2::disasm::get_bytes(&session, &addr, count)
                    .await
                    .map_err(|e| err(e.to_string()))?;
                let lookup = rbm_r2::disasm::lookup_address(&session, &addr)
                    .await
                    .map_err(|e| err(e.to_string()))?;
                let addr_value = rbm_r2::disasm::calculate(&session, &addr)
                    .await
                    .ok()
                    .and_then(|v| v.get("decimal").and_then(|s| s.as_str().map(String::from)))
                    .and_then(|d| d.parse::<u64>().ok());
                let sections = rbm_r2::format::sections(&session)
                    .await
                    .unwrap_or_else(|_| serde_json::json!([]));
                let mapping = build_address_mapping(addr_value, &sections);

                let result = build_extract_bytes_result(&crate::support::ExtractBytesResultInput {
                    binary_path: &result_binary_path,
                    addr: &addr,
                    requested_count: count,
                    hex_text: &hex,
                    out_path: out_path.as_deref(),
                    overwrite,
                    lookup: &lookup,
                    mapping: &mapping,
                })
                .map_err(|e| err(e.to_string()))?;

                self.ok_json(result)
            }

            "r2_lookup_address" => self
                .with_session_json(&self.s(&params, "binary_path"), |session| async move {
                    rbm_r2::disasm::lookup_address(&session, &self.s(&params, "addr")).await
                })
                .await
                .map(|s| CallToolResult::success(vec![Content::text(s)])),

            "r2_flags" => {
                let session = self.session_for(&self.s(&params, "binary_path")).await?;
                let offset = self.opt_usize(&params, "offset").unwrap_or(0);
                let limit = self.opt_usize(&params, "limit").unwrap_or(50);
                let result = rbm_r2::navigation::flags(
                    &session,
                    self.opt_s(&params, "mode").unwrap_or("flags"),
                    offset,
                    limit,
                    self.opt_s(&params, "filter"),
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                self.ok_json(result)
            }

            "r2_address_info" => self
                .with_session_json(&self.s(&params, "binary_path"), |session| async move {
                    rbm_r2::disasm::address_info(&session, &self.s(&params, "addr")).await
                })
                .await
                .map(|s| CallToolResult::success(vec![Content::text(s)])),

            "r2_calculate" => self
                .with_session_json(&self.s(&params, "binary_path"), |session| async move {
                    rbm_r2::disasm::calculate(&session, &self.s(&params, "expression")).await
                })
                .await
                .map(|s| CallToolResult::success(vec![Content::text(s)])),

            "r2_opcodes" => self
                .with_session_json(&self.s(&params, "binary_path"), |session| async move {
                    let count = self.opt_u32(&params, "count").unwrap_or(8);
                    rbm_r2::disasm::opcodes(&session, &self.s(&params, "addr"), count).await
                })
                .await
                .map(|s| CallToolResult::success(vec![Content::text(s)])),

            "r2_disassemble" => {
                let binary_path = self.s(&params, "binary_path");
                let addr = self.s(&params, "addr");
                let count = self.opt_u64(&params, "count").unwrap_or(32);
                let function = self.opt_bool(&params, "function").unwrap_or(false);
                let format = self.s(&params, "format").trim().to_ascii_lowercase();

                match format.as_str() {
                    "" | "json" | "structured" => self
                        .with_session_json(&binary_path, |session| async move {
                            if function {
                                rbm_r2::disasm::disassemble_function_json(&session, &addr).await
                            } else {
                                rbm_r2::disasm::disassemble_json(&session, &addr, count).await
                            }
                        })
                        .await
                        .map(|s| CallToolResult::success(vec![Content::text(s)])),
                    "text" | "raw" => self
                        .with_session_raw(&binary_path, |session| async move {
                            if function {
                                rbm_r2::disasm::disassemble_function(&session, &addr).await
                            } else {
                                rbm_r2::disasm::disassemble(&session, &addr, count).await
                            }
                        })
                        .await
                        .map(|s| CallToolResult::success(vec![Content::text(s)])),
                    other => Err(err(format!(
                        "unknown r2_disassemble format {other:?}; expected json or text"
                    ))),
                }
            }

            "r2_block_hash" => self
                .with_session_json(&self.s(&params, "binary_path"), |session| async move {
                    let count = self.opt_u64(&params, "count").unwrap_or(64);
                    rbm_r2::disasm::block_hash(
                        &session,
                        &self.s(&params, "addr"),
                        count,
                        self.opt_s(&params, "algorithm").unwrap_or("sha256"),
                    )
                    .await
                })
                .await
                .map(|s| CallToolResult::success(vec![Content::text(s)])),

            "r2_pointer_scan" => self
                .with_session_json(&self.s(&params, "binary_path"), |session| async move {
                    let count = self.opt_u64(&params, "count").unwrap_or(64);
                    rbm_r2::navigation::pointer_scan(&session, &self.s(&params, "addr"), count)
                        .await
                })
                .await
                .map(|s| CallToolResult::success(vec![Content::text(s)])),

            "r2_string_at" => self
                .with_session_json(&self.s(&params, "binary_path"), |session| async move {
                    rbm_r2::navigation::string_at(
                        &session,
                        &self.s(&params, "addr"),
                        self.opt_s(&params, "mode").unwrap_or("auto"),
                    )
                    .await
                })
                .await
                .map(|s| CallToolResult::success(vec![Content::text(s)])),

            "r2_find" => self
                .with_session_json(&self.s(&params, "binary_path"), |session| async move {
                    let limit = self.opt_usize(&params, "limit").unwrap_or(50);
                    rbm_r2::search::find(
                        &session,
                        &self.s(&params, "search_type"),
                        &self.s(&params, "pattern"),
                        limit,
                    )
                    .await
                })
                .await
                .map(|s| CallToolResult::success(vec![Content::text(s)])),

            "r2_semantic_search" => self
                .with_session_json(&self.s(&params, "binary_path"), |session| async move {
                    let limit = self.opt_usize(&params, "limit").unwrap_or(50);
                    rbm_r2::navigation::semantic_search(
                        &session,
                        self.opt_s(&params, "mode").unwrap_or("opcode_type"),
                        &self.s(&params, "pattern"),
                        limit,
                    )
                    .await
                })
                .await
                .map(|s| CallToolResult::success(vec![Content::text(s)])),

            "r2_find_xrefs" => {
                // Inline a simple find_xrefs implementation since the original
                // used a service layer not available here
                let binary_path = self.s(&params, "binary_path");
                let search_type = self.s(&params, "search_type");
                let pattern = self.s(&params, "pattern");
                let limit = self.opt_usize(&params, "limit").unwrap_or(20).min(50);
                let max_xrefs = self
                    .opt_usize(&params, "max_xrefs_per_hit")
                    .unwrap_or(12)
                    .min(50);

                let session = self.session_for(&binary_path).await?;

                let search_results = rbm_r2::search::find(&session, &search_type, &pattern, limit)
                    .await
                    .map_err(|e| err(e.to_string()))?;

                let search_items = find_xref_search_items(&search_results);
                let mut hits = Vec::new();
                for item in search_items {
                    let addr_field = find_xref_item_addr(item);

                    let xrefs_val = if addr_field.is_empty() {
                        serde_json::json!([])
                    } else {
                        rbm_r2::disasm::xrefs(&session, &addr_field, rbm_r2::disasm::XrefDir::To)
                            .await
                            .ok()
                            .unwrap_or_else(|| serde_json::json!([]))
                    };

                    let xrefs_count = xrefs_val.as_array().map_or(0, std::vec::Vec::len);
                    let xrefs_trimmed = if let Some(arr) = xrefs_val.as_array() {
                        Value::Array(arr.iter().take(max_xrefs).cloned().collect())
                    } else {
                        xrefs_val
                    };

                    hits.push(serde_json::json!({
                        "hit": item,
                        "xref_count": xrefs_count,
                        "xref_count_is_exact": xrefs_count <= max_xrefs,
                        "xrefs": xrefs_trimmed,
                    }));
                }

                self.ok_json(serde_json::json!({
                    "schema": "rbm.r2.find_xrefs.v0",
                    "binary_path": binary_path,
                    "search_type": search_type,
                    "pattern": pattern,
                    "hit_count": hits.len(),
                    "hits": hits,
                }))
            }

            "r2_decompile" => {
                let binary_path = self.s(&params, "binary_path");
                let addr = self.s(&params, "addr");
                let mode = self.s(&params, "mode").trim().to_ascii_lowercase();

                match mode.as_str() {
                    "" | "code" | "pseudocode" | "body" => self
                        .with_session_raw(&binary_path, |session| async move {
                            rbm_r2::disasm::decompile(&session, &addr).await
                        })
                        .await
                        .map(|s| CallToolResult::success(vec![Content::text(s)])),
                    "meta" | "metadata" | "summary" => self
                        .with_session_json(&binary_path, |session| async move {
                            rbm_r2::disasm::decompile_meta(&session, &addr).await
                        })
                        .await
                        .map(|s| CallToolResult::success(vec![Content::text(s)])),
                    other => Err(err(format!(
                        "unknown r2_decompile mode {other:?}; expected code or meta"
                    ))),
                }
            }

            "r2_function_view" => {
                let binary_path = self.s(&params, "binary_path");
                let addr = self.s(&params, "addr");
                let mode = self.s(&params, "mode");
                let include_asm = self.opt_bool(&params, "include_asm").unwrap_or(false);
                let mode = normalize_r2_function_view_mode(&mode)?;

                let session = self.session_for(&binary_path).await?;
                let result = match mode {
                    "analyze" => rbm_r2::analyze::analyze_function(&session, &addr, include_asm)
                        .await
                        .map_err(|e| err(e.to_string()))?,
                    "info" => rbm_r2::disasm::function_info(&session, &addr)
                        .await
                        .map_err(|e| err(e.to_string()))?,
                    "signature" => rbm_r2::disasm::function_signature(&session, &addr)
                        .await
                        .map_err(|e| err(e.to_string()))?,
                    "vars" => rbm_r2::disasm::function_vars(&session, &addr)
                        .await
                        .map_err(|e| err(e.to_string()))?,
                    "profile" => serde_json::json!(
                        rbm_r2::func_profile::func_profile(&session, &addr)
                            .await
                            .map_err(|e| err(e.to_string()))?
                    ),
                    "strings" => serde_json::json!(
                        rbm_r2::func_profile::function_strings(&session, &addr)
                            .await
                            .map_err(|e| err(e.to_string()))?
                    ),
                    "constants" => serde_json::json!(
                        rbm_r2::func_profile::function_constants(&session, &addr)
                            .await
                            .map_err(|e| err(e.to_string()))?
                    ),
                    "callees" => rbm_r2::disasm::callees(&session, &addr)
                        .await
                        .map_err(|e| err(e.to_string()))?,
                    "refs" => rbm_r2::disasm::function_refs(&session, &addr)
                        .await
                        .map_err(|e| err(e.to_string()))?,
                    "cfg" => rbm_r2::disasm::function_cfg(&session, &addr)
                        .await
                        .map_err(|e| err(e.to_string()))?,
                    _ => unreachable!("mode is normalized before dispatch"),
                };

                self.ok_json(serde_json::json!({
                    "schema": "rbm.r2.function_view.v0",
                    "binary_path": binary_path,
                    "addr": addr,
                    "mode": mode,
                    "result": result,
                }))
            }

            "r2_graph" => {
                let session = self.session_for(&self.s(&params, "binary_path")).await?;
                let result = rbm_r2::disasm::graph(
                    &session,
                    self.opt_s(&params, "kind").unwrap_or("function"),
                    self.opt_s(&params, "format").unwrap_or("json"),
                    self.opt_s(&params, "addr"),
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                self.ok_json(result)
            }

            "r2_security" => {
                let session = self.session_for(&self.s(&params, "binary_path")).await?;
                let mode = self.s(&params, "mode");
                let mode = match mode.trim() {
                    "" | "checksec" | "hardening" => "checksec",
                    "entropy" | "sections_entropy" => "entropy",
                    other => {
                        return Err(err(format!(
                            "unknown r2_security mode {other:?}; expected checksec or entropy"
                        )));
                    }
                };
                let result = match mode {
                    "checksec" => rbm_r2::security::checksec(&session)
                        .await
                        .map_err(|e| err(e.to_string()))?,
                    "entropy" => rbm_r2::security::entropy(&session)
                        .await
                        .map_err(|e| err(e.to_string()))?,
                    _ => unreachable!("mode is normalized before dispatch"),
                };
                self.ok_json(serde_json::json!({
                    "schema": "rbm.r2.security.v0",
                    "mode": mode,
                    "result": result,
                }))
            }

            "r2_xrefs" => {
                let binary_path = self.s(&params, "binary_path");
                let addr = self.s(&params, "addr");
                let direction = self.opt_s(&params, "direction").unwrap_or("to");

                let session = self.session_for(&binary_path).await?;
                let dir =
                    rbm_r2::disasm::XrefDir::parse(direction).map_err(|e| err(e.to_string()))?;
                let result = rbm_r2::disasm::xrefs(&session, &addr, dir)
                    .await
                    .map_err(|e| err(e.to_string()))?;
                self.ok_json(result)
            }

            "r2_global_xrefs" => {
                let session = self.session_for(&self.s(&params, "binary_path")).await?;
                let offset = self.opt_usize(&params, "offset").unwrap_or(0);
                let limit = self.opt_usize(&params, "limit").unwrap_or(50);
                let result = rbm_r2::navigation::global_xrefs(&session, offset, limit)
                    .await
                    .map_err(|e| err(e.to_string()))?;
                self.ok_json(result)
            }

            "r2_esil_accesses" => {
                let session = self.session_for(&self.s(&params, "binary_path")).await?;
                let count = self.opt_u32(&params, "count").unwrap_or(32);
                let result = rbm_r2::disasm::esil_accesses(
                    &session,
                    &self.s(&params, "addr"),
                    self.opt_s(&params, "mode").unwrap_or("instructions"),
                    count,
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                self.ok_json(result)
            }

            "r2_var_xrefs" => {
                let session = self.session_for(&self.s(&params, "binary_path")).await?;
                let result = rbm_r2::disasm::variable_xrefs(&session, &self.s(&params, "addr"))
                    .await
                    .map_err(|e| err(e.to_string()))?;
                self.ok_json(result)
            }

            "r2_cmd" => {
                let session = self.session_for(&self.s(&params, "binary_path")).await?;
                let raw = rbm_r2::cmd::raw_cmd(&session, &self.s(&params, "command"))
                    .await
                    .map_err(|e| err(e.to_string()))?;
                let guarded =
                    guard_r2_cmd_output(&self.output_guard, raw).map_err(|e| err(e.to_string()))?;
                self.ok_json(guarded)
            }

            "r2_trace_data_flow" => {
                let session = self.session_for(&self.s(&params, "binary_path")).await?;
                let direction = self.opt_s(&params, "direction").unwrap_or("backward");
                let tra_dir = rbm_r2::trace::TraceDirection::parse(direction)
                    .map_err(|e| err(e.to_string()))?;
                let max_depth = self.opt_u64(&params, "max_depth").unwrap_or(5) as i64;
                let result = rbm_r2::trace::trace_data_flow(
                    &session,
                    &self.s(&params, "addr"),
                    tra_dir,
                    max_depth,
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                self.ok_json(result)
            }

            "r2_value_trace" => {
                let session = self.session_for(&self.s(&params, "binary_path")).await?;
                let result = rbm_r2::trace::trace_seed_value(
                    &session,
                    &self.s(&params, "start_addr"),
                    rbm_r2::trace::ValueTraceOptions {
                        arch: self.opt_s(&params, "arch"),
                        bits: self.opt_u32(&params, "bits").unwrap_or(0),
                        seed_register: &self.s(&params, "seed_register"),
                        seed_memory: self.opt_s(&params, "seed_memory"),
                        seed_value: self.opt_s(&params, "seed_value"),
                        max_instructions: self.opt_u32(&params, "max_instructions").unwrap_or(300),
                        max_events: self.opt_usize(&params, "max_events").unwrap_or(100),
                    },
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                self.ok_json(result)
            }

            "r2_windows_driver_dispatch" => {
                let session = self.session_for(&self.s(&params, "binary_path")).await?;
                let result = rbm_r2::windows_driver::windows_driver_dispatch(
                    &session,
                    rbm_r2::windows_driver::DriverDispatchOptions {
                        init_addr: &self.s(&params, "init_addr"),
                        driver_register: self.opt_s(&params, "driver_register").unwrap_or("rcx"),
                        max_instructions: self.opt_u64(&params, "max_instructions").unwrap_or(220),
                    },
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                self.ok_json(result)
            }

            "r2_jump_table_slices" => self
                .with_session_json(&self.s(&params, "binary_path"), |session| async move {
                    let entry_count = self
                        .opt_u32(&params, "entry_count")
                        .ok_or_else(|| ToolError::invalid("entry_count is required"))?;
                    let pointer_size = self.opt_u32(&params, "pointer_size").unwrap_or(4);
                    let target_bytes = self.opt_u64(&params, "target_bytes").unwrap_or(512);
                    let max_instructions = self.opt_u32(&params, "max_instructions").unwrap_or(120);
                    rbm_r2::jump_table::jump_table_slices(
                        &session,
                        &self.s(&params, "table_addr"),
                        entry_count,
                        pointer_size,
                        target_bytes,
                        max_instructions,
                    )
                    .await
                })
                .await
                .map(|s| CallToolResult::success(vec![Content::text(s)])),

            "r2_path_digest" => {
                let session = self.session_for(&self.s(&params, "binary_path")).await?;
                let result = rbm_r2::path_digest::path_digest(
                    &session,
                    &self.s(&params, "start_addr"),
                    rbm_r2::path_digest::PathDigestOptions {
                        arch: self.opt_s(&params, "arch"),
                        bits: self.opt_u32(&params, "bits").unwrap_or(0),
                        range_end: self.opt_s(&params, "range_end"),
                        stop_addresses: self.opt_s(&params, "stop_addresses"),
                        state_register: self.opt_s(&params, "state_register"),
                        marker_constants: self.opt_s(&params, "marker_constants"),
                        max_instructions: self.opt_u32(&params, "max_instructions").unwrap_or(800),
                        max_events: self.opt_usize(&params, "max_events").unwrap_or(80),
                    },
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                self.ok_json(result)
            }

            "r2_artifact_summary" => {
                let session = self.session_for(&self.s(&params, "binary_path")).await?;
                let result = rbm_r2::artifact_summary::artifact_summary(
                    &session,
                    &self.s(&params, "start_addr"),
                    rbm_r2::artifact_summary::ArtifactSummaryOptions {
                        arch: self.opt_s(&params, "arch"),
                        bits: self.opt_u32(&params, "bits").unwrap_or(0),
                        range_end: self.opt_s(&params, "range_end"),
                        max_instructions: self.opt_u32(&params, "max_instructions").unwrap_or(1200),
                        max_steps: self.opt_usize(&params, "max_steps").unwrap_or(20000),
                        min_string_len: self.opt_usize(&params, "min_string_len").unwrap_or(4),
                    },
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                self.ok_json(result)
            }

            "r2_field_xrefs" => {
                let session = self.session_for(&self.s(&params, "binary_path")).await?;
                let result = rbm_r2::field_xrefs::field_xrefs(
                    &session,
                    &self.s(&params, "start_addr"),
                    rbm_r2::field_xrefs::FieldXrefsOptions {
                        arch: self.opt_s(&params, "arch"),
                        bits: self.opt_u32(&params, "bits").unwrap_or(0),
                        range_end: self.opt_s(&params, "range_end"),
                        root_register: self.opt_s(&params, "root_register"),
                        root_name: self.opt_s(&params, "root_name"),
                        arg_names: self.opt_s(&params, "arg_names"),
                        resolver_function: self.opt_s(&params, "resolver_function"),
                        marker_constants: self.opt_s(&params, "marker_constants"),
                        ignore_stack: self.opt_bool(&params, "ignore_stack").unwrap_or(false),
                        max_instructions: self.opt_u32(&params, "max_instructions").unwrap_or(800),
                        max_rows: self.opt_usize(&params, "max_rows").unwrap_or(60),
                    },
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                self.ok_json(result)
            }

            _ => Err(ErrorData::new(
                rmcp::model::ErrorCode::INVALID_PARAMS,
                format!("unknown tool: {name}"),
                None,
            )),
        }
    }
}

pub(crate) fn normalize_r2_metadata_mode(mode: &str) -> Result<&'static str, ErrorData> {
    match mode.trim() {
        "" | "info" => Ok("info"),
        "headers" | "header" | "rich_header" => Ok("headers"),
        "version_info" | "version" | "versions" => Ok("version_info"),
        "entry_points" | "entrypoints" | "entry" | "entries" => Ok("entry_points"),
        "sections" | "section" => Ok("sections"),
        "relocations" | "relocation" | "relocs" => Ok("relocations"),
        "resources" | "resource" | "res" => Ok("resources"),
        "libraries" | "library" | "libs" => Ok("libraries"),
        "imports" | "import" => Ok("imports"),
        "exports" | "export" => Ok("exports"),
        "symbols" | "symbol" => Ok("symbols"),
        "strings" | "string" => Ok("strings"),
        "functions" | "function" | "afl" | "aflj" => Ok("functions"),
        other => Err(err(format!(
            "unknown r2_metadata mode {other:?}; expected info, headers, version_info, entry_points, sections, relocations, resources, libraries, imports, exports, symbols, strings, or functions"
        ))),
    }
}

pub(crate) fn normalize_r2_function_view_mode(mode: &str) -> Result<&'static str, ErrorData> {
    match mode.trim() {
        "" | "analyze" | "analysis" => Ok("analyze"),
        "info" | "metadata" => Ok("info"),
        "signature" | "sig" => Ok("signature"),
        "vars" | "variables" => Ok("vars"),
        "profile" | "stats" => Ok("profile"),
        "strings" | "string_refs" => Ok("strings"),
        "constants" | "consts" => Ok("constants"),
        "callees" | "calls" => Ok("callees"),
        "refs" | "references" | "xrefs" => Ok("refs"),
        "cfg" | "graph" | "blocks" => Ok("cfg"),
        other => Err(err(format!(
            "unknown r2_function_view mode {other:?}; expected analyze, info, signature, vars, profile, strings, constants, callees, refs, or cfg"
        ))),
    }
}

fn find_xref_search_items(search_results: &Value) -> &[Value] {
    search_results.as_array().map_or_else(
        || {
            search_results
                .get("results")
                .and_then(Value::as_array)
                .map_or(&[], Vec::as_slice)
        },
        Vec::as_slice,
    )
}

fn find_xref_item_addr(item: &Value) -> String {
    for key in ["addr", "offset", "vaddr", "paddr", "plt"] {
        if let Some(addr) = item.get(key) {
            if let Some(s) = addr.as_str().filter(|s| !s.is_empty()) {
                return s.to_string();
            }
            if let Some(n) = addr.as_u64() {
                return format!("{n:#x}");
            }
        }
    }
    String::new()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{RbmServer, find_xref_item_addr, find_xref_search_items};

    #[test]
    fn tool_schemas_are_exposed_to_mcp_clients() {
        let tools = RbmServer::build_tools();

        assert_eq!(tools.len(), 39);
        for tool in tools {
            assert_eq!(
                tool.input_schema.get("type").and_then(|v| v.as_str()),
                Some("object"),
                "{} should expose an object input schema",
                tool.name
            );
            assert!(
                tool.input_schema.contains_key("properties"),
                "{} should expose parameter properties",
                tool.name
            );
            assert_eq!(
                tool.input_schema
                    .get("additionalProperties")
                    .and_then(|v| v.as_bool()),
                Some(false),
                "{} should reject unknown parameter names",
                tool.name
            );
        }
    }

    #[test]
    fn decompile_schema_documents_plugin_and_meta_mode() {
        let tools = RbmServer::build_tools();
        let tool = tools
            .iter()
            .find(|tool| tool.name == "r2_decompile")
            .expect("r2_decompile tool");

        let description = tool.description.as_ref().expect("description");
        assert!(description.contains("r2ghidra"));
        assert!(description.contains("mode=meta"));

        let mode = &tool.input_schema["properties"]["mode"];
        assert_eq!(mode["enum"], serde_json::json!(["code", "meta"]));
    }

    #[test]
    fn find_xrefs_accepts_wrapped_search_results() {
        let wrapped = json!({
            "count": 1,
            "results": [{"addr": "0x140044048", "name": "CreateProcessA"}]
        });

        let items = find_xref_search_items(&wrapped);

        assert_eq!(items.len(), 1);
        assert_eq!(find_xref_item_addr(&items[0]), "0x140044048");
    }

    #[test]
    fn find_xrefs_accepts_numeric_address_fields() {
        let item = json!({"plt": 5368987720_u64, "name": "CreateProcessA"});

        assert_eq!(find_xref_item_addr(&item), "0x140044048");
    }
}
