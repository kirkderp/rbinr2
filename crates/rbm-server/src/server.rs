// Manual MCP server for radare2-based binary analysis.
use std::sync::Arc;

use rbm_core::{GuardedOutput, OutputGuard, ServerConfig, ToolError};
use rbm_r2::SessionManager;
use rmcp::handler::server::ServerHandler;
use rmcp::model::{
    CallToolRequestParams, CallToolResult, Content, ErrorData, Implementation, ListToolsResult,
    PaginatedRequestParams, ServerCapabilities, ServerInfo, Tool,
};
use rmcp::service::{RequestContext, RoleServer};
use serde_json::{Value, json};

use crate::support::{
    R2_CMD_MAX_INLINE_CHARS, apply_name_filter, build_address_mapping, build_extract_bytes_result,
    guard_r2_cmd_output,
};

#[derive(Clone)]
pub struct RbmServer {
    config: Arc<ServerConfig>,
    r2: Arc<SessionManager>,
    output_guard: Arc<OutputGuard>,
    tools: Vec<Tool>,
}

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

fn enum_s_default(desc: &str, values: &[&str], default: &str) -> serde_json::Value {
    serde_json::json!({"type": "string", "description": desc, "enum": values, "default": default})
}

fn opt_u32(desc: &str, def: u32) -> serde_json::Value {
    serde_json::json!({"type": "integer", "format": "uint32", "description": desc, "default": def})
}

fn opt_u32_capped(desc: &str, def: u32, max: u32) -> serde_json::Value {
    serde_json::json!({"type": "integer", "format": "uint32", "description": desc, "default": def, "maximum": max})
}

fn schema(props: Vec<(&str, serde_json::Value)>, required: Vec<&str>) -> serde_json::Value {
    let mut p = serde_json::Map::new();
    for (k, v) in props {
        p.insert(k.to_string(), v);
    }
    let required: Vec<serde_json::Value> =
        required.into_iter().map(serde_json::Value::from).collect();
    serde_json::json!({
        "type": "object",
        "properties": p,
        "required": required,
        "additionalProperties": false
    })
}

macro_rules! try_call_tools {
    ($server:expr, $name:expr, $params:expr, $($handler:ident),+ $(,)?) => {
        $(
            if let Some(result) = $server.$handler($name, $params).await? {
                return Ok(result);
            }
        )+
    };
}

impl RbmServer {
    #[must_use]
    pub fn new(config: ServerConfig) -> Self {
        let output_guard = Arc::new(OutputGuard::new(config.cache.overflow_dir()));
        let r2_open_timeout = config.r2_open_timeout;
        let tool_timeout = config.tool_timeout;
        Self {
            config: Arc::new(config),
            r2: Arc::new(
                SessionManager::with_open_timeout(r2_open_timeout).with_tool_timeout(tool_timeout),
            ),
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
    ///
    /// # Errors
    ///
    /// Returns an error if the stdio transport cannot start or the service exits
    /// with a transport error.
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
        let mut tools = Vec::new();
        tools.extend(Self::tool_group_0());
        tools.extend(Self::tool_group_1());
        tools.extend(Self::tool_group_2());
        tools.extend(Self::tool_group_3());
        tools.extend(Self::tool_group_4());
        tools.extend(Self::tool_group_5());
        tools.extend(Self::tool_group_6());
        tools.extend(Self::tool_group_7());
        tools.extend(Self::tool_group_8());
        tools.extend(Self::tool_group_9());
        tools
    }

    fn tool_group_0() -> Vec<Tool> {
        vec![
            t(
                "r2_open",
                "Open a binary with radare2 and start a persistent r2pipe session. Set force_reload=true to close an existing session and re-open (e.g., after the binary was modified on disk).",
                schema(
                    vec![
                        ("binary_path", req("absolute path to the binary")),
                        (
                            "force_reload",
                            json!({"type": "boolean", "description": "close and re-open if session already exists", "default": false}),
                        ),
                    ],
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
                            enum_s_default(
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
                                "info",
                            ),
                        ),
                        ("filter", opt_s("optional glob/substring filter")),
                        (
                            "min_length",
                            json!({"type": "integer", "description": "minimum string length for mode=strings", "default": 5}),
                        ),
                        ("all_sections", json!({"type": "boolean", "default": true})),
                        ("offset", opt_u32("result offset", 0)),
                        ("limit", opt_u32("max results; 0 returns all", 0)),
                    ],
                    vec!["binary_path"],
                ),
            ),
        ]
    }

    fn tool_group_1() -> Vec<Tool> {
        vec![
            t(
                "r2_classes",
                "List classes or inspect one class. Without classname, returns class list with optional glob/substring filter. With classname, format=json (default) returns sorted methods/fields; format=text returns raw ic output.",
                schema(
                    vec![
                        ("binary_path", req("absolute path to the binary")),
                        ("classname", opt_s("specific class to inspect")),
                        ("filter", opt_s("glob/substring filter for class names")),
                        (
                            "format",
                            enum_s_default("output format", &["json", "text"], "json"),
                        ),
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
                        ("offset", opt_u32("result offset", 0)),
                        ("limit", opt_u32_capped("max results", 50, 500)),
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
                            enum_s_default(
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
                                "list",
                            ),
                        ),
                        ("type_name", opt_s("type name for c/view/format/cast modes")),
                        ("addr", opt_s("address, symbol, or r2 flag for cast mode")),
                        (
                            "filter",
                            opt_s("optional glob/substring filter for JSON list modes"),
                        ),
                        ("offset", opt_u32("result offset", 0)),
                        ("limit", opt_u32("max results", 50)),
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
        ]
    }

    fn tool_group_2() -> Vec<Tool> {
        vec![
            t(
                "r2_plugins",
                "List r2 capabilities/plugins. mode can be asm, analysis, bin, hash, or decompile.",
                schema(
                    vec![
                        ("binary_path", req("absolute path to the binary")),
                        (
                            "mode",
                            enum_s_default(
                                "plugin mode",
                                &["asm", "analysis", "bin", "hash", "decompile"],
                                "asm",
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
                        ("count", opt_u32("number of bytes to read", 64)),
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
                        ("count", opt_u32("number of bytes to extract", 64)),
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
        ]
    }

    fn tool_group_3() -> Vec<Tool> {
        vec![
            t(
                "r2_flags",
                "Read r2 flags, demangled/real flag names, or flagspaces. Supports glob/substring filter and pagination for flag rows.",
                schema(
                    vec![
                        ("binary_path", req("absolute path to the binary")),
                        (
                            "mode",
                            enum_s_default(
                                "flags mode",
                                &["flags", "realnames", "flagspaces"],
                                "flags",
                            ),
                        ),
                        ("filter", opt_s("optional glob/substring filter")),
                        ("offset", opt_u32("result offset", 0)),
                        ("limit", opt_u32("max results", 50)),
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
                            opt_u32_capped("number of opcodes to inspect", 8, 500),
                        ),
                    ],
                    vec!["binary_path", "addr"],
                ),
            ),
        ]
    }

    fn tool_group_4() -> Vec<Tool> {
        vec![
            t(
                "r2_disassemble",
                "Disassemble a bounded instruction window from any address, symbol, or r2 flag. Set function=true for function-bounded disassembly when starting from a function symbol; otherwise count may walk into adjacent data. format=json (default) returns structured rows; format=text returns raw text. Default count=32.",
                schema(
                    vec![
                        ("binary_path", req("absolute path to the binary")),
                        ("addr", req("address, symbol, or r2 flag")),
                        (
                            "count",
                            opt_u32("number of instructions; ignored when function=true", 32),
                        ),
                        (
                            "function",
                            json!({"type": "boolean", "description": "use function-bounded pdf/pdfj instead of a fixed instruction window", "default": false}),
                        ),
                        (
                            "format",
                            enum_s_default("output format", &["json", "text"], "json"),
                        ),
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
                            opt_u32_capped("number of bytes to hash", 64, 16 * 1024 * 1024),
                        ),
                        (
                            "algorithm",
                            enum_s_default(
                                "hash or entropy algorithm",
                                &["sha256", "sha1", "sha512", "md5", "crc32", "entropy"],
                                "sha256",
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
                        ("count", opt_u32_capped("bytes to scan", 64, 1024 * 1024)),
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
                            enum_s_default(
                                "string decode mode",
                                &["auto", "ascii", "utf16", "utf32", "pascal"],
                                "auto",
                            ),
                        ),
                    ],
                    vec!["binary_path", "addr"],
                ),
            ),
        ]
    }

    fn tool_group_5() -> Vec<Tool> {
        vec![
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
                        ("limit", opt_u32("maximum results", 50)),
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
                            enum_s_default(
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
                                "opcode_type",
                            ),
                        ),
                        (
                            "pattern",
                            req("search pattern or address, depending on mode"),
                        ),
                        ("limit", opt_u32("maximum results", 50)),
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
                        ("limit", opt_u32_capped("maximum search hits", 20, 50)),
                        (
                            "max_xrefs_per_hit",
                            opt_u32_capped("maximum xrefs per hit", 12, 50),
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
                        (
                            "mode",
                            enum_s_default("decompile mode", &["code", "meta"], "code"),
                        ),
                    ],
                    vec!["binary_path", "addr"],
                ),
            ),
        ]
    }

    fn tool_group_6() -> Vec<Tool> {
        vec![
            t(
                "r2_function_view",
                "Mode-driven r2 function view. mode can be analyze, info, signature, vars, profile, strings, constants, callees, refs, or cfg. Default analyze returns compact function triage.",
                schema(
                    vec![
                        ("binary_path", req("absolute path to the binary")),
                        ("addr", req("address, symbol, or r2 flag")),
                        (
                            "mode",
                            enum_s_default(
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
                                "analyze",
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
                            enum_s_default(
                                "graph output format",
                                &["json", "text", "dot", "mermaid"],
                                "json",
                            ),
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
                        (
                            "mode",
                            enum_s_default("security mode", &["checksec", "entropy"], "checksec"),
                        ),
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
                        (
                            "direction",
                            enum_s_default("xref direction", &["to", "from"], "to"),
                        ),
                    ],
                    vec!["binary_path", "addr"],
                ),
            ),
        ]
    }

    fn tool_group_7() -> Vec<Tool> {
        vec![
            t(
                "r2_global_xrefs",
                "Return a paginated global xref inventory from axlj.",
                schema(
                    vec![
                        ("binary_path", req("absolute path to the binary")),
                        ("offset", opt_u32("result offset", 0)),
                        ("limit", opt_u32("max results", 50)),
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
                            enum_s_default(
                                "ESIL access mode",
                                &["instructions", "bytes", "block", "function"],
                                "instructions",
                            ),
                        ),
                        ("count", opt_u32("instruction or byte count", 32)),
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
                "Run a single read-only radare2 query command and return guarded output. Rejects separators, shell escapes, writes, seeks, and eval-setting mutations. Prefer named rbinr2 tools when available.",
                schema(
                    vec![
                        ("binary_path", req("absolute path to the binary")),
                        ("command", req("raw r2 command")),
                    ],
                    vec!["binary_path", "command"],
                ),
            ),
        ]
    }

    fn tool_group_8() -> Vec<Tool> {
        vec![
            t(
                "r2_trace_data_flow",
                "BFS over xrefs (axfj/axtj) from or to an address. 'backward' answers 'who reaches this string/global/import?'; 'forward' answers 'where does data flow next?'. max_depth clamped to 1-15.",
                schema(
                    vec![
                        ("binary_path", req("absolute path to the binary")),
                        ("addr", req("address, symbol, or r2 flag")),
                        (
                            "direction",
                            enum_s_default("trace direction", &["forward", "backward"], "backward"),
                        ),
                        (
                            "max_depth",
                            opt_u32_capped("maximum traversal depth", 5, 15),
                        ),
                    ],
                    vec!["binary_path", "addr"],
                ),
            ),
            t(
                "r2_value_trace",
                "Trace a seeded register or memory value through a bounded radare2 disassembly window. Tracks register aliases, stack slots, memory saves/restores, mutations, and calls/jumps reached by the seed. Provide seed_register or seed_memory.",
                schema(
                    vec![
                        ("binary_path", req("absolute path to the binary")),
                        ("start_addr", req("start address to scan")),
                        (
                            "seed_register",
                            opt_s("optional register carrying the value"),
                        ),
                        ("seed_memory", opt_s("optional memory/stack slot")),
                        ("seed_value", opt_s("optional concrete value")),
                        ("arch", opt_s("r2 architecture override")),
                        ("bits", opt_u32("r2 bitness override; 0 uses r2 default", 0)),
                        (
                            "max_instructions",
                            opt_u32("max instructions to inspect", 300),
                        ),
                        ("max_events", opt_u32("max events to return", 100)),
                    ],
                    vec!["binary_path", "start_addr"],
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
                            opt_u32("max instructions to inspect", 220),
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
                            serde_json::json!({"type": "integer", "format": "uint32", "description": "number of pointer entries", "minimum": 1}),
                        ),
                        ("pointer_size", opt_u32("pointer size in bytes", 4)),
                        (
                            "target_bytes",
                            opt_u32("bytes to inspect at each target", 512),
                        ),
                        (
                            "max_instructions",
                            opt_u32("max instructions to inspect", 120),
                        ),
                    ],
                    vec!["binary_path", "table_addr", "entry_count"],
                ),
            ),
        ]
    }

    fn tool_group_9() -> Vec<Tool> {
        vec![
            t(
                "r2_path_digest",
                "Return a cheap radare2-backed macro path digest over a function or raw address range.",
                schema(
                    vec![
                        ("binary_path", req("absolute path to the binary")),
                        ("start_addr", req("start address to scan")),
                        ("arch", opt_s("r2 architecture override")),
                        ("bits", opt_u32("r2 bitness override; 0 uses r2 default", 0)),
                        ("range_end", opt_s("exclusive end address")),
                        ("stop_addresses", opt_s("stop addresses")),
                        ("state_register", opt_s("state/base register")),
                        ("marker_constants", opt_s("marker constants")),
                        (
                            "max_instructions",
                            opt_u32("max instructions to inspect", 800),
                        ),
                        ("max_events", opt_u32("max events to return", 80)),
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
                        ("bits", opt_u32("r2 bitness override; 0 uses r2 default", 0)),
                        ("range_end", opt_s("exclusive end address")),
                        (
                            "max_instructions",
                            opt_u32("max instructions to inspect", 1200),
                        ),
                        ("max_steps", opt_u32("max emulation steps", 20000)),
                        (
                            "min_string_len",
                            opt_u32("minimum decoded string length", 4),
                        ),
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
                        ("bits", opt_u32("r2 bitness override; 0 uses r2 default", 0)),
                        ("range_end", opt_s("exclusive end address")),
                        ("root_register", opt_s("root register")),
                        ("root_name", opt_s("root register symbol name")),
                        ("arg_names", opt_s("stack argument offset=name pairs")),
                        ("resolver_function", opt_s("resolver call target")),
                        ("marker_constants", opt_s("marker constants")),
                        ("ignore_stack", json!({"type": "boolean", "default": false})),
                        (
                            "max_instructions",
                            opt_u32("max instructions to inspect", 800),
                        ),
                        ("max_rows", opt_u32("max rows to return", 60)),
                    ],
                    vec!["binary_path", "start_addr"],
                ),
            ),
        ]
    }

    fn s(v: &serde_json::Map<String, serde_json::Value>, key: &str) -> String {
        v.get(key)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    }

    fn opt_s<'a>(v: &'a serde_json::Map<String, serde_json::Value>, key: &str) -> Option<&'a str> {
        v.get(key).and_then(|s| {
            let s = s.as_str()?;
            if s.is_empty() { None } else { Some(s) }
        })
    }

    fn opt_u64(v: &serde_json::Map<String, serde_json::Value>, key: &str) -> Option<u64> {
        v.get(key).and_then(serde_json::Value::as_u64)
    }

    fn opt_u32(v: &serde_json::Map<String, serde_json::Value>, key: &str) -> Option<u32> {
        v.get(key)
            .and_then(serde_json::Value::as_u64)
            .and_then(|x| u32::try_from(x).ok())
    }

    fn opt_bool(v: &serde_json::Map<String, serde_json::Value>, key: &str) -> Option<bool> {
        v.get(key).and_then(serde_json::Value::as_bool)
    }

    fn opt_usize(v: &serde_json::Map<String, serde_json::Value>, key: &str) -> Option<usize> {
        v.get(key)
            .and_then(serde_json::Value::as_u64)
            .and_then(|x| usize::try_from(x).ok())
    }

    fn ok_json(value: impl serde::Serialize) -> Result<CallToolResult, ErrorData> {
        let text = serde_json::to_string(&value).map_err(|e| err(e.to_string()))?;
        Ok(CallToolResult::success(vec![Content::text(text)]))
    }

    fn ok_json_guarded(
        &self,
        label: &str,
        value: impl serde::Serialize,
    ) -> Result<CallToolResult, ErrorData> {
        let text = serde_json::to_string(&value).map_err(|e| err(e.to_string()))?;
        let guarded = OutputGuard::new(self.output_guard.overflow_dir().to_path_buf())
            .with_max_inline_chars(R2_CMD_MAX_INLINE_CHARS)
            .with_ttl(self.output_guard.ttl())
            .guard_str(label, text)
            .map_err(|e| err(e.to_string()))?;
        match guarded {
            GuardedOutput::Inline(text) => Ok(CallToolResult::success(vec![Content::text(text)])),
            GuardedOutput::Overflow(summary) => Self::ok_json(summary),
        }
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

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let name = request.name.as_ref();
        let params = request.arguments.unwrap_or_default();
        match name {
            "r2_close" => {
                let outcome = self
                    .r2
                    .close(Self::s(&params, "binary_path"))
                    .map_err(|e| err(e.to_string()))?;
                return Self::ok_json(outcome);
            }
            "r2_sessions" => {
                let paths = self.r2.list();
                return Self::ok_json(serde_json::json!({
                    "schema": "rbm.r2.sessions.v0",
                    "count": paths.len(),
                    "sessions": paths,
                }));
            }
            _ => {}
        }
        try_call_tools!(
            self,
            name,
            &params,
            call_tool_0,
            call_tool_3,
            call_tool_4,
            call_tool_5,
            call_tool_6,
            call_tool_7,
            call_tool_8,
            call_tool_9,
            call_tool_10,
            call_tool_11,
            call_tool_12,
            call_tool_13,
            call_tool_14,
            call_tool_15,
            call_tool_16,
            call_tool_17,
            call_tool_18,
            call_tool_19,
            call_tool_20,
            call_tool_21,
            call_tool_22,
            call_tool_23,
            call_tool_24,
            call_tool_25,
            call_tool_26,
            call_tool_27,
            call_tool_28,
            call_tool_29,
            call_tool_30,
            call_tool_31,
            call_tool_32,
            call_tool_33,
            call_tool_34,
            call_tool_35,
            call_tool_36,
            call_tool_37,
            call_tool_38,
        );
        Err(ErrorData::new(
            rmcp::model::ErrorCode::INVALID_PARAMS,
            format!("unknown tool: {name}"),
            None,
        ))
    }
}

impl RbmServer {
    async fn call_tool_0(
        &self,
        name: &str,
        params: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<CallToolResult>, ErrorData> {
        let _ = params;
        let result = match name {
            "r2_open" => {
                let binary_path = Self::s(params, "binary_path");
                let force_reload = Self::opt_bool(params, "force_reload").unwrap_or(false);
                if force_reload {
                    let _ = self.r2.close(&binary_path);
                }
                let outcome = self
                    .r2
                    .open(&binary_path)
                    .await
                    .map_err(|e| err(e.to_string()))?;
                Self::ok_json(outcome)
            }

            _ => return Ok(None),
        };
        result.map(Some)
    }

    async fn call_tool_3(
        &self,
        name: &str,
        params: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<CallToolResult>, ErrorData> {
        let _ = params;
        let result = match name {
            "r2_metadata" => self.r2_metadata(params).await,

            _ => return Ok(None),
        };
        result.map(Some)
    }

    async fn call_tool_4(
        &self,
        name: &str,
        params: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<CallToolResult>, ErrorData> {
        let _ = params;
        let result = match name {
            "r2_classes" => {
                let binary_path = Self::s(params, "binary_path");
                let session = self.session_for(&binary_path).await?;
                let classname = Self::opt_s(params, "classname").filter(|s| !s.is_empty());

                let result = if let Some(name) = classname {
                    let format = Self::s(params, "format").trim().to_ascii_lowercase();
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
                    if let Some(pattern) = Self::opt_s(params, "filter").filter(|s| !s.is_empty()) {
                        value = rbm_r2::format::filter_classes(value, pattern)
                            .map_err(|e| err(e.to_string()))?;
                    }
                    serde_json::to_string(&value).map_err(|e| err(e.to_string()))?
                };

                Ok(CallToolResult::success(vec![Content::text(result)]))
            }

            _ => return Ok(None),
        };
        result.map(Some)
    }

    async fn call_tool_5(
        &self,
        name: &str,
        params: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<CallToolResult>, ErrorData> {
        let _ = params;
        let result = match name {
            "r2_vtables" => {
                let session = self.session_for(&Self::s(params, "binary_path")).await?;
                let offset = Self::opt_usize(params, "offset").unwrap_or(0);
                let limit = Self::opt_usize(params, "limit").unwrap_or(50);
                let result = rbm_r2::format::vtables(&session, offset, limit)
                    .await
                    .map_err(|e| err(e.to_string()))?;
                Self::ok_json(result)
            }

            _ => return Ok(None),
        };
        result.map(Some)
    }

    async fn call_tool_6(
        &self,
        name: &str,
        params: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<CallToolResult>, ErrorData> {
        let _ = params;
        let result = match name {
            "r2_types" => {
                let session = self.session_for(&Self::s(params, "binary_path")).await?;
                let offset = Self::opt_usize(params, "offset").unwrap_or(0);
                let limit = Self::opt_usize(params, "limit").unwrap_or(50);
                let result = rbm_r2::types::types_view(
                    &session,
                    Self::opt_s(params, "mode").unwrap_or("list"),
                    Self::opt_s(params, "type_name"),
                    Self::opt_s(params, "addr"),
                    offset,
                    limit,
                    Self::opt_s(params, "filter"),
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                Self::ok_json(result)
            }

            _ => return Ok(None),
        };
        result.map(Some)
    }

    async fn call_tool_7(
        &self,
        name: &str,
        params: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<CallToolResult>, ErrorData> {
        let _ = params;
        let result = match name {
            "r2_imports_grouped" => {
                let binary_path = Self::s(params, "binary_path");
                let session = self.session_for(&binary_path).await?;
                let result = rbm_r2::symbols::imports_grouped(&session)
                    .await
                    .map_err(|e| err(e.to_string()))?;
                Self::ok_json(serde_json::json!({
                    "schema": "rbm.r2.imports_grouped.v0",
                    "binary_path": binary_path,
                    "result": result,
                }))
            }

            _ => return Ok(None),
        };
        result.map(Some)
    }

    async fn call_tool_8(
        &self,
        name: &str,
        params: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<CallToolResult>, ErrorData> {
        let _ = params;
        let result = match name {
            "r2_plugins" => {
                let session = self.session_for(&Self::s(params, "binary_path")).await?;
                let result = rbm_r2::navigation::plugins(
                    &session,
                    Self::opt_s(params, "mode").unwrap_or("asm"),
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                Self::ok_json(result)
            }

            _ => return Ok(None),
        };
        result.map(Some)
    }

    async fn call_tool_9(
        &self,
        name: &str,
        params: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<CallToolResult>, ErrorData> {
        let _ = params;
        let result = match name {
            "r2_get_bytes" => {
                let binary_path = Self::s(params, "binary_path");
                let addr = Self::s(params, "addr");
                let count = Self::opt_u64(params, "count").unwrap_or(64);
                let session = self.session_for(&binary_path).await?;
                let hex = rbm_r2::disasm::get_bytes(&session, &addr, count)
                    .await
                    .map_err(|e| err(e.to_string()))?;
                let compact_hex: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
                Self::ok_json(serde_json::json!({
                    "schema": "rbm.r2.get_bytes.v0",
                    "binary_path": binary_path,
                    "addr": addr,
                    "requested_count": count,
                    "byte_count": compact_hex.len() / 2,
                    "hex": compact_hex,
                }))
            }

            _ => return Ok(None),
        };
        result.map(Some)
    }

    async fn call_tool_10(
        &self,
        name: &str,
        params: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<CallToolResult>, ErrorData> {
        let _ = params;
        let result = match name {
            "r2_extract_bytes" => {
                let binary_path = Self::s(params, "binary_path");
                let addr = Self::s(params, "addr");
                let count = Self::opt_u64(params, "count").unwrap_or(64);
                let out_path = Self::opt_s(params, "out_path").map(String::from);
                let overwrite = Self::opt_bool(params, "overwrite").unwrap_or(true);
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

                Self::ok_json(result)
            }

            _ => return Ok(None),
        };
        result.map(Some)
    }

    async fn call_tool_11(
        &self,
        name: &str,
        params: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<CallToolResult>, ErrorData> {
        let _ = params;
        let result = match name {
            "r2_lookup_address" => self
                .with_session_json(&Self::s(params, "binary_path"), |session| async move {
                    rbm_r2::disasm::lookup_address(&session, &Self::s(params, "addr")).await
                })
                .await
                .map(|s| CallToolResult::success(vec![Content::text(s)])),
            _ => return Ok(None),
        };
        result.map(Some)
    }

    async fn call_tool_12(
        &self,
        name: &str,
        params: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<CallToolResult>, ErrorData> {
        let _ = params;
        let result = match name {
            "r2_flags" => {
                let session = self.session_for(&Self::s(params, "binary_path")).await?;
                let offset = Self::opt_usize(params, "offset").unwrap_or(0);
                let limit = Self::opt_usize(params, "limit").unwrap_or(50);
                let result = rbm_r2::navigation::flags(
                    &session,
                    Self::opt_s(params, "mode").unwrap_or("flags"),
                    offset,
                    limit,
                    Self::opt_s(params, "filter"),
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                Self::ok_json(result)
            }

            _ => return Ok(None),
        };
        result.map(Some)
    }

    async fn call_tool_13(
        &self,
        name: &str,
        params: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<CallToolResult>, ErrorData> {
        let _ = params;
        let result = match name {
            "r2_address_info" => self
                .with_session_json(&Self::s(params, "binary_path"), |session| async move {
                    rbm_r2::disasm::address_info(&session, &Self::s(params, "addr")).await
                })
                .await
                .map(|s| CallToolResult::success(vec![Content::text(s)])),
            _ => return Ok(None),
        };
        result.map(Some)
    }

    async fn call_tool_14(
        &self,
        name: &str,
        params: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<CallToolResult>, ErrorData> {
        let _ = params;
        let result = match name {
            "r2_calculate" => self
                .with_session_json(&Self::s(params, "binary_path"), |session| async move {
                    rbm_r2::disasm::calculate(&session, &Self::s(params, "expression")).await
                })
                .await
                .map(|s| CallToolResult::success(vec![Content::text(s)])),
            _ => return Ok(None),
        };
        result.map(Some)
    }

    async fn call_tool_15(
        &self,
        name: &str,
        params: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<CallToolResult>, ErrorData> {
        let _ = params;
        let result = match name {
            "r2_opcodes" => self
                .with_session_json(&Self::s(params, "binary_path"), |session| async move {
                    let count = Self::opt_u32(params, "count").unwrap_or(8);
                    rbm_r2::disasm::opcodes(&session, &Self::s(params, "addr"), count).await
                })
                .await
                .map(|s| CallToolResult::success(vec![Content::text(s)])),
            _ => return Ok(None),
        };
        result.map(Some)
    }

    async fn call_tool_16(
        &self,
        name: &str,
        params: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<CallToolResult>, ErrorData> {
        let _ = params;
        let result = match name {
            "r2_disassemble" => {
                let binary_path = Self::s(params, "binary_path");
                let addr = Self::s(params, "addr");
                let count = Self::opt_u64(params, "count").unwrap_or(32);
                let function = Self::opt_bool(params, "function").unwrap_or(false);
                let format = Self::s(params, "format").trim().to_ascii_lowercase();

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

            _ => return Ok(None),
        };
        result.map(Some)
    }

    async fn call_tool_17(
        &self,
        name: &str,
        params: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<CallToolResult>, ErrorData> {
        let _ = params;
        let result = match name {
            "r2_block_hash" => self
                .with_session_json(&Self::s(params, "binary_path"), |session| async move {
                    let count = Self::opt_u64(params, "count").unwrap_or(64);
                    rbm_r2::disasm::block_hash(
                        &session,
                        &Self::s(params, "addr"),
                        count,
                        Self::opt_s(params, "algorithm").unwrap_or("sha256"),
                    )
                    .await
                })
                .await
                .map(|s| CallToolResult::success(vec![Content::text(s)])),
            _ => return Ok(None),
        };
        result.map(Some)
    }

    async fn call_tool_18(
        &self,
        name: &str,
        params: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<CallToolResult>, ErrorData> {
        let _ = params;
        let result = match name {
            "r2_pointer_scan" => self
                .with_session_json(&Self::s(params, "binary_path"), |session| async move {
                    let count = Self::opt_u64(params, "count").unwrap_or(64);
                    rbm_r2::navigation::pointer_scan(&session, &Self::s(params, "addr"), count)
                        .await
                })
                .await
                .map(|s| CallToolResult::success(vec![Content::text(s)])),
            _ => return Ok(None),
        };
        result.map(Some)
    }

    async fn call_tool_19(
        &self,
        name: &str,
        params: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<CallToolResult>, ErrorData> {
        let _ = params;
        let result = match name {
            "r2_string_at" => self
                .with_session_json(&Self::s(params, "binary_path"), |session| async move {
                    rbm_r2::navigation::string_at(
                        &session,
                        &Self::s(params, "addr"),
                        Self::opt_s(params, "mode").unwrap_or("auto"),
                    )
                    .await
                })
                .await
                .map(|s| CallToolResult::success(vec![Content::text(s)])),
            _ => return Ok(None),
        };
        result.map(Some)
    }

    async fn call_tool_20(
        &self,
        name: &str,
        params: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<CallToolResult>, ErrorData> {
        let _ = params;
        let result = match name {
            "r2_find" => {
                let binary_path = Self::s(params, "binary_path");
                let session = self.session_for(&binary_path).await?;
                let mut result = rbm_r2::search::find(
                    &session,
                    &Self::s(params, "search_type"),
                    &Self::s(params, "pattern"),
                    Self::opt_usize(params, "limit").unwrap_or(50),
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                if let Some(result) = result.as_object_mut() {
                    result.insert("binary_path".to_string(), serde_json::json!(binary_path));
                }
                Self::ok_json(result)
            }

            _ => return Ok(None),
        };
        result.map(Some)
    }

    async fn call_tool_21(
        &self,
        name: &str,
        params: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<CallToolResult>, ErrorData> {
        let _ = params;
        let result = match name {
            "r2_semantic_search" => self
                .with_session_json(&Self::s(params, "binary_path"), |session| async move {
                    let limit = Self::opt_usize(params, "limit").unwrap_or(50);
                    rbm_r2::navigation::semantic_search(
                        &session,
                        Self::opt_s(params, "mode").unwrap_or("opcode_type"),
                        &Self::s(params, "pattern"),
                        limit,
                    )
                    .await
                })
                .await
                .map(|s| CallToolResult::success(vec![Content::text(s)])),
            _ => return Ok(None),
        };
        result.map(Some)
    }

    async fn call_tool_22(
        &self,
        name: &str,
        params: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<CallToolResult>, ErrorData> {
        let _ = params;
        let result = match name {
            "r2_find_xrefs" => {
                // Inline a simple find_xrefs implementation since the original
                // used a service layer not available here
                let binary_path = Self::s(params, "binary_path");
                let search_type = Self::s(params, "search_type");
                let pattern = Self::s(params, "pattern");
                let limit = Self::opt_usize(params, "limit").unwrap_or(20).min(50);
                let max_xrefs = Self::opt_usize(params, "max_xrefs_per_hit")
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
                    let xrefs_trimmed = xrefs_val.as_array().map_or_else(
                        || xrefs_val.clone(),
                        |arr| Value::Array(arr.iter().take(max_xrefs).cloned().collect()),
                    );

                    hits.push(serde_json::json!({
                        "hit": item,
                        "xref_count": xrefs_count,
                        "xref_count_is_exact": xrefs_count <= max_xrefs,
                        "xrefs": xrefs_trimmed,
                    }));
                }

                Self::ok_json(serde_json::json!({
                    "schema": "rbm.r2.find_xrefs.v0",
                    "binary_path": binary_path,
                    "search_type": search_type,
                    "pattern": pattern,
                    "hit_count": hits.len(),
                    "hits": hits,
                }))
            }

            _ => return Ok(None),
        };
        result.map(Some)
    }

    async fn call_tool_23(
        &self,
        name: &str,
        params: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<CallToolResult>, ErrorData> {
        let _ = params;
        let result = match name {
            "r2_decompile" => {
                let binary_path = Self::s(params, "binary_path");
                let addr = Self::s(params, "addr");
                let mode = Self::s(params, "mode").trim().to_ascii_lowercase();

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

            _ => return Ok(None),
        };
        result.map(Some)
    }

    async fn call_tool_24(
        &self,
        name: &str,
        params: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<CallToolResult>, ErrorData> {
        let _ = params;
        let result = match name {
            "r2_function_view" => {
                let binary_path = Self::s(params, "binary_path");
                let addr = Self::s(params, "addr");
                let mode = Self::s(params, "mode");
                let include_asm = Self::opt_bool(params, "include_asm").unwrap_or(false);
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

                Self::ok_json(serde_json::json!({
                    "schema": "rbm.r2.function_view.v0",
                    "binary_path": binary_path,
                    "addr": addr,
                    "mode": mode,
                    "result": result,
                }))
            }

            _ => return Ok(None),
        };
        result.map(Some)
    }

    async fn call_tool_25(
        &self,
        name: &str,
        params: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<CallToolResult>, ErrorData> {
        let _ = params;
        let result = match name {
            "r2_graph" => {
                let session = self.session_for(&Self::s(params, "binary_path")).await?;
                let kind = Self::opt_s(params, "kind").unwrap_or("function");
                let addr = Self::opt_s(params, "addr");
                // Per-kind addr validation: function, callgraph, imports, refs, xrefs, and
                // data_refs require an addr. Without it the agent gets a massive global graph.
                let needs_addr = matches!(
                    kind.trim(),
                    "" | "function"
                        | "cfg"
                        | "agf"
                        | "callgraph"
                        | "calls"
                        | "agc"
                        | "imports"
                        | "agi"
                        | "refs"
                        | "references"
                        | "agr"
                        | "xrefs"
                        | "crossrefs"
                        | "agx"
                        | "data_refs"
                        | "data"
                        | "aga"
                );
                if needs_addr && addr.is_none() {
                    return Err(err(format!(
                        "r2_graph kind {kind:?} requires an addr parameter; pass an address, symbol, or r2 flag"
                    )));
                }
                let result = rbm_r2::disasm::graph(
                    &session,
                    kind,
                    Self::opt_s(params, "format").unwrap_or("json"),
                    addr,
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                self.ok_json_guarded("r2_graph", result)
            }

            _ => return Ok(None),
        };
        result.map(Some)
    }

    async fn call_tool_26(
        &self,
        name: &str,
        params: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<CallToolResult>, ErrorData> {
        let _ = params;
        let result = match name {
            "r2_security" => {
                let session = self.session_for(&Self::s(params, "binary_path")).await?;
                let mode = Self::s(params, "mode");
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
                Self::ok_json(serde_json::json!({
                    "schema": "rbm.r2.security.v0",
                    "mode": mode,
                    "result": result,
                }))
            }

            _ => return Ok(None),
        };
        result.map(Some)
    }

    async fn call_tool_27(
        &self,
        name: &str,
        params: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<CallToolResult>, ErrorData> {
        let _ = params;
        let result = match name {
            "r2_xrefs" => {
                let binary_path = Self::s(params, "binary_path");
                let addr = Self::s(params, "addr");
                let direction = Self::opt_s(params, "direction").unwrap_or("to");

                let session = self.session_for(&binary_path).await?;
                let dir =
                    rbm_r2::disasm::XrefDir::parse(direction).map_err(|e| err(e.to_string()))?;
                let result = rbm_r2::disasm::xrefs(&session, &addr, dir)
                    .await
                    .map_err(|e| err(e.to_string()))?;
                let count = result.as_array().map_or(0, Vec::len);
                Self::ok_json(serde_json::json!({
                    "schema": "rbm.r2.xrefs.v0",
                    "binary_path": binary_path,
                    "addr": addr,
                    "direction": direction,
                    "count": count,
                    "xrefs": result,
                }))
            }

            _ => return Ok(None),
        };
        result.map(Some)
    }

    async fn call_tool_28(
        &self,
        name: &str,
        params: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<CallToolResult>, ErrorData> {
        let _ = params;
        let result = match name {
            "r2_global_xrefs" => {
                let session = self.session_for(&Self::s(params, "binary_path")).await?;
                let offset = Self::opt_usize(params, "offset").unwrap_or(0);
                let limit = Self::opt_usize(params, "limit").unwrap_or(50);
                let result = rbm_r2::navigation::global_xrefs(&session, offset, limit)
                    .await
                    .map_err(|e| err(e.to_string()))?;
                Self::ok_json(result)
            }

            _ => return Ok(None),
        };
        result.map(Some)
    }

    async fn call_tool_29(
        &self,
        name: &str,
        params: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<CallToolResult>, ErrorData> {
        let _ = params;
        let result = match name {
            "r2_esil_accesses" => {
                let session = self.session_for(&Self::s(params, "binary_path")).await?;
                let count = Self::opt_u32(params, "count").unwrap_or(32);
                let result = rbm_r2::disasm::esil_accesses(
                    &session,
                    &Self::s(params, "addr"),
                    Self::opt_s(params, "mode").unwrap_or("instructions"),
                    count,
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                Self::ok_json(result)
            }

            _ => return Ok(None),
        };
        result.map(Some)
    }

    async fn call_tool_30(
        &self,
        name: &str,
        params: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<CallToolResult>, ErrorData> {
        let _ = params;
        let result = match name {
            "r2_var_xrefs" => {
                let session = self.session_for(&Self::s(params, "binary_path")).await?;
                let result = rbm_r2::disasm::variable_xrefs(&session, &Self::s(params, "addr"))
                    .await
                    .map_err(|e| err(e.to_string()))?;
                Self::ok_json(result)
            }

            _ => return Ok(None),
        };
        result.map(Some)
    }

    async fn call_tool_31(
        &self,
        name: &str,
        params: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<CallToolResult>, ErrorData> {
        let _ = params;
        let result = match name {
            "r2_cmd" => {
                let session = self.session_for(&Self::s(params, "binary_path")).await?;
                let raw = rbm_r2::cmd::raw_cmd(&session, &Self::s(params, "command"))
                    .await
                    .map_err(|e| err(e.to_string()))?;
                let guarded =
                    guard_r2_cmd_output(&self.output_guard, raw).map_err(|e| err(e.to_string()))?;
                Self::ok_json(guarded)
            }

            _ => return Ok(None),
        };
        result.map(Some)
    }

    async fn call_tool_32(
        &self,
        name: &str,
        params: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<CallToolResult>, ErrorData> {
        let _ = params;
        let result = match name {
            "r2_trace_data_flow" => {
                let session = self.session_for(&Self::s(params, "binary_path")).await?;
                let direction = Self::opt_s(params, "direction").unwrap_or("backward");
                let tra_dir = rbm_r2::trace::TraceDirection::parse(direction)
                    .map_err(|e| err(e.to_string()))?;
                let max_depth = i64::try_from(Self::opt_u64(params, "max_depth").unwrap_or(5))
                    .unwrap_or(i64::MAX);
                let result = rbm_r2::trace::trace_data_flow(
                    &session,
                    &Self::s(params, "addr"),
                    tra_dir,
                    max_depth,
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                Self::ok_json(result)
            }

            _ => return Ok(None),
        };
        result.map(Some)
    }

    async fn call_tool_33(
        &self,
        name: &str,
        params: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<CallToolResult>, ErrorData> {
        let _ = params;
        let result = match name {
            "r2_value_trace" => {
                let session = self.session_for(&Self::s(params, "binary_path")).await?;
                let result = rbm_r2::trace::trace_seed_value(
                    &session,
                    &Self::s(params, "start_addr"),
                    rbm_r2::trace::ValueTraceOptions {
                        arch: Self::opt_s(params, "arch"),
                        bits: Self::opt_u32(params, "bits").unwrap_or(0),
                        seed_register: &Self::s(params, "seed_register"),
                        seed_memory: Self::opt_s(params, "seed_memory"),
                        seed_value: Self::opt_s(params, "seed_value"),
                        max_instructions: Self::opt_u32(params, "max_instructions").unwrap_or(300),
                        max_events: Self::opt_usize(params, "max_events").unwrap_or(100),
                    },
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                Self::ok_json(result)
            }

            _ => return Ok(None),
        };
        result.map(Some)
    }

    async fn call_tool_34(
        &self,
        name: &str,
        params: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<CallToolResult>, ErrorData> {
        let _ = params;
        let result = match name {
            "r2_windows_driver_dispatch" => {
                let session = self.session_for(&Self::s(params, "binary_path")).await?;
                let result = rbm_r2::windows_driver::windows_driver_dispatch(
                    &session,
                    rbm_r2::windows_driver::DriverDispatchOptions {
                        init_addr: &Self::s(params, "init_addr"),
                        driver_register: Self::opt_s(params, "driver_register").unwrap_or("rcx"),
                        max_instructions: Self::opt_u64(params, "max_instructions").unwrap_or(220),
                    },
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                Self::ok_json(result)
            }

            _ => return Ok(None),
        };
        result.map(Some)
    }

    async fn call_tool_35(
        &self,
        name: &str,
        params: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<CallToolResult>, ErrorData> {
        let _ = params;
        let result = match name {
            "r2_jump_table_slices" => self
                .with_session_json(&Self::s(params, "binary_path"), |session| async move {
                    let entry_count = Self::opt_u32(params, "entry_count")
                        .ok_or_else(|| ToolError::invalid("entry_count is required"))?;
                    let pointer_size = Self::opt_u32(params, "pointer_size").unwrap_or(4);
                    let target_bytes = Self::opt_u64(params, "target_bytes").unwrap_or(512);
                    let max_instructions = Self::opt_u32(params, "max_instructions").unwrap_or(120);
                    rbm_r2::jump_table::jump_table_slices(
                        &session,
                        &Self::s(params, "table_addr"),
                        entry_count,
                        pointer_size,
                        target_bytes,
                        max_instructions,
                    )
                    .await
                })
                .await
                .map(|s| CallToolResult::success(vec![Content::text(s)])),
            _ => return Ok(None),
        };
        result.map(Some)
    }

    async fn call_tool_36(
        &self,
        name: &str,
        params: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<CallToolResult>, ErrorData> {
        let _ = params;
        let result = match name {
            "r2_path_digest" => {
                let session = self.session_for(&Self::s(params, "binary_path")).await?;
                let result = rbm_r2::path_digest::path_digest(
                    &session,
                    &Self::s(params, "start_addr"),
                    rbm_r2::path_digest::PathDigestOptions {
                        arch: Self::opt_s(params, "arch"),
                        bits: Self::opt_u32(params, "bits").unwrap_or(0),
                        range_end: Self::opt_s(params, "range_end"),
                        stop_addresses: Self::opt_s(params, "stop_addresses"),
                        state_register: Self::opt_s(params, "state_register"),
                        marker_constants: Self::opt_s(params, "marker_constants"),
                        max_instructions: Self::opt_u32(params, "max_instructions").unwrap_or(800),
                        max_events: Self::opt_usize(params, "max_events").unwrap_or(80),
                    },
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                Self::ok_json(result)
            }

            _ => return Ok(None),
        };
        result.map(Some)
    }

    async fn call_tool_37(
        &self,
        name: &str,
        params: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<CallToolResult>, ErrorData> {
        let _ = params;
        let result = match name {
            "r2_artifact_summary" => {
                let session = self.session_for(&Self::s(params, "binary_path")).await?;
                let result = rbm_r2::artifact_summary::artifact_summary(
                    &session,
                    &Self::s(params, "start_addr"),
                    rbm_r2::artifact_summary::ArtifactSummaryOptions {
                        arch: Self::opt_s(params, "arch"),
                        bits: Self::opt_u32(params, "bits").unwrap_or(0),
                        range_end: Self::opt_s(params, "range_end"),
                        max_instructions: Self::opt_u32(params, "max_instructions").unwrap_or(1200),
                        max_steps: Self::opt_usize(params, "max_steps").unwrap_or(20000),
                        min_string_len: Self::opt_usize(params, "min_string_len").unwrap_or(4),
                    },
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                Self::ok_json(result)
            }

            _ => return Ok(None),
        };
        result.map(Some)
    }

    async fn call_tool_38(
        &self,
        name: &str,
        params: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<CallToolResult>, ErrorData> {
        let _ = params;
        let result = match name {
            "r2_field_xrefs" => {
                let session = self.session_for(&Self::s(params, "binary_path")).await?;
                let result = rbm_r2::field_xrefs::field_xrefs(
                    &session,
                    &Self::s(params, "start_addr"),
                    rbm_r2::field_xrefs::FieldXrefsOptions {
                        arch: Self::opt_s(params, "arch"),
                        bits: Self::opt_u32(params, "bits").unwrap_or(0),
                        range_end: Self::opt_s(params, "range_end"),
                        root_register: Self::opt_s(params, "root_register"),
                        root_name: Self::opt_s(params, "root_name"),
                        arg_names: Self::opt_s(params, "arg_names"),
                        resolver_function: Self::opt_s(params, "resolver_function"),
                        marker_constants: Self::opt_s(params, "marker_constants"),
                        ignore_stack: Self::opt_bool(params, "ignore_stack").unwrap_or(false),
                        max_instructions: Self::opt_u32(params, "max_instructions").unwrap_or(800),
                        max_rows: Self::opt_usize(params, "max_rows").unwrap_or(60),
                    },
                )
                .await
                .map_err(|e| err(e.to_string()))?;
                Self::ok_json(result)
            }

            _ => return Ok(None),
        };
        result.map(Some)
    }

    async fn r2_metadata(
        &self,
        params: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<CallToolResult, ErrorData> {
        let binary_path = Self::s(params, "binary_path");
        let mode = Self::s(params, "mode");
        let mode = normalize_r2_metadata_mode(&mode)?;
        let session = self.session_for(&binary_path).await?;
        let result = self.r2_metadata_value(&session, mode, params).await?;

        if paginates_metadata(mode) {
            let offset = Self::opt_usize(params, "offset").unwrap_or(0);
            let limit = Self::opt_usize(params, "limit").unwrap_or(0);
            let (result, total_matched, returned, truncated) =
                paginate_with_counts(result, offset, limit);
            return Self::ok_json(serde_json::json!({
                "schema": "rbm.r2.metadata.v0",
                "binary_path": binary_path,
                "mode": mode,
                "offset": offset,
                "limit": limit,
                "total_matched": total_matched,
                "returned": returned,
                "truncated": truncated,
                "result": result,
            }));
        }

        Self::ok_json(serde_json::json!({
            "schema": "rbm.r2.metadata.v0",
            "binary_path": binary_path,
            "mode": mode,
            "result": result,
        }))
    }

    async fn r2_metadata_value(
        &self,
        session: &Arc<rbm_r2::Session>,
        mode: &str,
        params: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<Value, ErrorData> {
        match mode {
            "info" => rbm_r2::meta::info(session)
                .await
                .map_err(|e| err(e.to_string())),
            "headers" => rbm_r2::meta::rich_header(session)
                .await
                .map(|value| serde_json::json!(value))
                .map_err(|e| err(e.to_string())),
            "version_info" => rbm_r2::meta::version_info(session)
                .await
                .map(|value| serde_json::json!(value))
                .map_err(|e| err(e.to_string())),
            "entry_points" => rbm_r2::meta::entry_points(session)
                .await
                .map_err(|e| err(e.to_string())),
            "sections" => rbm_r2::format::sections(session)
                .await
                .map_err(|e| err(e.to_string())),
            "relocations" => rbm_r2::format::relocations(session)
                .await
                .map_err(|e| err(e.to_string())),
            "resources" => rbm_r2::format::resources(session)
                .await
                .map_err(|e| err(e.to_string())),
            "libraries" => rbm_r2::format::libraries(session)
                .await
                .map(|value| serde_json::json!(value))
                .map_err(|e| err(e.to_string())),
            "imports" => self.filtered_imports(session, params).await,
            "exports" => self.filtered_exports(session, params).await,
            "symbols" => self.filtered_symbols(session, params).await,
            "strings" => self.filtered_strings(session, params).await,
            "functions" => self.filtered_functions(session, params).await,
            _ => unreachable!("mode is normalized before dispatch"),
        }
    }

    async fn filtered_imports(
        &self,
        session: &Arc<rbm_r2::Session>,
        params: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<Value, ErrorData> {
        let value = rbm_r2::symbols::imports(session)
            .await
            .map_err(|e| err(e.to_string()))?;
        apply_name_filter(value, Self::opt_s(params, "filter")).map_err(|e| err(e.to_string()))
    }

    async fn filtered_exports(
        &self,
        session: &Arc<rbm_r2::Session>,
        params: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<Value, ErrorData> {
        let value = rbm_r2::symbols::exports(session)
            .await
            .map_err(|e| err(e.to_string()))?;
        apply_name_filter(value, Self::opt_s(params, "filter")).map_err(|e| err(e.to_string()))
    }

    async fn filtered_symbols(
        &self,
        session: &Arc<rbm_r2::Session>,
        params: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<Value, ErrorData> {
        let value = rbm_r2::symbols::symbols(session)
            .await
            .map_err(|e| err(e.to_string()))?;
        apply_name_filter(value, Self::opt_s(params, "filter")).map_err(|e| err(e.to_string()))
    }

    async fn filtered_functions(
        &self,
        session: &Arc<rbm_r2::Session>,
        params: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<Value, ErrorData> {
        let value = rbm_r2::disasm::functions(session)
            .await
            .map_err(|e| err(e.to_string()))?;
        apply_name_filter(value, Self::opt_s(params, "filter")).map_err(|e| err(e.to_string()))
    }

    async fn filtered_strings(
        &self,
        session: &Arc<rbm_r2::Session>,
        params: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<Value, ErrorData> {
        let min_length = Self::opt_usize(params, "min_length").unwrap_or(5);
        let all_sections = Self::opt_bool(params, "all_sections").unwrap_or(true);
        let value = if all_sections {
            rbm_r2::symbols::strings_all(session, min_length).await
        } else {
            rbm_r2::symbols::strings(session, min_length).await
        }
        .map_err(|e| err(e.to_string()))?;
        if let Some(pattern) = Self::opt_s(params, "filter").filter(|s| !s.is_empty()) {
            rbm_r2::symbols::filter_by_string_content(value, pattern)
                .map_err(|e| err(e.to_string()))
        } else {
            Ok(value)
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

fn paginate_with_counts(value: Value, offset: usize, limit: usize) -> (Value, usize, usize, bool) {
    let total = value.as_array().map_or(0, Vec::len);
    let paged = rbm_r2::filters::paginate(value, offset, limit);
    let returned = paged.as_array().map_or(0, Vec::len);
    let truncated = limit != 0 && total > offset.saturating_add(returned);
    (paged, total, returned, truncated)
}

fn paginates_metadata(mode: &str) -> bool {
    matches!(
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
    )
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
                    .and_then(serde_json::Value::as_bool),
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
    fn value_trace_schema_allows_memory_only_seed() {
        let tools = RbmServer::build_tools();
        let tool = tools
            .iter()
            .find(|tool| tool.name == "r2_value_trace")
            .expect("r2_value_trace tool");

        assert_eq!(
            tool.input_schema["required"],
            serde_json::json!(["binary_path", "start_addr"])
        );
        assert_eq!(
            tool.input_schema["properties"]["seed_register"]["type"],
            serde_json::json!("string")
        );
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
        let item = json!({"plt": 5_368_987_720_u64, "name": "CreateProcessA"});

        assert_eq!(find_xref_item_addr(&item), "0x140044048");
    }
}
