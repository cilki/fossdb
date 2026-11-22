//! Symbolic execution to discover reachable Linux x86_64 syscalls from a
//! binary's entry point.
//!
//! The analyzer is whole-program: it loads the main ELF and every shared
//! library reachable through DT_NEEDED, lays them out in disjoint virtual
//! address ranges, and walks instructions across them. PLT/GOT indirect jumps
//! are resolved statically by mapping each GOT slot to its imported symbol via
//! relocations and then to a defining module's export table.
//!
//! Conditional jumps fork the analysis to follow both paths. Each fork has its
//! own visited set so cycles within a fork terminate, but the same instruction
//! may be (re-)visited along distinct paths through the program.

use anyhow::{Result, anyhow};
use fossdb::{AnalysisFinding, FindingKind, FindingSeverity};
use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

/// Cap on total instructions executed across all forks. Whole-program analysis
/// of a libc-linked binary explores a lot of code, so this is generous.
const MAX_STEPS: usize = 5_000_000;
/// Cap on the number of fork events. Each conditional jump or call may add one.
const MAX_FORKS: usize = 200_000;
/// Cap on recursion depth (call nesting). Bounds stack usage.
const MAX_DEPTH: usize = 256;

#[derive(Default, Clone)]
struct RegisterState {
    /// The 16 general-purpose registers, in iced's RAX..=R15 order.
    gprs: [u64; 16],
    /// Current instruction pointer (absolute virtual address).
    rip: u64,
    stack: Vec<u64>,
}

impl RegisterState {
    /// Slot in `gprs` backing `register`, whatever its width. The legacy high
    /// byte registers (AH..BH) and anything that is not a GPR are untracked.
    fn slot(register: Register) -> Option<usize> {
        if matches!(
            register,
            Register::AH | Register::CH | Register::DH | Register::BH
        ) {
            return None;
        }
        (register.full_register() as usize)
            .checked_sub(Register::RAX as usize)
            .filter(|&i| i < 16)
    }

    fn set(&mut self, register: Register, value: u64) {
        if let Some(i) = Self::slot(register) {
            self.gprs[i] = value;
        }
    }

    fn get(&self, register: Register) -> u64 {
        Self::slot(register).map_or(0, |i| self.gprs[i])
    }
}

/// A syscall reached by the analyzer, captured at the point of the `syscall`
/// instruction.
#[derive(Debug, Clone, PartialEq)]
pub struct DiscoveredSyscall {
    pub address: u64,
    pub number: u64,
    pub name: &'static str,
    /// Linux x86_64 syscall ABI: rdi, rsi, rdx, r10, r8, r9.
    pub args: [u64; 6],
}

/// A whole-program address space: the main binary plus every loaded shared
/// library, with PLT/GOT bookkeeping wired up so indirect calls can be
/// resolved statically.
#[derive(Default)]
pub struct Program {
    /// Decoded instructions across every loaded module, keyed by their assigned
    /// virtual address.
    instructions: HashMap<u64, Instruction>,
    /// GOT entry virtual address -> imported symbol name. Populated from
    /// R_X86_64_JUMP_SLOT and R_X86_64_GLOB_DAT relocations.
    got_to_symbol: HashMap<u64, String>,
    /// Symbol name -> defining address. First module wins, mirroring ld.so.
    exports: HashMap<String, u64>,
    /// Entry point of the main binary in this address space.
    entry: u64,
    /// Names of modules we successfully loaded, for diagnostics.
    pub modules: Vec<String>,
    /// Names of dependencies we couldn't load (missing on disk, wrong arch...).
    pub missing_modules: Vec<String>,
}

impl Program {
    /// Build a program by loading `path` and walking its DT_NEEDED graph.
    /// Missing dependencies are recorded but don't fail the load.
    pub fn from_path(path: &Path) -> Result<Self> {
        let mut prog = Program::default();
        let mut next_dyn_base: u64 = 0x10_0000_0000;
        let mut seen: HashSet<PathBuf> = HashSet::new();
        let mut queue: Vec<(PathBuf, bool)> = vec![(path.to_path_buf(), true)];

        while let Some((p, is_main)) = queue.pop() {
            let canonical = p.canonicalize().unwrap_or_else(|_| p.clone());
            if !seen.insert(canonical.clone()) {
                continue;
            }
            let bytes = match std::fs::read(&p) {
                Ok(b) => b,
                Err(e) => {
                    prog.missing_modules.push(format!("{}: {}", p.display(), e));
                    continue;
                }
            };
            let elf = match goblin::elf::Elf::parse(&bytes) {
                Ok(e) => e,
                Err(e) => {
                    prog.missing_modules
                        .push(format!("{}: parse failed: {}", p.display(), e));
                    continue;
                }
            };
            if !elf.is_64 || elf.header.e_machine != goblin::elf::header::EM_X86_64 {
                prog.missing_modules
                    .push(format!("{}: not x86_64", p.display()));
                continue;
            }
            // ET_EXEC binaries use absolute addresses, so they must live at base 0.
            // ET_DYN modules (PIE main + every shared library) get a fresh slice
            // of high address space to avoid colliding with each other.
            let base = if elf.header.e_type == goblin::elf::header::ET_EXEC {
                0
            } else {
                let b = next_dyn_base;
                next_dyn_base = next_dyn_base
                    .checked_add(0x1_0000_0000)
                    .unwrap_or(next_dyn_base);
                b
            };

            if is_main {
                prog.entry = elf.entry.wrapping_add(base);
            }
            prog.load_module(&elf, &bytes, base);
            prog.modules.push(format!("{} @ 0x{:x}", p.display(), base));

            // Queue dependencies. Resolve via ldd if it can run, falling back to
            // standard search paths.
            let needed: Vec<String> = elf.libraries.iter().map(|s| s.to_string()).collect();
            let resolved = resolve_libraries(&p, &needed, &mut prog.missing_modules);
            for dep in resolved {
                queue.push((dep, false));
            }
        }

        if prog.instructions.is_empty() {
            return Err(anyhow!("no instructions decoded from {}", path.display()));
        }
        Ok(prog)
    }

    fn load_module(&mut self, elf: &goblin::elf::Elf, bytes: &[u8], base: u64) {
        // Decode every executable PROGBITS section.
        for sh in &elf.section_headers {
            if sh.sh_type != goblin::elf::section_header::SHT_PROGBITS {
                continue;
            }
            if sh.sh_flags & u64::from(goblin::elf::section_header::SHF_EXECINSTR) == 0 {
                continue;
            }
            let start = sh.sh_offset as usize;
            let size = sh.sh_size as usize;
            let end = match start.checked_add(size) {
                Some(e) if e <= bytes.len() => e,
                _ => continue,
            };
            self.decode(&bytes[start..end], sh.sh_addr.wrapping_add(base));
        }

        // Map GOT slots to imported symbol names.
        for reloc in elf
            .pltrelocs
            .iter()
            .chain(elf.dynrelas.iter())
            .chain(elf.dynrels.iter())
        {
            self.record_got_reloc(elf, base, reloc.r_type, reloc.r_sym, reloc.r_offset);
        }

        // Map exported (defined) symbol names to their address.
        for sym in elf.dynsyms.iter() {
            // SHN_UNDEF is 0; defined symbols have a non-zero section index and
            // a non-zero value (skip ABS/COMMON/etc. zero-valued entries).
            if sym.st_shndx == 0 || sym.st_value == 0 {
                continue;
            }
            if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                if !name.is_empty() {
                    self.exports
                        .entry(name.to_string())
                        .or_insert(sym.st_value.wrapping_add(base));
                }
            }
        }
    }

    /// Decode `code`, loaded at virtual address `va`, into `instructions`.
    fn decode(&mut self, code: &[u8], va: u64) {
        let mut decoder = Decoder::with_ip(64, code, va, DecoderOptions::NONE);
        let mut ins = Instruction::default();
        while decoder.can_decode() {
            decoder.decode_out(&mut ins);
            if !ins.is_invalid() {
                self.instructions.insert(ins.ip(), ins);
            }
        }
    }

    fn record_got_reloc(
        &mut self,
        elf: &goblin::elf::Elf,
        base: u64,
        r_type: u32,
        r_sym: usize,
        r_offset: u64,
    ) {
        // R_X86_64_GLOB_DAT = 6, R_X86_64_JUMP_SLOT = 7.
        if r_type != 6 && r_type != 7 {
            return;
        }
        let sym = match elf.dynsyms.get(r_sym) {
            Some(s) => s,
            None => return,
        };
        if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
            if !name.is_empty() {
                self.got_to_symbol
                    .insert(r_offset.wrapping_add(base), name.to_string());
            }
        }
    }

    /// Resolve a control-flow target. Direct branches use the immediate; an
    /// rip-relative memory operand (the shape of every PLT thunk) is resolved
    /// by mapping GOT slot -> symbol -> defining module.
    fn resolve_target(&self, ins: &Instruction) -> Option<u64> {
        match ins.op0_kind() {
            OpKind::NearBranch16 => Some(u64::from(ins.near_branch16())),
            OpKind::NearBranch32 => Some(u64::from(ins.near_branch32())),
            OpKind::NearBranch64 => Some(ins.near_branch64()),
            OpKind::Memory if ins.is_ip_rel_memory_operand() => {
                let got = ins.ip_rel_memory_address();
                let name = self.got_to_symbol.get(&got)?;
                self.exports.get(name).copied()
            }
            _ => None,
        }
    }
}

/// Whole-program syscall discovery: load the main binary and every reachable
/// shared library, then run symbolic execution across the unified address
/// space.
pub fn extract_syscalls_program(path: &Path) -> Result<Vec<DiscoveredSyscall>> {
    let prog = Program::from_path(path)?;
    Ok(run(&prog))
}

fn run(prog: &Program) -> Vec<DiscoveredSyscall> {
    let mut state = RegisterState {
        rip: prog.entry,
        ..Default::default()
    };
    let mut walk = Walk::new(prog);
    walk.emulate(&mut state, &mut HashSet::new(), 0);
    walk.syscalls
}

/// One analysis run: the program being walked, the syscalls found so far, and
/// the step and fork budgets that every fork draws from.
struct Walk<'a> {
    prog: &'a Program,
    syscalls: Vec<DiscoveredSyscall>,
    steps: usize,
    forks: usize,
}

impl<'a> Walk<'a> {
    fn new(prog: &'a Program) -> Self {
        Walk {
            prog,
            syscalls: Vec::new(),
            steps: 0,
            forks: 0,
        }
    }

    /// Explore `target` on copies of `state` and `visited`, unless the fork
    /// budget is spent.
    fn fork(&mut self, state: &RegisterState, visited: &HashSet<u64>, target: u64, depth: usize) {
        if self.forks >= MAX_FORKS {
            return;
        }
        self.forks += 1;
        let mut forked = state.clone();
        forked.rip = target;
        self.emulate(&mut forked, &mut visited.clone(), depth + 1);
    }

    fn emulate(&mut self, state: &mut RegisterState, visited: &mut HashSet<u64>, depth: usize) {
        if depth >= MAX_DEPTH {
            return;
        }
        loop {
            if self.steps >= MAX_STEPS {
                return;
            }
            self.steps += 1;

            if !visited.insert(state.rip) {
                return;
            }

            let ins = match self.prog.instructions.get(&state.rip) {
                Some(i) => *i,
                None => return,
            };
            state.rip = ins.next_ip();

            match ins.mnemonic() {
                m @ (Mnemonic::Mov
                | Mnemonic::Add
                | Mnemonic::Sub
                | Mnemonic::And
                | Mnemonic::Or
                | Mnemonic::Xor) => {
                    if ins.op_kind(0) != OpKind::Register {
                        continue;
                    }
                    let Some(src) = operand(&ins, 1, state) else {
                        continue;
                    };
                    let dst = ins.op_register(0);
                    let cur = state.get(dst);
                    let value = match m {
                        Mnemonic::Add => cur.wrapping_add(src),
                        Mnemonic::Sub => cur.wrapping_sub(src),
                        Mnemonic::And => cur & src,
                        Mnemonic::Or => cur | src,
                        Mnemonic::Xor => cur ^ src,
                        _ => src,
                    };
                    state.set(dst, value);
                }
                Mnemonic::Lea => {
                    if ins.op_kind(0) == OpKind::Register && ins.is_ip_rel_memory_operand() {
                        state.set(ins.op_register(0), ins.ip_rel_memory_address());
                    }
                }
                Mnemonic::Not => {
                    if ins.op_kind(0) == OpKind::Register {
                        let v = !state.get(ins.op_register(0));
                        state.set(ins.op_register(0), v);
                    }
                }
                Mnemonic::Push => {
                    if let Some(v) = operand(&ins, 0, state) {
                        state.stack.push(v);
                    }
                }
                Mnemonic::Pop => {
                    let v = state.stack.pop().unwrap_or(0);
                    if ins.op_kind(0) == OpKind::Register {
                        state.set(ins.op_register(0), v);
                    }
                }
                Mnemonic::Jmp => match self.prog.resolve_target(&ins) {
                    Some(target) => state.rip = target,
                    None => return,
                },
                Mnemonic::Je
                | Mnemonic::Jne
                | Mnemonic::Jl
                | Mnemonic::Jg
                | Mnemonic::Jle
                | Mnemonic::Jge
                | Mnemonic::Ja
                | Mnemonic::Jae
                | Mnemonic::Jb
                | Mnemonic::Jbe
                | Mnemonic::Js
                | Mnemonic::Jns
                | Mnemonic::Jp
                | Mnemonic::Jnp
                | Mnemonic::Jcxz
                | Mnemonic::Jecxz
                | Mnemonic::Jrcxz
                | Mnemonic::Loop
                | Mnemonic::Loope
                | Mnemonic::Loopne => {
                    if let Some(target) = self.prog.resolve_target(&ins) {
                        self.fork(state, visited, target, depth);
                    }
                    // Fall through with the current thread.
                }
                Mnemonic::Call => {
                    state.stack.push(ins.next_ip());
                    if let Some(target) = self.prog.resolve_target(&ins) {
                        if self.prog.instructions.contains_key(&target) {
                            self.fork(state, visited, target, depth);
                        }
                    }
                    let _ = state.stack.pop();
                }
                Mnemonic::Ret | Mnemonic::Hlt | Mnemonic::Ud2 => return,
                Mnemonic::Syscall => {
                    let number = state.get(Register::RAX);
                    let args = [
                        Register::RDI,
                        Register::RSI,
                        Register::RDX,
                        Register::R10,
                        Register::R8,
                        Register::R9,
                    ]
                    .map(|r| state.get(r));
                    self.syscalls.push(DiscoveredSyscall {
                        address: ins.ip(),
                        number,
                        name: syscall_name(number),
                        args,
                    });
                }
                _ => {
                    // Unmodeled instruction (or one with no effect on the
                    // tracked state, like cmp/test/nop): register state may
                    // now be stale, but we keep walking the control flow
                    // rather than aborting.
                }
            }
        }
    }
}

/// Value of operand `n` if it is a register or an immediate.
fn operand(ins: &Instruction, n: u32, state: &RegisterState) -> Option<u64> {
    match ins.op_kind(n) {
        OpKind::Register => Some(state.get(ins.op_register(n))),
        k if is_immediate(k) => Some(ins.immediate(n)),
        _ => None,
    }
}

fn is_immediate(kind: OpKind) -> bool {
    matches!(
        kind,
        OpKind::Immediate8
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate32to64
            | OpKind::Immediate64
    )
}

/// Resolve the on-disk paths of a binary's dependencies. Tries `ldd` first
/// (which honors ld.so.cache, RPATH, LD_LIBRARY_PATH), then falls back to
/// scanning standard library directories using DT_NEEDED soname matches.
fn resolve_libraries(binary: &Path, needed: &[String], missing: &mut Vec<String>) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = Vec::new();
    let mut found_names: HashSet<String> = HashSet::new();

    if let Ok(out) = std::process::Command::new("ldd").arg(binary).output() {
        if out.status.success() {
            for line in String::from_utf8_lossy(&out.stdout).lines() {
                if let Some(path) = parse_ldd_line(line) {
                    if path.exists() {
                        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                            found_names.insert(name.to_string());
                        }
                        found.push(path);
                    }
                }
            }
        }
    }

    // Fall back to fixed search paths for any DT_NEEDED soname ldd didn't give us.
    let search_dirs = [
        "/lib/x86_64-linux-gnu",
        "/usr/lib/x86_64-linux-gnu",
        "/lib64",
        "/usr/lib64",
        "/lib",
        "/usr/lib",
    ];
    for soname in needed {
        if found_names.contains(soname.as_str()) {
            continue;
        }
        let mut hit = false;
        for dir in &search_dirs {
            let candidate = PathBuf::from(dir).join(soname);
            if candidate.exists() {
                found.push(candidate);
                found_names.insert(soname.clone());
                hit = true;
                break;
            }
        }
        if !hit {
            missing.push(format!("could not resolve dependency: {}", soname));
        }
    }
    found
}

fn parse_ldd_line(line: &str) -> Option<PathBuf> {
    let trimmed = line.trim();
    // Two shapes:
    //   "soname => /abs/path (0x...)"
    //   "/abs/path (0x...)"  — typically the dynamic linker
    if let Some(idx) = trimmed.find(" => ") {
        let after = &trimmed[idx + 4..];
        let end = after.find(" (").unwrap_or(after.len());
        let p = after[..end].trim();
        if p == "not found" || p.is_empty() {
            return None;
        }
        return Some(PathBuf::from(p));
    }
    if trimmed.starts_with('/') {
        let end = trimmed.find(" (").unwrap_or(trimmed.len());
        return Some(PathBuf::from(trimmed[..end].trim()));
    }
    None
}

/// Translate a Linux x86_64 syscall number into its name. Anything unknown
/// maps to `"unknown"`.
fn syscall_name(n: u64) -> &'static str {
    match n {
        0 => "read",
        1 => "write",
        2 => "open",
        3 => "close",
        4 => "stat",
        5 => "fstat",
        6 => "lstat",
        7 => "poll",
        8 => "lseek",
        9 => "mmap",
        10 => "mprotect",
        11 => "munmap",
        12 => "brk",
        13 => "rt_sigaction",
        14 => "rt_sigprocmask",
        15 => "rt_sigreturn",
        16 => "ioctl",
        17 => "pread64",
        18 => "pwrite64",
        19 => "readv",
        20 => "writev",
        21 => "access",
        22 => "pipe",
        23 => "select",
        24 => "sched_yield",
        25 => "mremap",
        26 => "msync",
        28 => "madvise",
        32 => "dup",
        33 => "dup2",
        35 => "nanosleep",
        37 => "alarm",
        39 => "getpid",
        41 => "socket",
        42 => "connect",
        43 => "accept",
        44 => "sendto",
        45 => "recvfrom",
        46 => "sendmsg",
        47 => "recvmsg",
        48 => "shutdown",
        49 => "bind",
        50 => "listen",
        56 => "clone",
        57 => "fork",
        58 => "vfork",
        59 => "execve",
        60 => "exit",
        61 => "wait4",
        62 => "kill",
        63 => "uname",
        72 => "fcntl",
        73 => "flock",
        74 => "fsync",
        78 => "getdents",
        79 => "getcwd",
        80 => "chdir",
        82 => "rename",
        83 => "mkdir",
        84 => "rmdir",
        85 => "creat",
        86 => "link",
        87 => "unlink",
        89 => "readlink",
        90 => "chmod",
        92 => "chown",
        96 => "gettimeofday",
        102 => "getuid",
        104 => "getgid",
        105 => "setuid",
        106 => "setgid",
        107 => "geteuid",
        108 => "getegid",
        110 => "getppid",
        158 => "arch_prctl",
        186 => "gettid",
        202 => "futex",
        217 => "getdents64",
        218 => "set_tid_address",
        228 => "clock_gettime",
        230 => "clock_nanosleep",
        231 => "exit_group",
        257 => "openat",
        262 => "newfstatat",
        263 => "unlinkat",
        273 => "set_robust_list",
        302 => "prlimit64",
        318 => "getrandom",
        322 => "execveat",
        334 => "rseq",
        435 => "clone3",
        _ => "unknown",
    }
}

/// Convert discovered syscalls into analysis findings.
pub fn syscalls_to_findings(
    syscalls: &[DiscoveredSyscall],
    location: &str,
) -> Vec<AnalysisFinding> {
    let mut seen: HashMap<u64, &DiscoveredSyscall> = HashMap::new();
    for sc in syscalls {
        seen.entry(sc.number).or_insert(sc);
    }

    let mut findings = Vec::new();
    if seen.is_empty() {
        return findings;
    }

    let mut numbers: Vec<&DiscoveredSyscall> = seen.values().copied().collect();
    numbers.sort_by_key(|s| s.number);

    let summary = numbers
        .iter()
        .map(|s| format!("{}({})", s.name, s.number))
        .collect::<Vec<_>>()
        .join(", ");

    findings.push(AnalysisFinding {
        kind: FindingKind::SyscallReachable,
        severity: FindingSeverity::Info,
        description: format!("Reachable syscalls ({}): {}", numbers.len(), summary),
        location: Some(location.to_string()),
    });

    for sc in &numbers {
        let severity = match sc.name {
            "execve" | "execveat" | "ptrace" => Some(FindingSeverity::Medium),
            "socket" | "connect" | "bind" | "sendto" | "sendmsg" => Some(FindingSeverity::Low),
            _ => None,
        };
        if let Some(sev) = severity {
            findings.push(AnalysisFinding {
                kind: FindingKind::SyscallReachable,
                severity: sev,
                description: format!(
                    "Reachable syscall {} (#{}) at 0x{:x} args=[0x{:x}, 0x{:x}, 0x{:x}, 0x{:x}, 0x{:x}, 0x{:x}]",
                    sc.name,
                    sc.number,
                    sc.address,
                    sc.args[0],
                    sc.args[1],
                    sc.args[2],
                    sc.args[3],
                    sc.args[4],
                    sc.args[5],
                ),
                location: Some(location.to_string()),
            });
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use iced_x86::code_asm::*;

    fn run_assembled(mut a: CodeAssembler, state: &mut RegisterState) -> Vec<DiscoveredSyscall> {
        let bytes = a.assemble(0x1000).unwrap();
        let mut prog = Program::default();
        prog.decode(&bytes, 0x1000);
        state.rip = 0x1000;
        let mut walk = Walk::new(&prog);
        walk.emulate(state, &mut HashSet::new(), 0);
        walk.syscalls
    }

    #[test]
    fn mov_register_and_immediate() {
        let mut a = CodeAssembler::new(64).unwrap();
        a.mov(rax, rbx).unwrap();
        a.mov(rbx, 0x100u64).unwrap();
        let mut state = RegisterState::default();
        state.set(Register::RAX, 0x1337);
        state.set(Register::RBX, 0x890);
        run_assembled(a, &mut state);
        assert_eq!(state.get(Register::RAX), 0x890);
        assert_eq!(state.get(Register::RBX), 0x100);
    }

    #[test]
    fn alu_ops_on_partial_registers_track_the_full_register() {
        let mut a = CodeAssembler::new(64).unwrap();
        a.mov(eax, 0x40u32).unwrap();
        a.add(rax, 0x0fi32).unwrap();
        a.sub(eax, 0x02u32).unwrap();
        a.and(rax, 0x3fi32).unwrap(); // 0x0d
        a.mov(rcx, 0x30u64).unwrap();
        a.or(rax, rcx).unwrap(); // 0x3d
        a.xor(edi, edi).unwrap();
        a.push(rax).unwrap();
        a.pop(rsi).unwrap();
        a.syscall().unwrap();
        let mut state = RegisterState::default();
        state.set(Register::RDI, 0xdead);
        let syscalls = run_assembled(a, &mut state);
        assert_eq!(syscalls.len(), 1);
        assert_eq!(syscalls[0].number, 61);
        assert_eq!(syscalls[0].name, "wait4");
        assert_eq!(syscalls[0].args[0], 0);
        assert_eq!(syscalls[0].args[1], 61);
    }

    #[test]
    fn syscall_close_recorded() {
        let mut a = CodeAssembler::new(64).unwrap();
        a.mov(rax, 3u64).unwrap();
        a.mov(rdi, 7u64).unwrap();
        a.syscall().unwrap();
        let mut state = RegisterState::default();
        let syscalls = run_assembled(a, &mut state);
        assert_eq!(syscalls.len(), 1);
        assert_eq!(syscalls[0].number, 3);
        assert_eq!(syscalls[0].name, "close");
        assert_eq!(syscalls[0].args[0], 7);
    }

    #[test]
    fn conditional_jump_explores_both_paths() {
        let mut a = CodeAssembler::new(64).unwrap();
        let mut taken = a.create_label();
        let mut done = a.create_label();
        a.mov(rax, 1u64).unwrap();
        a.test(rbx, rbx).unwrap();
        a.je(taken).unwrap();
        a.syscall().unwrap();
        a.jmp(done).unwrap();
        a.set_label(&mut taken).unwrap();
        a.mov(rax, 60u64).unwrap();
        a.syscall().unwrap();
        a.set_label(&mut done).unwrap();
        a.nop().unwrap();
        let mut state = RegisterState::default();
        let syscalls = run_assembled(a, &mut state);
        let names: Vec<_> = syscalls.iter().map(|s| s.name).collect();
        assert!(names.contains(&"write"), "names = {:?}", names);
        assert!(names.contains(&"exit"), "names = {:?}", names);
    }

    #[test]
    fn loop_terminates_via_visited_set() {
        let mut a = CodeAssembler::new(64).unwrap();
        let mut top = a.create_label();
        a.set_label(&mut top).unwrap();
        a.mov(rax, 39u64).unwrap();
        a.syscall().unwrap();
        a.jmp(top).unwrap();
        let mut state = RegisterState::default();
        let syscalls = run_assembled(a, &mut state);
        assert_eq!(syscalls.len(), 1);
        assert_eq!(syscalls[0].name, "getpid");
    }

    /// Parse one strace line into a syscall name. Handles `[pid N] name(...)`,
    /// plain `name(...)`, `<... name resumed>`, and skips status/signal lines.
    fn parse_strace_syscall_name(line: &str) -> Option<String> {
        let trimmed = line.trim_start();
        let rest = if let Some(stripped) = trimmed.strip_prefix('[') {
            let close = stripped.find(']')?;
            stripped[close + 1..].trim_start()
        } else {
            trimmed
        };
        if rest.is_empty()
            || rest.starts_with("+++")
            || rest.starts_with("---")
            || rest.starts_with("???")
        {
            return None;
        }
        if let Some(after) = rest.strip_prefix("<... ") {
            let end = after.find(" resumed")?;
            return Some(after[..end].trim().to_string());
        }
        let paren = rest.find('(')?;
        let name = rest[..paren].trim();
        let first = name.chars().next()?;
        if !(first.is_ascii_alphabetic() || first == '_') {
            return None;
        }
        if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return None;
        }
        Some(name.to_string())
    }

    /// Run whole-program symbolic analysis on the bundled `tests/md5sum` and
    /// require every syscall observed by `strace` to appear in the reachable
    /// set. Skips when strace or the binary cannot run in this environment.
    #[test]
    #[cfg(target_os = "linux")]
    fn md5sum_strace_subset_of_reachable() {
        use std::collections::HashSet;
        use std::process::Command;

        let bin_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("md5sum");
        if !bin_path.exists() {
            eprintln!("skipping: {} not found", bin_path.display());
            return;
        }
        if Command::new("strace").arg("--version").output().is_err() {
            eprintln!("skipping: strace not available on PATH");
            return;
        }

        // Confirm we can actually execute md5sum here. NixOS, for instance,
        // can't run a generic-Linux ELF without a patched interpreter.
        match Command::new(&bin_path).arg("--help").output() {
            Ok(o) if o.status.success() => {}
            Ok(o) => {
                eprintln!(
                    "skipping: cannot execute {}: status={:?} stderr={}",
                    bin_path.display(),
                    o.status,
                    String::from_utf8_lossy(&o.stderr).trim()
                );
                return;
            }
            Err(e) => {
                eprintln!("skipping: cannot launch {}: {}", bin_path.display(), e);
                return;
            }
        }

        // Whole-program static analysis (main + libc + ld + ...).
        let discovered = extract_syscalls_program(&bin_path).expect("symbolic execution failed");
        let reachable: HashSet<&'static str> = discovered.iter().map(|s| s.name).collect();
        eprintln!(
            "symbolic analysis discovered {} syscall sites, {} unique names",
            discovered.len(),
            reachable.len()
        );

        let strace_log = tempfile::NamedTempFile::new().expect("tempfile");
        let out = Command::new("strace")
            .args(["-f", "-qq", "-o"])
            .arg(strace_log.path())
            .arg(&bin_path)
            .arg("--help")
            .output()
            .expect("invoke strace");
        assert!(
            out.status.success(),
            "strace did not exit cleanly: status={:?} stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );

        let log = std::fs::read_to_string(strace_log.path()).expect("read strace log");
        let observed: HashSet<String> = log.lines().filter_map(parse_strace_syscall_name).collect();
        assert!(!observed.is_empty(), "strace produced no syscall lines");

        let missing: Vec<&String> = observed
            .iter()
            .filter(|name| !reachable.contains(name.as_str()))
            .collect();

        assert!(
            missing.is_empty(),
            "syscalls observed by strace but not statically reachable: {:?}\n\
             reachable ({} unique): {:?}",
            missing,
            reachable.len(),
            reachable
        );
    }
}
