/// UFunction call tracing and property change detection
///
/// ProcessEvent をフックして全 UFunction 呼び出しをキャプチャし、
/// プロパティのポーリングで変数変更を自動検出する。

use super::inject::{allocate_remote, free_remote, read_remote, write_remote, write_executable};
use super::structures::{UObject, UStruct};
use super::{EngineError, Result, UnrealEngine};
use crate::engine::types::*;
use crate::platform::windows::read_process_memory;
use std::collections::{HashMap, VecDeque};
use std::time::Instant;
use windows::Win32::Foundation::HANDLE as WinHandle;

// ============================================
// トレースイベント型
// ============================================

/// UFunction 呼び出しイベント
#[derive(Clone, Debug)]
pub struct FunctionCallEvent {
    /// イベント発生からの経過秒
    pub elapsed_secs: f64,
    /// 呼び出し元インスタンスのアドレス
    pub instance_addr: usize,
    /// UFunction のアドレス
    pub function_addr: usize,
    /// 解決済み関数名（遅延解決）
    pub function_name: String,
    /// 呼び出し元クラス名
    pub class_name: String,
    /// パラメータのスナップショット（生バイト）
    pub params_snapshot: Vec<u8>,
}

/// プロパティ変更イベント
#[derive(Clone, Debug)]
pub struct PropertyChangeEvent {
    /// イベント発生からの経過秒
    pub elapsed_secs: f64,
    /// インスタンスのアドレス
    pub instance_addr: usize,
    /// フィールド名
    pub field_name: String,
    /// クラス名
    pub class_name: String,
    /// 変更前の値
    pub old_value: String,
    /// 変更後の値
    pub new_value: String,
}

/// 統一トレースイベント
#[derive(Clone, Debug)]
pub enum TraceEvent {
    FunctionCall(FunctionCallEvent),
    PropertyChange(PropertyChangeEvent),
}

impl TraceEvent {
    pub fn elapsed_secs(&self) -> f64 {
        match self {
            TraceEvent::FunctionCall(e) => e.elapsed_secs,
            TraceEvent::PropertyChange(e) => e.elapsed_secs,
        }
    }
}

// ============================================
// トレース対象
// ============================================

#[derive(Clone, Debug)]
pub struct TraceTarget {
    pub instance: InstanceHandle,
    pub class: ClassHandle,
    pub class_name: String,
    pub trace_functions: bool,
    pub trace_properties: bool,
    /// 関数名フィルタ（空なら全関数）
    pub function_filter: String,
}

// ============================================
// トレース統計
// ============================================

#[derive(Clone, Debug, Default)]
pub struct TraceStats {
    pub total_function_calls: u64,
    pub total_property_changes: u64,
    pub unique_functions: usize,
    pub calls_per_sec: f64,
}

// ============================================
// リングバッファレイアウト（リモートプロセス内）
// ============================================

/// ヘッダーサイズ: 0x100 (256バイト)
const RING_HEADER_SIZE: usize = 0x100;
/// バッファ全体サイズ: 1MB
const RING_BUFFER_TOTAL: usize = 1024 * 1024;
/// データ領域サイズ
const RING_DATA_SIZE: usize = RING_BUFFER_TOTAL - RING_HEADER_SIZE;
/// 1エントリのサイズ（固定）
const RING_ENTRY_SIZE: usize = 40; // timestamp(8) + instance(8) + function(8) + params_addr(8) + params_size(4) + padding(4)

/// リングバッファヘッダー（リモートプロセスのメモリレイアウト）
/// Offset 0x00: write_index (u64) - フックが書き込む次のエントリインデックス
/// Offset 0x08: read_index  (u64) - LightScanが読み取った最後のインデックス
/// Offset 0x10: total_count (u64) - 総書き込みエントリ数
/// Offset 0x18: flags       (u64) - bit 0: active, bit 1: overflow
/// Offset 0x20: spinlock    (u64) - スピンロック
/// Offset 0x28: trampoline  (u64) - 元のProcessEventトランポリンアドレス
/// Offset 0x30: max_entries (u64) - 最大エントリ数
/// Offset 0x38: target_instance (u64) - フィルタ: 0なら全インスタンス記録

// ============================================
// 簡易 x64 命令長デコーダー（トランポリン用）
// ============================================

/// x64 命令の長さを計算する簡易デコーダー
///
/// フックで上書きする最低バイト数（14バイト）以上の命令境界を見つけるために使用。
/// 全命令をカバーしてはいないが、UE の ProcessEvent プロローグに出現する
/// 一般的な命令は処理できる。
fn x64_instruction_length(code: &[u8]) -> Option<usize> {
    if code.is_empty() {
        return None;
    }

    let mut i = 0;

    // プレフィックス
    let mut rex = 0u8;
    let mut has_operand_size = false;

    // Legacy prefixes
    loop {
        if i >= code.len() {
            return None;
        }
        match code[i] {
            0x66 => { has_operand_size = true; i += 1; }
            0x67 | 0xF0 | 0xF2 | 0xF3 | 0x2E | 0x3E | 0x26 | 0x36 | 0x64 | 0x65 => { i += 1; }
            _ => break,
        }
    }

    // REX prefix
    if i < code.len() && (code[i] & 0xF0) == 0x40 {
        rex = code[i];
        i += 1;
    }

    if i >= code.len() {
        return None;
    }

    let opcode = code[i];
    i += 1;

    // 2-byte opcode (0F xx)
    if opcode == 0x0F {
        if i >= code.len() {
            return None;
        }
        let op2 = code[i];
        i += 1;

        match op2 {
            // Jcc rel32 (0F 80..8F)
            0x80..=0x8F => return Some(i + 4),
            // movzx, movsx
            0xB6 | 0xB7 | 0xBE | 0xBF => {
                // ModRM + possible displacement
                if i >= code.len() { return None; }
                return Some(i + modrm_length(&code[i..])?);
            }
            // NOP with ModRM (0F 1F)
            0x1F => {
                if i >= code.len() { return None; }
                return Some(i + modrm_length(&code[i..])?);
            }
            // CMOV
            0x40..=0x4F => {
                if i >= code.len() { return None; }
                return Some(i + modrm_length(&code[i..])?);
            }
            // SSE (movaps, movups, etc.)
            0x10 | 0x11 | 0x28 | 0x29 | 0x2E | 0x2F | 0x57 | 0x54 => {
                if i >= code.len() { return None; }
                return Some(i + modrm_length(&code[i..])?);
            }
            _ => return None, // 未知の2バイトオペコード
        }
    }

    match opcode {
        // NOP
        0x90 => Some(i),
        // INT3
        0xCC => Some(i),
        // RET
        0xC3 => Some(i),
        // RET imm16
        0xC2 => Some(i + 2),
        // PUSH reg (50-57)
        0x50..=0x57 => Some(i),
        // POP reg (58-5F)
        0x58..=0x5F => Some(i),
        // MOV reg, imm64 (B8-BF with REX.W)
        0xB8..=0xBF if rex & 0x08 != 0 => Some(i + 8),
        // MOV reg, imm32 (B8-BF without REX.W)
        0xB8..=0xBF => Some(i + 4),
        // MOV r/m, r (89) or MOV r, r/m (8B)
        0x89 | 0x8B => {
            if i >= code.len() { return None; }
            Some(i + modrm_length(&code[i..])?)
        }
        // LEA (8D)
        0x8D => {
            if i >= code.len() { return None; }
            Some(i + modrm_length(&code[i..])?)
        }
        // SUB r/m, imm32 (81 /5), ADD r/m, imm32 (81 /0), CMP r/m, imm32 (81 /7)
        0x81 => {
            if i >= code.len() { return None; }
            Some(i + modrm_length(&code[i..])? + 4)
        }
        // SUB r/m, imm8 (83 /5), ADD r/m, imm8 (83 /0), CMP r/m, imm8 (83 /7)
        0x83 => {
            if i >= code.len() { return None; }
            Some(i + modrm_length(&code[i..])? + 1)
        }
        // TEST r/m, r (85)
        0x85 => {
            if i >= code.len() { return None; }
            Some(i + modrm_length(&code[i..])?)
        }
        // XOR r/m, r (31 or 33)
        0x31 | 0x33 => {
            if i >= code.len() { return None; }
            Some(i + modrm_length(&code[i..])?)
        }
        // AND r/m, r (21, 23)
        0x21 | 0x23 => {
            if i >= code.len() { return None; }
            Some(i + modrm_length(&code[i..])?)
        }
        // OR r/m, r (09, 0B)
        0x09 | 0x0B => {
            if i >= code.len() { return None; }
            Some(i + modrm_length(&code[i..])?)
        }
        // ADD r/m, r (01, 03)
        0x01 | 0x03 => {
            if i >= code.len() { return None; }
            Some(i + modrm_length(&code[i..])?)
        }
        // SUB r/m, r (29, 2B)
        0x29 | 0x2B => {
            if i >= code.len() { return None; }
            Some(i + modrm_length(&code[i..])?)
        }
        // CMP r/m, r (39, 3B)
        0x39 | 0x3B => {
            if i >= code.len() { return None; }
            Some(i + modrm_length(&code[i..])?)
        }
        // CALL rel32 (E8)
        0xE8 => Some(i + 4),
        // JMP rel32 (E9)
        0xE9 => Some(i + 4),
        // JMP rel8 (EB)
        0xEB => Some(i + 1),
        // Jcc rel8 (70-7F)
        0x70..=0x7F => Some(i + 1),
        // MOV r/m, imm32 (C7 /0)
        0xC7 => {
            if i >= code.len() { return None; }
            Some(i + modrm_length(&code[i..])? + 4)
        }
        // MOV r/m8, imm8 (C6 /0)
        0xC6 => {
            if i >= code.len() { return None; }
            Some(i + modrm_length(&code[i..])? + 1)
        }
        // FF group (INC/DEC/CALL/JMP/PUSH r/m)
        0xFF => {
            if i >= code.len() { return None; }
            Some(i + modrm_length(&code[i..])?)
        }
        // INC r/m (FE, FF — handled above for FF)
        0xFE => {
            if i >= code.len() { return None; }
            Some(i + modrm_length(&code[i..])?)
        }
        _ => None,
    }
}

/// ModRM バイトから、ModRM + SIB + displacement の合計長を返す
fn modrm_length(code: &[u8]) -> Option<usize> {
    if code.is_empty() {
        return None;
    }

    let modrm = code[0];
    let mod_bits = (modrm >> 6) & 0x03;
    let rm = modrm & 0x07;

    let mut len = 1; // ModRM 自身

    match mod_bits {
        0b11 => {
            // レジスタ直接 — 追加なし
        }
        0b00 => {
            if rm == 0b100 {
                // SIB バイトあり
                if code.len() < 2 { return None; }
                len += 1;
                let sib = code[1];
                let base = sib & 0x07;
                if base == 0b101 {
                    len += 4; // disp32
                }
            } else if rm == 0b101 {
                len += 4; // RIP-relative (disp32)
            }
        }
        0b01 => {
            if rm == 0b100 {
                len += 1; // SIB
            }
            len += 1; // disp8
        }
        0b10 => {
            if rm == 0b100 {
                len += 1; // SIB
            }
            len += 4; // disp32
        }
        _ => unreachable!(),
    }

    Some(len)
}

/// 命令列をデコードして、min_bytes 以上の命令境界を返す
/// 成功時: (コピーすべきバイト数, RIP相対命令のリスト)
/// RIP相対命令: (命令先頭からのオフセット, 命令長, disp32のオフセット)
fn find_instruction_boundary(code: &[u8], min_bytes: usize) -> Option<(usize, Vec<RipRelativeInfo>)> {
    let mut offset = 0;
    let mut rip_relatives = Vec::new();

    while offset < min_bytes {
        let remaining = &code[offset..];
        let len = x64_instruction_length(remaining)?;

        // RIP相対命令を検出
        if let Some(rip_info) = detect_rip_relative(remaining, len, offset) {
            rip_relatives.push(rip_info);
        }

        offset += len;
    }

    Some((offset, rip_relatives))
}

/// RIP相対命令の情報
struct RipRelativeInfo {
    /// 命令の開始オフセット（元のコード先頭から）
    instruction_offset: usize,
    /// 命令の長さ
    instruction_length: usize,
    /// disp32 フィールドの位置（元のコード先頭から）
    disp32_offset: usize,
}

/// RIP相対命令を検出する
fn detect_rip_relative(instruction: &[u8], inst_len: usize, base_offset: usize) -> Option<RipRelativeInfo> {
    let mut i = 0;

    // プレフィックスをスキップ
    while i < instruction.len() {
        match instruction[i] {
            0x66 | 0x67 | 0xF0 | 0xF2 | 0xF3 | 0x2E | 0x3E | 0x26 | 0x36 | 0x64 | 0x65 => { i += 1; }
            _ => break,
        }
    }

    // REX
    if i < instruction.len() && (instruction[i] & 0xF0) == 0x40 {
        i += 1;
    }

    if i >= instruction.len() {
        return None;
    }

    let opcode = instruction[i];
    i += 1;

    // CALL rel32 (E8) or JMP rel32 (E9)
    if opcode == 0xE8 || opcode == 0xE9 {
        return Some(RipRelativeInfo {
            instruction_offset: base_offset,
            instruction_length: inst_len,
            disp32_offset: base_offset + i,
        });
    }

    // 2-byte opcode (0F xx)
    let has_modrm = if opcode == 0x0F {
        if i >= instruction.len() { return None; }
        i += 1; // skip op2
        true
    } else {
        // ModRM を持つ 1-byte opcode
        matches!(opcode, 0x89 | 0x8B | 0x8D | 0x81 | 0x83 | 0x85 | 0x31 | 0x33 |
                        0x21 | 0x23 | 0x09 | 0x0B | 0x01 | 0x03 | 0x29 | 0x2B |
                        0x39 | 0x3B | 0xC7 | 0xC6 | 0xFF | 0xFE)
    };

    if has_modrm && i < instruction.len() {
        let modrm = instruction[i];
        let mod_bits = (modrm >> 6) & 0x03;
        let rm = modrm & 0x07;

        // mod=00, rm=101 → RIP-relative
        if mod_bits == 0b00 && rm == 0b101 {
            return Some(RipRelativeInfo {
                instruction_offset: base_offset,
                instruction_length: inst_len,
                disp32_offset: base_offset + i + 1, // disp32 は ModRM の直後
            });
        }
    }

    None
}

/// トランポリンコードを生成（RIP相対命令のリロケーション付き）
///
/// original_addr: 元のコードのアドレス
/// trampoline_addr: トランポリンの配置先アドレス
/// code: コピーするバイト列
/// copy_size: コピーサイズ
/// rip_relatives: RIP相対命令の情報
/// jump_back_addr: トランポリン終了後のジャンプ先
fn build_trampoline(
    original_addr: usize,
    trampoline_addr: usize,
    code: &[u8],
    copy_size: usize,
    rip_relatives: &[RipRelativeInfo],
    jump_back_addr: usize,
) -> Vec<u8> {
    let mut trampoline = code[..copy_size].to_vec();

    // RIP相対命令をリロケーション
    for rip in rip_relatives {
        let disp_local = rip.disp32_offset;
        if disp_local + 4 > trampoline.len() {
            continue;
        }

        let original_disp = i32::from_le_bytes(
            trampoline[disp_local..disp_local + 4].try_into().unwrap(),
        );

        // 元のRIP = original_addr + instruction_offset + instruction_length
        let original_rip = original_addr + rip.instruction_offset + rip.instruction_length;
        // 新しいRIP = trampoline_addr + instruction_offset + instruction_length
        let new_rip = trampoline_addr + rip.instruction_offset + rip.instruction_length;

        // 元のターゲット = original_rip + original_disp
        let target = (original_rip as i64) + (original_disp as i64);
        // 新しいdisp = target - new_rip
        let new_disp = target - (new_rip as i64);

        if new_disp < i32::MIN as i64 || new_disp > i32::MAX as i64 {
            tracing::warn!(
                "RIP-relative relocation overflow at offset 0x{:X}: target=0x{:X}",
                rip.instruction_offset,
                target
            );
            continue;
        }

        trampoline[disp_local..disp_local + 4].copy_from_slice(&(new_disp as i32).to_le_bytes());
        tracing::debug!(
            "Relocated RIP-relative at +0x{:X}: disp {} -> {}",
            rip.instruction_offset,
            original_disp,
            new_disp as i32
        );
    }

    // JMP back: FF 25 00 00 00 00 [8-byte addr]
    trampoline.extend_from_slice(&[0xFF, 0x25, 0x00, 0x00, 0x00, 0x00]);
    trampoline.extend_from_slice(&jump_back_addr.to_le_bytes());

    trampoline
}

// ============================================
// ProcessEvent フック用シェルコード生成
// ============================================

/// ProcessEventフック用のx64シェルコードを生成
///
/// ProcessEvent の呼び出し規約: void ProcessEvent(UObject* this, UFunction* func, void* params)
/// Windows x64 ABI: this=RCX, func=RDX, params=R8
///
/// スタックレイアウト（エントリ時 RSP は 8 mod 16 = call 直後）:
///   push rbp          → RSP = 0 mod 16
///   push rbx..r15 (8) → RSP = 0 mod 16 (偶数 push)
///   sub rsp, 0x80     → XMM退避(0x40) + QPC出力(0x08) + shadow(0x20) + padding(0x18)
///
/// トランポリンアドレスは buffer_addr + 0x28 に格納し、シェルコード内で読み出す。
/// これにより、シェルコードをフックインストール前に完成させられる。
pub fn generate_trace_shellcode(
    buffer_addr: usize,
    qpc_addr: usize,
    target_instance: usize, // 0 なら全インスタンス記録
) -> Vec<u8> {
    let mut code: Vec<u8> = Vec::with_capacity(512);

    // 後でパッチが必要な jz/jne のオフセットを記録
    let mut jz_patch_offset: usize = 0;
    let mut jne_patch_offset: Option<usize> = None;

    // ===== プロローグ =====
    // エントリ時: caller の `call ProcessEvent` → JMP でここに来る
    //   RSP には caller の戻りアドレスが積まれている (RSP = 8 mod 16)
    //
    // 元の RSP を保存して、自分のフレームを作る
    // push rbp           → RSP -= 8  (0 mod 16)
    // mov rbp, rsp
    // sub rsp, 0xC0      → ローカル領域確保
    //
    // ローカル領域レイアウト (0xC0 = 192 bytes):
    //   [rsp+0x00..0x1F] shadow space for sub-calls (32 bytes)
    //   [rsp+0x20..0x27] QPC output (8 bytes)
    //   [rsp+0x28..0x2F] saved RCX (8 bytes)
    //   [rsp+0x30..0x37] saved RDX (8 bytes)
    //   [rsp+0x38..0x3F] saved R8  (8 bytes)
    //   [rsp+0x40..0x4F] saved XMM0 (16 bytes)
    //   [rsp+0x50..0x5F] saved XMM1 (16 bytes)
    //   [rsp+0x60..0x6F] saved XMM2 (16 bytes)
    //   [rsp+0x70..0x7F] saved XMM3 (16 bytes)
    //   [rsp+0x80..0x87] saved RBX (8 bytes)
    //   [rsp+0x88..0x8F] saved RSI (8 bytes)
    //   [rsp+0x90..0x97] saved RDI (8 bytes)
    //   [rsp+0x98..0xBF] unused padding

    code.push(0x55); // push rbp
    code.extend_from_slice(&[0x48, 0x89, 0xE5]); // mov rbp, rsp
    code.extend_from_slice(&[0x48, 0x81, 0xEC, 0xC0, 0x00, 0x00, 0x00]); // sub rsp, 0xC0

    // 引数を退避（スタックへ — 非volatile レジスタは使わず安全に）
    // mov [rsp+0x28], rcx (this/instance)
    code.extend_from_slice(&[0x48, 0x89, 0x4C, 0x24, 0x28]);
    // mov [rsp+0x30], rdx (UFunction*)
    code.extend_from_slice(&[0x48, 0x89, 0x54, 0x24, 0x30]);
    // mov [rsp+0x38], r8  (params)
    code.extend_from_slice(&[0x4C, 0x89, 0x44, 0x24, 0x38]);

    // 非volatile レジスタ退避（最小限: rbx, rsi, rdi のみ使用）
    // mov [rsp+0x80], rbx
    code.extend_from_slice(&[0x48, 0x89, 0x9C, 0x24, 0x80, 0x00, 0x00, 0x00]);
    // mov [rsp+0x88], rsi
    code.extend_from_slice(&[0x48, 0x89, 0xB4, 0x24, 0x88, 0x00, 0x00, 0x00]);
    // mov [rsp+0x90], rdi
    code.extend_from_slice(&[0x48, 0x89, 0xBC, 0x24, 0x90, 0x00, 0x00, 0x00]);

    // XMM0-3 退避 (movups = アライメント不要で安全)
    // movups [rsp+0x40], xmm0
    code.extend_from_slice(&[0x0F, 0x11, 0x44, 0x24, 0x40]);
    // movups [rsp+0x50], xmm1
    code.extend_from_slice(&[0x0F, 0x11, 0x4C, 0x24, 0x50]);
    // movups [rsp+0x60], xmm2
    code.extend_from_slice(&[0x0F, 0x11, 0x54, 0x24, 0x60]);
    // movups [rsp+0x70], xmm3
    code.extend_from_slice(&[0x0F, 0x11, 0x5C, 0x24, 0x70]);

    // ===== フラグチェック =====
    // mov rbx, buffer_addr (以降 rbx = buffer base)
    code.extend_from_slice(&[0x48, 0xBB]);
    code.extend_from_slice(&buffer_addr.to_le_bytes());
    // mov rax, [rbx + 0x18] (flags)
    code.extend_from_slice(&[0x48, 0x8B, 0x43, 0x18]);
    // test rax, 1
    code.extend_from_slice(&[0x48, 0xA9, 0x01, 0x00, 0x00, 0x00]);
    // jz .call_original
    jz_patch_offset = code.len();
    code.extend_from_slice(&[0x0F, 0x84, 0x00, 0x00, 0x00, 0x00]); // rel32 パッチ対象

    // ===== インスタンスフィルタ =====
    if target_instance != 0 {
        // mov rax, target_instance
        code.extend_from_slice(&[0x48, 0xB8]);
        code.extend_from_slice(&target_instance.to_le_bytes());
        // cmp [rsp+0x28], rax  (saved rcx = instance)
        code.extend_from_slice(&[0x48, 0x39, 0x44, 0x24, 0x28]);
        // jne .call_original
        jne_patch_offset = Some(code.len());
        code.extend_from_slice(&[0x0F, 0x85, 0x00, 0x00, 0x00, 0x00]); // rel32 パッチ対象
    }

    // ===== タイムスタンプ取得 (QueryPerformanceCounter) =====
    // lea rcx, [rsp + 0x20] (QPC出力先)
    code.extend_from_slice(&[0x48, 0x8D, 0x4C, 0x24, 0x20]);
    // mov rax, qpc_addr
    code.extend_from_slice(&[0x48, 0xB8]);
    code.extend_from_slice(&qpc_addr.to_le_bytes());
    // call rax (shadow space = rsp+0x00..0x1F は確保済み)
    code.extend_from_slice(&[0xFF, 0xD0]);

    // ===== リングバッファに書き込み =====
    // rbx = buffer_addr (既にロード済み)

    // write_index を取得して次のエントリアドレスを計算
    // mov rdi, [rbx] (write_index)
    code.extend_from_slice(&[0x48, 0x8B, 0x3B]);
    // mov rax, rdi
    code.extend_from_slice(&[0x48, 0x89, 0xF8]);
    // imul rax, RING_ENTRY_SIZE
    code.extend_from_slice(&[0x48, 0x6B, 0xC0, RING_ENTRY_SIZE as u8]);
    // lea rsi, [rbx + RING_HEADER_SIZE + rax] (エントリアドレス)
    code.extend_from_slice(&[0x48, 0x8D, 0xB4, 0x03]);
    code.extend_from_slice(&(RING_HEADER_SIZE as u32).to_le_bytes());

    // タイムスタンプ書き込み
    // mov rax, [rsp + 0x20]
    code.extend_from_slice(&[0x48, 0x8B, 0x44, 0x24, 0x20]);
    // mov [rsi], rax
    code.extend_from_slice(&[0x48, 0x89, 0x06]);

    // instance 書き込み: mov rax, [rsp+0x28]; mov [rsi+8], rax
    code.extend_from_slice(&[0x48, 0x8B, 0x44, 0x24, 0x28]);
    code.extend_from_slice(&[0x48, 0x89, 0x46, 0x08]);

    // function 書き込み: mov rax, [rsp+0x30]; mov [rsi+16], rax
    code.extend_from_slice(&[0x48, 0x8B, 0x44, 0x24, 0x30]);
    code.extend_from_slice(&[0x48, 0x89, 0x46, 0x10]);

    // params_addr 書き込み: mov rax, [rsp+0x38]; mov [rsi+24], rax
    code.extend_from_slice(&[0x48, 0x8B, 0x44, 0x24, 0x38]);
    code.extend_from_slice(&[0x48, 0x89, 0x46, 0x18]);

    // write_index をインクリメント（ラップアラウンド）
    // inc rdi
    code.extend_from_slice(&[0x48, 0xFF, 0xC7]);
    // mov rax, [rbx + 0x30] (max_entries)
    code.extend_from_slice(&[0x48, 0x8B, 0x43, 0x30]);
    // cmp rdi, rax
    code.extend_from_slice(&[0x48, 0x39, 0xC7]);
    // jb .no_wrap (2バイト short jmp)
    code.extend_from_slice(&[0x72, 0x03]);
    // xor rdi, rdi
    code.extend_from_slice(&[0x48, 0x31, 0xFF]);
    // .no_wrap:
    // mov [rbx], rdi (write_index 更新)
    code.extend_from_slice(&[0x48, 0x89, 0x3B]);

    // total_count インクリメント
    // lock inc qword [rbx + 0x10]
    code.extend_from_slice(&[0xF0, 0x48, 0xFF, 0x43, 0x10]);

    // ===== .call_original =====
    let call_original_offset = code.len();

    // jz パッチ (フラグチェック → ここへ飛ぶ)
    let rel = (call_original_offset as i32) - (jz_patch_offset as i32 + 6);
    code[jz_patch_offset + 2..jz_patch_offset + 6].copy_from_slice(&rel.to_le_bytes());

    // jne パッチ（インスタンスフィルタ → ここへ飛ぶ）
    if let Some(offset) = jne_patch_offset {
        let rel2 = (call_original_offset as i32) - (offset as i32 + 6);
        code[offset + 2..offset + 6].copy_from_slice(&rel2.to_le_bytes());
    }

    // 引数を復元
    // mov rcx, [rsp+0x28]
    code.extend_from_slice(&[0x48, 0x8B, 0x4C, 0x24, 0x28]);
    // mov rdx, [rsp+0x30]
    code.extend_from_slice(&[0x48, 0x8B, 0x54, 0x24, 0x30]);
    // mov r8, [rsp+0x38]
    code.extend_from_slice(&[0x4C, 0x8B, 0x44, 0x24, 0x38]);

    // XMM 復元 (movups)
    // movups xmm0, [rsp+0x40]
    code.extend_from_slice(&[0x0F, 0x10, 0x44, 0x24, 0x40]);
    // movups xmm1, [rsp+0x50]
    code.extend_from_slice(&[0x0F, 0x10, 0x4C, 0x24, 0x50]);
    // movups xmm2, [rsp+0x60]
    code.extend_from_slice(&[0x0F, 0x10, 0x54, 0x24, 0x60]);
    // movups xmm3, [rsp+0x70]
    code.extend_from_slice(&[0x0F, 0x10, 0x5C, 0x24, 0x70]);

    // 非volatile レジスタ復元（rbx を最後に復元 — トランポリンアドレス読み出しに使うため）
    // mov rsi, [rsp+0x88]
    code.extend_from_slice(&[0x48, 0x8B, 0xB4, 0x24, 0x88, 0x00, 0x00, 0x00]);
    // mov rdi, [rsp+0x90]
    code.extend_from_slice(&[0x48, 0x8B, 0xBC, 0x24, 0x90, 0x00, 0x00, 0x00]);

    // トランポリンアドレスを rax に読み出し（rbx = buffer_addr はまだ有効）
    // mov rax, [rbx + 0x28]
    code.extend_from_slice(&[0x48, 0x8B, 0x43, 0x28]);

    // rbx 復元
    // mov rbx, [rsp+0x80]
    code.extend_from_slice(&[0x48, 0x8B, 0x9C, 0x24, 0x80, 0x00, 0x00, 0x00]);

    // ===== エピローグ =====
    // add rsp, 0xC0
    code.extend_from_slice(&[0x48, 0x81, 0xC4, 0xC0, 0x00, 0x00, 0x00]);
    // pop rbp
    code.push(0x5D);

    // トランポリンへジャンプ（rax に既にアドレスが入っている）
    // jmp rax
    code.extend_from_slice(&[0xFF, 0xE0]);

    code
}

// ============================================
// PropertyPoller - プロパティ変更自動検出
// ============================================

pub struct PropertyPoller {
    /// 対象インスタンス
    pub instance: InstanceHandle,
    /// クラス名
    pub class_name: String,
    /// 監視対象フィールド一覧（継承含む全フィールド）
    pub fields: Vec<FieldInfo>,
    /// 前回の値スナップショット
    last_values: HashMap<FieldHandle, Value>,
    /// 開始時刻
    start_time: Instant,
}

impl PropertyPoller {
    pub fn new(instance: InstanceHandle, class_name: String, fields: Vec<FieldInfo>) -> Self {
        Self {
            instance,
            class_name,
            fields,
            last_values: HashMap::new(),
            start_time: Instant::now(),
        }
    }

    /// 全フィールドをポーリングし、変更があった分をイベントとして返す
    pub fn poll(&mut self, engine: &dyn crate::engine::GameEngine) -> Vec<TraceEvent> {
        let mut events = Vec::new();
        let elapsed = self.start_time.elapsed().as_secs_f64();

        for field in &self.fields {
            let value = match engine.read_field(self.instance, field.handle) {
                Ok(v) => v,
                Err(_) => continue,
            };

            let changed = self.last_values.get(&field.handle)
                .map(|old| old != &value)
                .unwrap_or(false); // 初回は変更なしとする

            if changed {
                let old_display = self.last_values.get(&field.handle)
                    .map(|v| format!("{}", v))
                    .unwrap_or_default();

                events.push(TraceEvent::PropertyChange(PropertyChangeEvent {
                    elapsed_secs: elapsed,
                    instance_addr: self.instance.0,
                    field_name: field.name.clone(),
                    class_name: self.class_name.clone(),
                    old_value: old_display,
                    new_value: format!("{}", value),
                }));
            }

            self.last_values.insert(field.handle, value);
        }

        events
    }
}

// ============================================
// TraceSession - トレースセッション管理
// ============================================

pub const MAX_TRACE_EVENTS: usize = 10_000;

pub struct TraceSession {
    pub target: TraceTarget,
    pub events: VecDeque<TraceEvent>,
    pub stats: TraceStats,
    pub active: bool,
    pub start_time: Instant,

    /// プロパティポーラー
    pub property_poller: Option<PropertyPoller>,

    /// 関数トレース用: リモートバッファアドレス
    pub ring_buffer_addr: Option<usize>,
    /// 関数トレース用: シェルコードアドレス
    pub shellcode_addr: Option<usize>,
    /// 関数トレース用: トランポリンアドレス
    pub trampoline_addr: Option<usize>,
    /// 関数トレース用: フックでコピーした元の命令バイト数
    pub hook_copy_size: usize,
    /// 関数トレース用: 保存された元のバイト列
    pub original_bytes: Option<Vec<u8>>,
    /// 関数名キャッシュ（function_addr -> name）
    function_name_cache: HashMap<usize, String>,
    /// 最後に読み取った write_index
    last_read_index: u64,

    /// 統計用: 最後の統計更新時刻
    last_stats_time: Instant,
    /// 統計用: 最後の統計更新時の関数呼び出し数
    last_stats_calls: u64,
}

impl TraceSession {
    pub fn new(target: TraceTarget) -> Self {
        let now = Instant::now();
        Self {
            target,
            events: VecDeque::new(),
            stats: TraceStats::default(),
            active: true,
            start_time: now,
            property_poller: None,
            ring_buffer_addr: None,
            shellcode_addr: None,
            trampoline_addr: None,
            hook_copy_size: 0,
            original_bytes: None,
            function_name_cache: HashMap::new(),
            last_read_index: 0,
            last_stats_time: now,
            last_stats_calls: 0,
        }
    }

    pub fn push_event(&mut self, event: TraceEvent) {
        match &event {
            TraceEvent::FunctionCall(_) => self.stats.total_function_calls += 1,
            TraceEvent::PropertyChange(_) => self.stats.total_property_changes += 1,
        }
        self.events.push_back(event);
        while self.events.len() > MAX_TRACE_EVENTS {
            self.events.pop_front();
        }
    }

    pub fn update_stats(&mut self) {
        let now = Instant::now();
        let dt = now.duration_since(self.last_stats_time).as_secs_f64();
        if dt >= 1.0 {
            let new_calls = self.stats.total_function_calls - self.last_stats_calls;
            self.stats.calls_per_sec = new_calls as f64 / dt;
            self.last_stats_calls = self.stats.total_function_calls;
            self.last_stats_time = now;
            self.stats.unique_functions = self.function_name_cache.len();
        }
    }
}

// ============================================
// UnrealEngine へのトレース機能追加
// ============================================

impl UnrealEngine {
    /// 継承チェーンを辿って全フィールドを列挙（親クラスのフィールドも含む）
    pub fn enumerate_all_fields_inherited(&self, class: ClassHandle) -> Result<Vec<FieldInfo>> {
        let handle = unsafe { std::mem::transmute::<usize, WinHandle>(self.process_handle) };
        let mut all_fields = Vec::new();
        let mut seen_names = std::collections::HashSet::new();
        let mut current_class = class.0;

        for _ in 0..20 {
            if current_class == 0 {
                break;
            }

            if let Ok(fields) = self.enumerate_fields_impl(current_class) {
                for field in fields {
                    if seen_names.insert(field.name.clone()) {
                        all_fields.push(field);
                    }
                }
            }

            // 親クラスへ移動
            match UStruct::read(handle, current_class) {
                Ok(ustruct) => {
                    current_class = ustruct.super_struct;
                }
                Err(_) => break,
            }
        }

        Ok(all_fields)
    }

    /// 関数トレースを開始: ProcessEvent をフックしてリングバッファに記録
    ///
    /// 手順:
    /// 1. リングバッファ確保 + ヘッダー初期化 (flags=0: まだ無効)
    /// 2. シェルコード生成・配置 (トランポリンは buffer+0x28 から実行時読出し)
    /// 3. フックインストール (ProcessEvent → シェルコード)
    /// 4. トランポリンアドレスを buffer+0x28 に書き込み
    /// 5. flags=1 で有効化 (ゲームスレッドが安全にシェルコードを実行開始)
    pub fn start_function_trace(&mut self, session: &mut TraceSession) -> Result<()> {
        if self.process_event == 0 {
            return Err(EngineError::InitializationFailed(
                "ProcessEvent address not found. Function tracing unavailable.".into(),
            ));
        }

        let handle_usize = self.process_handle;
        let target_inst = session.target.instance.0;

        // 1. リングバッファを確保
        let buffer_addr = allocate_remote(handle_usize, RING_BUFFER_TOTAL, false)?;
        tracing::info!("Allocated ring buffer at 0x{:X}", buffer_addr);

        // 2. ヘッダーを初期化 (flags=0: まだ無効、シェルコードは即 call_original へ)
        let max_entries = (RING_DATA_SIZE / RING_ENTRY_SIZE) as u64;
        let mut header = vec![0u8; RING_HEADER_SIZE];
        header[0x00..0x08].copy_from_slice(&0u64.to_le_bytes()); // write_index
        header[0x08..0x10].copy_from_slice(&0u64.to_le_bytes()); // read_index
        header[0x10..0x18].copy_from_slice(&0u64.to_le_bytes()); // total_count
        header[0x18..0x20].copy_from_slice(&0u64.to_le_bytes()); // flags = 0 (INACTIVE)
        header[0x20..0x28].copy_from_slice(&0u64.to_le_bytes()); // spinlock
        header[0x28..0x30].copy_from_slice(&0u64.to_le_bytes()); // trampoline (後で設定)
        header[0x30..0x38].copy_from_slice(&max_entries.to_le_bytes());
        header[0x38..0x40].copy_from_slice(&(target_inst as u64).to_le_bytes());
        write_remote(handle_usize, buffer_addr, &header)?;

        // 3. シェルコード生成・配置
        let qpc_addr = get_qpc_address()?;
        let shellcode = generate_trace_shellcode(buffer_addr, qpc_addr, target_inst);
        let shellcode_addr = write_executable(handle_usize, &shellcode)?;
        tracing::info!("Shellcode ({} bytes) at 0x{:X}", shellcode.len(), shellcode_addr);

        // 4. フックインストール
        let handle = unsafe { std::mem::transmute::<usize, WinHandle>(handle_usize) };

        // 4a. ProcessEvent 先頭を読み取って命令境界を解析
        let read_size = 32; // 余裕を持って32バイト読む
        let original_bytes = read_process_memory(handle, self.process_event, read_size)
            .map_err(|e| EngineError::MemoryError(format!("Failed to read ProcessEvent: {}", e)))?;

        // デバッグ: 先頭バイトをログ出力
        let hex_dump: String = original_bytes.iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(" ");
        tracing::info!("ProcessEvent bytes: {}", hex_dump);

        // 命令境界を解析（最低14バイト = JMP abs のサイズ）
        let (copy_size, rip_relatives) = find_instruction_boundary(&original_bytes, 14)
            .ok_or_else(|| EngineError::MemoryError(
                format!("Failed to decode instructions at ProcessEvent 0x{:X}. Bytes: {}",
                    self.process_event, hex_dump)
            ))?;
        tracing::info!(
            "Instruction boundary: {} bytes (min 14), {} RIP-relative instructions",
            copy_size, rip_relatives.len()
        );

        // 4b. トランポリンを確保（コード配置前にアドレスが必要）
        let trampoline_alloc_size = copy_size + 14; // copied instructions + JMP back
        let trampoline_addr = allocate_remote(handle_usize, trampoline_alloc_size, true)?;

        // 4c. RIP相対リロケーション付きトランポリンコードを生成
        let jump_back_addr = self.process_event + copy_size;
        let trampoline_code = build_trampoline(
            self.process_event,
            trampoline_addr,
            &original_bytes,
            copy_size,
            &rip_relatives,
            jump_back_addr,
        );
        write_remote(handle_usize, trampoline_addr, &trampoline_code)?;
        tracing::info!(
            "Trampoline at 0x{:X} ({} bytes copied + JMP to 0x{:X})",
            trampoline_addr, copy_size, jump_back_addr
        );

        // 4d. トランポリンアドレスを buffer+0x28 に書き込み（シェルコードが読む場所）
        write_remote(handle_usize, buffer_addr + 0x28, &trampoline_addr.to_le_bytes())?;

        // 4e. ProcessEvent の先頭を JMP shellcode_addr に書き換え
        // copy_size >= 14 なので、14バイトのJMPを書いて残りは NOP で埋める
        let mut jmp_bytes = vec![0x90u8; copy_size]; // NOP fill
        jmp_bytes[0] = 0xFF; // JMP
        jmp_bytes[1] = 0x25; // [RIP+0]
        // [2..6] = 0 (RIP-relative offset to next 8 bytes)
        jmp_bytes[2] = 0x00;
        jmp_bytes[3] = 0x00;
        jmp_bytes[4] = 0x00;
        jmp_bytes[5] = 0x00;
        jmp_bytes[6..14].copy_from_slice(&shellcode_addr.to_le_bytes());

        use super::inject::patch_memory;
        let _saved_bytes = patch_memory(handle_usize, self.process_event, &jmp_bytes)?;
        tracing::info!("ProcessEvent patched at 0x{:X} ({} bytes)", self.process_event, copy_size);

        // 5. flags=1 で有効化（アトミックに近い 8バイト書き込み）
        write_remote(handle_usize, buffer_addr + 0x18, &1u64.to_le_bytes())?;
        tracing::info!("Tracing ACTIVE");

        session.ring_buffer_addr = Some(buffer_addr);
        session.shellcode_addr = Some(shellcode_addr);
        session.trampoline_addr = Some(trampoline_addr);
        session.hook_copy_size = copy_size;
        session.original_bytes = Some(original_bytes[..copy_size].to_vec());
        session.last_read_index = 0;

        tracing::info!("Function tracing started");
        Ok(())
    }

    /// 関数トレースを停止
    pub fn stop_function_trace(&mut self, session: &mut TraceSession) -> Result<()> {
        // 1. フラグを 0 に設定（シェルコードは即 call_original へ飛ぶようになる）
        if let Some(buffer_addr) = session.ring_buffer_addr {
            let _ = write_remote(self.process_handle, buffer_addr + 0x18, &0u64.to_le_bytes());
        }

        // 2. 保存済みの元バイトで ProcessEvent を復元
        if let Some(ref original_bytes) = session.original_bytes {
            let _ = super::inject::patch_memory(
                self.process_handle,
                self.process_event,
                original_bytes,
            );
            tracing::info!("ProcessEvent restored at 0x{:X} ({} bytes)", self.process_event, original_bytes.len());
        }

        // トランポリンを解放
        if let Some(addr) = session.trampoline_addr.take() {
            let _ = free_remote(self.process_handle, addr);
        }

        // 3. メモリ解放
        if let Some(addr) = session.ring_buffer_addr.take() {
            let _ = free_remote(self.process_handle, addr);
        }
        if let Some(addr) = session.shellcode_addr.take() {
            let _ = free_remote(self.process_handle, addr);
        }

        session.active = false;
        tracing::info!("Function tracing stopped");
        Ok(())
    }

    /// リングバッファから新しいイベントを読み取る
    pub fn poll_function_events(&self, session: &mut TraceSession) -> Result<Vec<TraceEvent>> {
        let buffer_addr = match session.ring_buffer_addr {
            Some(addr) => addr,
            None => return Ok(Vec::new()),
        };

        let handle = unsafe { std::mem::transmute::<usize, WinHandle>(self.process_handle) };

        // ヘッダー読み取り
        let header = read_process_memory(handle, buffer_addr, 0x40)
            .map_err(|e| EngineError::MemoryError(format!("Failed to read ring buffer header: {}", e)))?;

        let write_index = u64::from_le_bytes(header[0x00..0x08].try_into().unwrap());
        let total_count = u64::from_le_bytes(header[0x10..0x18].try_into().unwrap());
        let max_entries = u64::from_le_bytes(header[0x30..0x38].try_into().unwrap());

        let mut events = Vec::new();
        let mut read_idx = session.last_read_index;

        // 新しいエントリを読み取り（最大100件ずつ）
        let mut count = 0;
        while read_idx != write_index && count < 100 {
            let entry_offset = RING_HEADER_SIZE + (read_idx as usize) * RING_ENTRY_SIZE;
            if let Ok(entry_data) = read_process_memory(handle, buffer_addr + entry_offset, RING_ENTRY_SIZE) {
                let timestamp = u64::from_le_bytes(entry_data[0..8].try_into().unwrap());
                let instance_addr = usize::from_le_bytes(entry_data[8..16].try_into().unwrap());
                let function_addr = usize::from_le_bytes(entry_data[16..24].try_into().unwrap());
                let _params_addr = usize::from_le_bytes(entry_data[24..32].try_into().unwrap());

                // 関数名を解決（キャッシュ使用）
                let function_name = if let Some(name) = session.function_name_cache.get(&function_addr) {
                    name.clone()
                } else {
                    let name = self.get_object_name_impl(function_addr)
                        .unwrap_or_else(|_| format!("0x{:X}", function_addr));
                    session.function_name_cache.insert(function_addr, name.clone());
                    name
                };

                // クラス名を解決
                let class_name = if let Ok(obj) = UObject::read(handle, instance_addr) {
                    self.get_object_name_impl(obj.class)
                        .unwrap_or_else(|_| format!("0x{:X}", obj.class))
                } else {
                    "Unknown".to_string()
                };

                let elapsed = session.start_time.elapsed().as_secs_f64();

                events.push(TraceEvent::FunctionCall(FunctionCallEvent {
                    elapsed_secs: elapsed,
                    instance_addr,
                    function_addr,
                    function_name,
                    class_name,
                    params_snapshot: Vec::new(),
                }));
            }

            read_idx = (read_idx + 1) % max_entries;
            count += 1;
        }

        session.last_read_index = read_idx;

        // read_index をリモートバッファに書き戻し
        let _ = write_remote(
            self.process_handle,
            buffer_addr + 0x08,
            &read_idx.to_le_bytes(),
        );

        Ok(events)
    }

    /// プロパティポーリングのイベントを取得
    pub fn poll_property_events(&self, session: &mut TraceSession) -> Vec<TraceEvent> {
        if let Some(poller) = &mut session.property_poller {
            if let Some(engine) = self.as_game_engine() {
                return poller.poll(engine);
            }
        }
        Vec::new()
    }

    /// GameEngine trait への参照を取得するヘルパー
    fn as_game_engine(&self) -> Option<&dyn crate::engine::GameEngine> {
        // self は UnrealEngine で、GameEngine を impl しているが、
        // &self から &dyn GameEngine を取るには unsafe が必要
        // → poll で直接 engine.read_field を使うようにする
        None // PropertyPoller は外部から engine を渡す形に変更
    }
}

/// QueryPerformanceCounter のアドレスを取得
fn get_qpc_address() -> Result<usize> {
    unsafe {
        let module = windows::Win32::System::LibraryLoader::GetModuleHandleW(
            windows::core::w!("kernel32.dll"),
        )
        .map_err(|e| EngineError::MemoryError(format!("Failed to get kernel32: {}", e)))?;

        let name = std::ffi::CString::new("QueryPerformanceCounter").unwrap();
        let addr = windows::Win32::System::LibraryLoader::GetProcAddress(
            module,
            windows::core::PCSTR(name.as_ptr() as *const u8),
        )
        .ok_or_else(|| EngineError::MemoryError("QueryPerformanceCounter not found".into()))?;

        Ok(addr as usize)
    }
}
