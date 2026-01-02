/// Unreal Engine backend implementation details

use super::scanner::{scan_pattern, Pattern};
use super::signatures::VersionSignatures;
use super::structures::{FNamePool, FUObjectArray, UObject};
use super::{EngineError, Result, UnrealEngine};
use crate::platform::windows::{read_process_memory, HANDLE};
use windows::Win32::Foundation::HANDLE as WinHandle;

impl UnrealEngine {
    /// 値がASCIIテキストのように見えるかチェック（誤検出回避用）
    fn looks_like_ascii(value: usize) -> bool {
        let bytes = value.to_le_bytes();
        let ascii_count = bytes.iter().filter(|&&b| b >= 0x20 && b <= 0x7E).count();
        // 8バイト中6バイト以上がASCII印刷可能文字ならテキストと判定
        ascii_count >= 6
    }

    /// GNames (FNamePool/FNameEntryAllocator) が有効かどうか検証
    ///
    /// UE5.5 の FNameEntryAllocator 構造:
    /// - FRWLock Lock (8 bytes on Windows - SRWLOCK)
    /// - uint32 CurrentBlock (4 bytes)
    /// - uint32 CurrentByteCursor (4 bytes)
    /// - uint8* Blocks[8192] (65536 bytes)
    ///
    /// Blocks は offset 16 から始まる
    ///
    /// FNameEntry 構造 (WITH_CASE_PRESERVING_NAME=false, ランタイム):
    /// - FNameEntryHeader Header (2 bytes)
    ///   - bit 0: bIsWide
    ///   - bits 1-5: LowercaseProbeHash
    ///   - bits 6-15: Len (最大 1023)
    /// - char/wchar_t data[Len]
    ///
    /// index 0 は必ず "None" (len=4, ANSI)
    fn validate_gnames(&self, handle: WinHandle, addr: usize) -> bool {
        // 複数のBlocksオフセットを試す
        for blocks_offset in [16usize, 0, 8, 24, 32] {
            let blocks_addr = addr + blocks_offset;

            // Blocks[0] を読む
            let block0_data = match read_process_memory(handle, blocks_addr, 8) {
                Ok(data) => data,
                Err(_) => continue,
            };
            let block0 = usize::from_le_bytes(block0_data[..8].try_into().unwrap());

            // Blocks[0] がヒープアドレスであること
            // ヒープは通常 0x10000000000 以上の大きなアドレス
            if block0 == 0 || block0 < 0x10000 {
                continue;
            }

            // 0x7FF... はモジュールアドレス範囲なので除外
            if block0 >= 0x7F0000000000 {
                continue;
            }

            // Block0 の先頭 (index 0) を読んで FNameEntry ヘッダを確認
            // index 0 は必ず "None" (len=4, ANSI, bIsWide=0)
            let entry_data = match read_process_memory(handle, block0, 16) {
                Ok(data) => data,
                Err(_) => continue,
            };

            let header = u16::from_le_bytes([entry_data[0], entry_data[1]]);
            let is_wide = (header & 1) != 0;
            let len = (header >> 6) as usize;

            // "None" は ANSI で長さ 4
            if !is_wide && len == 4 {
                let name_bytes = &entry_data[2..6];
                if name_bytes == b"None" {
                    tracing::info!("  Valid GNames: addr=0x{:X}, blocks_offset={}, Blocks[0]=0x{:X}, first entry is 'None'",
                        addr, blocks_offset, block0);
                    return true;
                }
            }

            // "None" でなくても、有効な文字列データかチェック
            // ただし、index 0 は "None" でなければならないので、
            // 長さ1や2の短い文字列は誤検出の可能性が高い
            if len >= 3 && len <= 64 {
                let str_bytes = if is_wide { len.min(14) * 2 } else { len.min(14) };
                if str_bytes > 0 && str_bytes <= 14 {
                    let str_data = &entry_data[2..2 + str_bytes];

                    let name = if is_wide {
                        let chars: Vec<u16> = str_data.chunks_exact(2)
                            .map(|c| u16::from_le_bytes([c[0], c[1]]))
                            .collect();
                        String::from_utf16_lossy(&chars)
                    } else {
                        String::from_utf8_lossy(str_data).to_string()
                    };

                    // 英数字とアンダースコアのみで構成されているか
                    let valid_chars = name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');

                    // 最初のエントリとして期待される名前かチェック
                    // UE では "None" または "ByteProperty" などが最初に来る
                    let is_known_first_entry = name == "None"
                        || name.starts_with("ByteProperty")
                        || name.starts_with("Int")
                        || name.starts_with("Object");

                    if valid_chars && !name.is_empty() && is_known_first_entry {
                        tracing::info!("  Valid GNames candidate: addr=0x{:X}, blocks_offset={}, Blocks[0]=0x{:X}, first_entry='{}' (len={})",
                            addr, blocks_offset, block0, name, len);
                        return true;
                    } else if valid_chars && !name.is_empty() {
                        // 既知のエントリではないが、有効な文字列
                        tracing::debug!("  Possible GNames (unknown first entry): addr=0x{:X}, blocks_offset={}, Blocks[0]=0x{:X}, first_entry='{}' (len={})",
                            addr, blocks_offset, block0, name, len);
                        // 既知のエントリが見つからなかった場合のフォールバック用に記憶しない
                        // 厳密なチェックを優先
                    }
                }
            }
        }

        false
    }

    /// GNames のアドレスを検索
    ///
    /// 検索戦略:
    /// 1. 複数のパターンで候補を収集
    /// 2. 各候補について、index 0 が "None" になるかチェック
    /// 3. "None" が読めた候補を採用
    pub(super) fn find_gnames_impl(&self) -> Result<usize> {
        let handle = unsafe { std::mem::transmute::<usize, WinHandle>(self.process_handle) };

        let module_base = self.module_base;
        let module_size = self.module_size;

        tracing::info!("Scanning for GNames in range 0x{:X} - 0x{:X} (size: 0x{:X})",
            module_base, module_base + module_size, module_size);

        let patterns = VersionSignatures::all();
        let mut all_candidates: Vec<(usize, &str)> = Vec::new();

        // まずすべてのパターンから候補を収集
        for (i, pattern_str) in patterns.gnames_patterns.iter().enumerate() {
            tracing::info!("Trying GNames pattern {}: {}", i + 1, pattern_str);
            let pattern = Pattern::from_string(pattern_str);

            match scan_pattern(handle, &pattern, module_base, module_size) {
                Ok(results) => {
                    tracing::info!("Pattern {} found {} matches", i + 1, results.len());

                    for result in results.iter().take(50) {
                        // パターンに応じてオフセット位置を調整
                        let (offset_pos, instruction_end) = match *pattern_str {
                            // 48 8D 0D (lea rcx, [rip+offset])
                            s if s.starts_with("48 8D 0D") => (3, 7),
                            // 48 8B 1D (mov rbx, [rip+offset])
                            s if s.starts_with("48 8B 1D") => (3, 7),
                            // 長いパターン (ALT2)
                            s if s.len() > 50 => (pattern.len() - 7, pattern.len() - 3),
                            // デフォルト: 48 8B 05 (mov rax, [rip+offset])
                            _ => (3, 7),
                        };

                        // RIP相対アドレスを解決
                        let inst_data = match read_process_memory(handle, result.address, pattern.len() + 8) {
                            Ok(data) => data,
                            Err(_) => continue,
                        };

                        if inst_data.len() < offset_pos + 4 {
                            continue;
                        }

                        let rel_offset = i32::from_le_bytes([
                            inst_data[offset_pos],
                            inst_data[offset_pos + 1],
                            inst_data[offset_pos + 2],
                            inst_data[offset_pos + 3],
                        ]);

                        let gnames_ptr = (result.address as i64 + instruction_end as i64 + rel_offset as i64) as usize;

                        if gnames_ptr > module_base && gnames_ptr < module_base + module_size + 0x10000000 {
                            if !all_candidates.iter().any(|(addr, _)| *addr == gnames_ptr) {
                                all_candidates.push((gnames_ptr, pattern_str));
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Pattern {} scan failed: {}", i + 1, e);
                }
            }
        }

        tracing::info!("Collected {} unique GNames candidates", all_candidates.len());

        // デバッグ: 各候補のメモリダンプを出力
        for (idx, (ptr_addr, pattern)) in all_candidates.iter().take(5).enumerate() {
            if let Ok(dump) = read_process_memory(handle, *ptr_addr, 64) {
                tracing::info!("Candidate {} at 0x{:X} (pattern: {}):", idx, ptr_addr, pattern);
                for i in 0..8 {
                    let off = i * 8;
                    let val = usize::from_le_bytes(dump[off..off+8].try_into().unwrap());
                    tracing::info!("  [+{:02X}] {:02X?} = 0x{:X}", off, &dump[off..off+8], val);
                }
            }
        }

        // すべての候補を検証 - "None" が読めるものを探す
        for (idx, (ptr_addr, pattern)) in all_candidates.iter().enumerate() {
            // 候補周辺のオフセットも試す（ポインタの間接参照など）
            for addr_offset in [0i64, 8, 16, -8, -16] {
                let try_ptr_addr = match (*ptr_addr as i64).checked_add(addr_offset) {
                    Some(a) if a > 0 => a as usize,
                    _ => continue,
                };

                // ポインタを読む
                let ptr_data = match read_process_memory(handle, try_ptr_addr, 8) {
                    Ok(data) => data,
                    Err(_) => continue,
                };
                let gnames_value = usize::from_le_bytes(ptr_data[..8].try_into().unwrap());

                // 複数のアドレス解釈を試す
                let addrs_to_try = [
                    gnames_value,           // 間接参照
                    try_ptr_addr,           // 直接
                ];

                for &test_addr in &addrs_to_try {
                    if test_addr == 0 || test_addr < 0x10000 {
                        continue;
                    }

                    // 複数の Blocks オフセットを試す
                    for blocks_offset in [16i64, 0, 8, 24, 32] {
                        let blocks_addr = match (test_addr as i64).checked_add(blocks_offset) {
                            Some(a) if a > 0 => a as usize,
                            _ => continue,
                        };

                        // "None" が index 0 で読めるかテスト
                        if let Some(name) = self.try_read_fname_at_index_0(handle, blocks_addr) {
                            if name == "None" {
                                tracing::info!("Found valid GNames at 0x{:X} (blocks at 0x{:X}, pattern={}, idx={})",
                                    test_addr, blocks_addr, pattern, idx);
                                // blocks_addr を直接返す（Blocks 配列のアドレス）
                                // ただし mod.rs では gnames_ptr を返すので、ここでは test_addr を返す
                                // get_fname_impl で blocks_offset=16 を使う前提
                                return Ok(try_ptr_addr);
                            } else if !name.is_empty() {
                                tracing::debug!("Candidate 0x{:X} (offset {}) has first entry '{}' (not 'None')",
                                    blocks_addr, blocks_offset, name);
                            }
                        }
                    }
                }
            }
        }

        // 見つからなかった場合は元の検証方法にフォールバック
        tracing::warn!("'None' entry not found via pattern, falling back to original validation");
        for (idx, (ptr_addr, pattern)) in all_candidates.iter().enumerate() {
            let ptr_data = match read_process_memory(handle, *ptr_addr, 8) {
                Ok(data) => data,
                Err(_) => continue,
            };
            let gnames_value = usize::from_le_bytes(ptr_data[..8].try_into().unwrap());

            if gnames_value == 0 || gnames_value < module_base || gnames_value > module_base + module_size * 2 {
                continue;
            }

            tracing::info!("Fallback candidate {}: ptr_addr=0x{:X}, gnames=0x{:X}, pattern={}",
                idx, ptr_addr, gnames_value, pattern);

            if self.validate_gnames(handle, gnames_value) {
                tracing::info!("Found valid GNames at 0x{:X} (ptr at 0x{:X})", gnames_value, ptr_addr);
                return Ok(*ptr_addr);
            }

            if self.validate_gnames(handle, *ptr_addr) {
                tracing::info!("Found valid GNames directly at 0x{:X}", ptr_addr);
                return Ok(*ptr_addr);
            }
        }

        // パターンマッチングも検証も失敗した場合、メモリ直接検索を試行
        tracing::warn!("Pattern-based GNames detection failed, trying direct memory search for 'None' entry...");

        // "None" FNameEntry をヒープ内で直接検索
        if let Some(none_entry_addr) = self.search_for_none_entry(handle) {
            tracing::info!("Found 'None' entry at 0x{:X}, searching for Blocks array...", none_entry_addr);

            // "None" エントリを指しているポインタ (= Blocks[0]) を探す
            if let Some(blocks_addr) = self.find_blocks_from_none_entry(handle, none_entry_addr) {
                tracing::info!("Found Blocks array at 0x{:X}", blocks_addr);

                // Blocks 配列のアドレスを返す
                // FNameEntryAllocator は Blocks - 16 にあるはず
                // ただし get_fname_impl では blocks_addr を直接使うため、
                // ここでは blocks_addr - 16 を返して gnames_ptr として保存
                // refresh_gnames で gnames = gnames_ptr を設定するので、
                // get_fname_impl で gnames + 16 = blocks_addr となる
                let allocator_addr = blocks_addr.saturating_sub(16);
                tracing::info!("Using FNameEntryAllocator at 0x{:X} (Blocks at +16 = 0x{:X})",
                    allocator_addr, blocks_addr);

                return Ok(allocator_addr);
            }

            // Blocks 配列が見つからなかった場合でも、none_entry_addr を Blocks[0] の値として使える
            // この場合、偽の Blocks 配列アドレスを構築する必要がある
            tracing::warn!("Could not find Blocks array, using None entry address directly");

            // none_entry_addr を直接返し、get_fname_impl で特別処理する
            // SENTINEL値として特殊なマーカーを使用
            // 実際には none_entry_addr を保存して後で使う
        }

        Err(EngineError::InitializationFailed(
            "GNames not found after exhaustive search".into(),
        ))
    }

    /// index 0 の FName を読んでみる (検証用)
    fn try_read_fname_at_index_0(&self, handle: WinHandle, blocks_addr: usize) -> Option<String> {
        // Blocks[0] を読む
        let block0_data = read_process_memory(handle, blocks_addr, 8).ok()?;
        let block0 = usize::from_le_bytes(block0_data[..8].try_into().unwrap());

        // ヒープアドレスチェック
        // ヒープは通常 0x100000000 (4GB) 以上、0x7F0000000000 未満
        if block0 == 0 || block0 < 0x10000 {
            return None;
        }
        // 0x7F0000000000 以上はカーネル空間なので除外
        if block0 >= 0x7F0000000000 {
            return None;
        }

        // index 0 = offset 0 = Blocks[0] + 0 * STRIDE = Blocks[0]
        let entry_data = read_process_memory(handle, block0, 16).ok()?;

        let header = u16::from_le_bytes([entry_data[0], entry_data[1]]);
        let is_wide = (header & 1) != 0;
        let len = (header >> 6) as usize;

        if len == 0 || len > 64 {
            return None;
        }

        let str_bytes = if is_wide { len * 2 } else { len };
        if str_bytes > 14 {
            return None;
        }

        let str_data = &entry_data[2..2 + str_bytes];

        if is_wide {
            let chars: Vec<u16> = str_data.chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            Some(String::from_utf16_lossy(&chars))
        } else {
            // ASCII チェック
            if str_data.iter().all(|&b| b.is_ascii_alphanumeric() || b == b'_') {
                Some(String::from_utf8_lossy(str_data).to_string())
            } else {
                None
            }
        }
    }

    /// メモリ内で "None" FNameEntry パターンを直接検索
    ///
    /// "None" エントリのバイトパターン:
    /// - Header (2 bytes): bIsWide=0, LowercaseProbeHash=variable, Len=4
    ///   - Len は bits 6-15 なので、len=4 => header & 0xFFC0 = 0x0100
    ///   - bIsWide=0 => header & 1 = 0
    /// - Data (4 bytes): "None" = [0x4E, 0x6F, 0x6E, 0x65]
    ///
    /// 返り値: 見つかった Blocks[0] のアドレス（FNameEntry "None" のアドレス）
    fn search_for_none_entry(&self, handle: WinHandle) -> Option<usize> {
        // "None" のデータ部分
        const NONE_DATA: [u8; 4] = [0x4E, 0x6F, 0x6E, 0x65];  // "None"

        // ヒープ領域をスキャン
        // Windows x64 のユーザーモードヒープは通常 0x100000000 ~ 0x7F0000000000 あたり
        // ただし、全部スキャンは非効率なので、ゲームが使いそうな範囲に限定

        // GObjects から参照されているヒープ領域のベースを推測
        // 例: gobjects = 0x1E60723B800 => base = 0x1E600000000 (上位12ビット + 下位をゼロ)
        let heap_base_guess = if self.gobjects > 0x100000000 {
            // 上位を維持し、下位32ビットをクリア（4GB境界）
            self.gobjects & 0xFFFFFF00000000
        } else {
            0x100000000  // デフォルト: 4GB以上
        };

        tracing::info!("search_for_none_entry: gobjects=0x{:X}, heap_base_guess=0x{:X}",
            self.gobjects, heap_base_guess);

        // スキャン範囲を複数設定
        // gobjects が 0x1E60723B800 の場合、heap_base_guess = 0x1E600000000
        let scan_ranges = [
            // gobjects 周辺のヒープ (最優先)
            (heap_base_guess, 0x200000000usize),  // 8GB 範囲
            // gobjects より少し低いアドレス
            (heap_base_guess.saturating_sub(0x100000000), 0x200000000usize),
        ];

        for (start, size) in scan_ranges {
            tracing::info!("Searching for 'None' FNameEntry in 0x{:X} - 0x{:X}...", start, start + size);

            // 64KB ページ単位でスキャン
            const PAGE_SIZE: usize = 0x10000;
            let mut pages_scanned = 0;
            let mut pages_readable = 0;

            for page_offset in (0..size).step_by(PAGE_SIZE) {
                let page_addr = start + page_offset;
                pages_scanned += 1;

                // 進捗表示
                if pages_scanned % 1000 == 0 {
                    tracing::debug!("  Scanned {} pages, {} readable...", pages_scanned, pages_readable);
                }

                // ページを読む
                let page_data = match read_process_memory(handle, page_addr, PAGE_SIZE) {
                    Ok(data) => data,
                    Err(_) => continue,  // 読めないページはスキップ
                };
                pages_readable += 1;

                // ページ内で "None" パターンを検索
                // FNameEntry は 2 バイトアラインメント
                for offset in (0..page_data.len() - 6).step_by(2) {
                    // まず "None" 文字列をチェック（高速）
                    if page_data[offset + 2..offset + 6] != NONE_DATA {
                        continue;
                    }

                    // ヘッダをチェック
                    let header = u16::from_le_bytes([page_data[offset], page_data[offset + 1]]);
                    let is_wide = (header & 1) != 0;
                    let len = (header >> 6) as usize;

                    // "None" は ANSI (bIsWide=0), 長さ 4
                    if is_wide || len != 4 {
                        continue;
                    }

                    let found_addr = page_addr + offset;
                    tracing::info!("Found 'None' FNameEntry at 0x{:X} (header=0x{:04X})", found_addr, header);

                    // 次のエントリも妥当かチェック（誤検出回避）
                    // "None" のサイズ: header(2) + data(4) = 6, aligned to 2 = 6
                    // 次のエントリは offset + 6
                    if offset + 12 < page_data.len() {
                        let next_header = u16::from_le_bytes([page_data[offset + 6], page_data[offset + 7]]);
                        let next_is_wide = (next_header & 1) != 0;
                        let next_len = (next_header >> 6) as usize;

                        // 次のエントリも妥当な長さ
                        if next_len > 0 && next_len <= 64 {
                            // 次のエントリの文字列をチェック
                            let next_str_len = if next_is_wide { next_len * 2 } else { next_len };
                            if offset + 8 + next_str_len <= page_data.len() {
                                let next_str = &page_data[offset + 8..offset + 8 + next_str_len.min(20)];
                                let valid_chars = if next_is_wide {
                                    // Wide文字のチェックは省略
                                    true
                                } else {
                                    next_str.iter().all(|&b| b.is_ascii_alphanumeric() || b == b'_')
                                };

                                if valid_chars {
                                    tracing::info!("  Next entry also valid: len={}, wide={}", next_len, next_is_wide);
                                    return Some(found_addr);
                                }
                            }
                        }
                    }

                    // 次のエントリチェックに失敗しても、候補として返す
                    tracing::info!("  Returning as candidate (next entry validation skipped)");
                    return Some(found_addr);
                }
            }

            tracing::info!("  Range complete: {} pages scanned, {} readable", pages_scanned, pages_readable);
        }

        None
    }

    /// "None" エントリのアドレスから Blocks 配列を見つける
    ///
    /// Blocks[0] は "None" エントリの先頭を指しているはず
    /// なので、Blocks[0] のポインタ値 == found_none_addr
    ///
    /// Blocks 配列を持つ FNameEntryAllocator を見つける
    fn find_blocks_from_none_entry(&self, handle: WinHandle, none_entry_addr: usize) -> Option<usize> {
        // none_entry_addr を指しているポインタをモジュール内で探す
        let target_bytes = none_entry_addr.to_le_bytes();

        // モジュールの .data セクション (後半) を探す
        let scan_start = self.module_base + (self.module_size / 2);
        let scan_end = self.module_base + self.module_size;

        tracing::info!("Searching for pointer to 0x{:X} in module 0x{:X} - 0x{:X}...",
            none_entry_addr, scan_start, scan_end);

        const PAGE_SIZE: usize = 0x1000;

        for page_addr in (scan_start..scan_end).step_by(PAGE_SIZE) {
            let page_data = match read_process_memory(handle, page_addr, PAGE_SIZE) {
                Ok(data) => data,
                Err(_) => continue,
            };

            // 8バイトアラインメントでポインタを探す
            for offset in (0..page_data.len() - 8).step_by(8) {
                if page_data[offset..offset + 8] == target_bytes {
                    let blocks_ptr_addr = page_addr + offset;
                    tracing::info!("Found pointer to None entry at 0x{:X}", blocks_ptr_addr);

                    // これが Blocks[0] であるかチェック
                    // Blocks[0] は FNameEntryAllocator 内で offset 16 にある
                    // FNameEntryAllocator の先頭 = blocks_ptr_addr - 16
                    let allocator_addr = blocks_ptr_addr - 16;

                    // FNamePool の確認: allocator_addr を Blocks 配列の先頭として使う
                    // 実際にはこの blocks_ptr_addr 自体が Blocks[0] のアドレス
                    return Some(blocks_ptr_addr);
                }
            }
        }

        // モジュール内で見つからなかった場合、ヒープ領域も探す
        // (FNameEntryAllocator 自体がヒープに確保されている可能性)
        let heap_ranges = [
            (none_entry_addr & 0xFFFF00000000, 0x100000000usize),
        ];

        for (start, size) in heap_ranges {
            tracing::info!("Searching for pointer in heap 0x{:X} - 0x{:X}...", start, start + size);

            for page_addr in (start..start + size).step_by(PAGE_SIZE) {
                let page_data = match read_process_memory(handle, page_addr, PAGE_SIZE) {
                    Ok(data) => data,
                    Err(_) => continue,
                };

                for offset in (0..page_data.len() - 8).step_by(8) {
                    if page_data[offset..offset + 8] == target_bytes {
                        let found_addr = page_addr + offset;

                        // 誤検出を避けるため、このポインタの周辺もチェック
                        // Blocks[1] があれば、それもヒープアドレスのはず
                        if offset + 16 <= page_data.len() {
                            let next_ptr = usize::from_le_bytes(page_data[offset + 8..offset + 16].try_into().unwrap());
                            if next_ptr > 0x10000 && next_ptr < 0x7F0000000000 && next_ptr != none_entry_addr {
                                tracing::info!("Found Blocks array at 0x{:X} (Blocks[0]=0x{:X}, Blocks[1]=0x{:X})",
                                    found_addr, none_entry_addr, next_ptr);
                                return Some(found_addr);
                            }
                        }
                    }
                }
            }
        }

        None
    }

    /// GObjects のアドレスを検索
    /// ブルートフォース方式: パターンで見つかった全候補から再帰的にポインタを辿り、
    /// 実際にUObjectが読めるアドレスを見つける
    pub(super) fn find_gobjects_impl(&self) -> Result<usize> {
        use super::structures::FUObjectItem;

        let handle = unsafe { std::mem::transmute::<usize, WinHandle>(self.process_handle) };

        let module_base = self.module_base;
        let module_size = self.module_size;

        tracing::info!("Scanning for GObjects (brute-force recursive mode)...");
        let patterns = VersionSignatures::all();

        // 全パターンから候補アドレスを収集
        let mut all_candidates: Vec<usize> = Vec::new();

        for (i, pattern_str) in patterns.gobjects_patterns.iter().enumerate() {
            let pattern = Pattern::from_string(pattern_str);

            if let Ok(results) = scan_pattern(handle, &pattern, module_base, module_size) {
                tracing::info!("Pattern {} found {} matches", i + 1, results.len());

                for result in results.iter().take(20) {  // 各パターン最大20マッチ
                    let inst_data = match read_process_memory(handle, result.address, pattern.len() + 8) {
                        Ok(data) => data,
                        Err(_) => continue,
                    };

                    if inst_data.len() < 7 {
                        continue;
                    }

                    let rel_offset = i32::from_le_bytes([
                        inst_data[3],
                        inst_data[4],
                        inst_data[5],
                        inst_data[6],
                    ]);

                    let ptr_addr = (result.address as i64 + 7 + rel_offset as i64) as usize;
                    if ptr_addr > module_base && ptr_addr < module_base + module_size + 0x10000000 {
                        if !all_candidates.contains(&ptr_addr) {
                            all_candidates.push(ptr_addr);
                        }
                    }
                }
            }
        }

        tracing::info!("Collected {} candidate addresses, trying recursive pointer chase...", all_candidates.len());

        // すべての候補アドレスをダンプして構造を確認
        for (idx, &candidate) in all_candidates.iter().enumerate() {
            if let Ok(data) = read_process_memory(handle, candidate, 48) {
                let val0 = usize::from_le_bytes(data[0..8].try_into().unwrap());
                let val1 = usize::from_le_bytes(data[8..16].try_into().unwrap());
                let val2_lo = i32::from_le_bytes(data[16..20].try_into().unwrap());
                let val2_hi = i32::from_le_bytes(data[20..24].try_into().unwrap());
                let val3_lo = i32::from_le_bytes(data[24..28].try_into().unwrap());
                let val3_hi = i32::from_le_bytes(data[28..32].try_into().unwrap());

                // FChunkedFixedUObjectArray の形式かどうかをチェック
                // Objects(ptr), PreAllocatedObjects(ptr), MaxElements(i32), NumElements(i32), MaxChunks(i32), NumChunks(i32)
                let is_chunked_array = val0 > 0x10000 && val0 < 0x7FFFFFFFFFFF
                    && val2_lo > 0 && val2_lo < 10_000_000  // MaxElements
                    && val2_hi > 0 && val2_hi < 10_000_000  // NumElements
                    && val3_lo > 0 && val3_lo < 1000        // MaxChunks
                    && val3_hi > 0 && val3_hi <= val3_lo;   // NumChunks <= MaxChunks

                // 全候補をINFOレベルで出力
                tracing::info!("Candidate {} at 0x{:X}: ptr0=0x{:X}, ptr1=0x{:X}, i32s=[{}, {}, {}, {}]",
                    idx, candidate, val0, val1, val2_lo, val2_hi, val3_lo, val3_hi);

                if is_chunked_array {
                    tracing::info!("  ==> Looks like FChunkedFixedUObjectArray!");
                    tracing::info!("    Objects=0x{:X}, PreAlloc=0x{:X}", val0, val1);
                    tracing::info!("    MaxElements={}, NumElements={}", val2_lo, val2_hi);
                    tracing::info!("    MaxChunks={}, NumChunks={}", val3_lo, val3_hi);
                }
            }
        }

        // 各候補から FChunkedFixedUObjectArray を直接探す
        for &candidate in &all_candidates {
            // FUObjectArray の場合、ObjObjects は offset 16 から始まる
            for offset in [0i64, 16, -16, 32, -32] {
                let addr = match (candidate as i64).checked_add(offset) {
                    Some(a) if a > 0 => a as usize,
                    _ => continue,
                };

                if let Ok(data) = read_process_memory(handle, addr, 48) {
                    let objects_ptr = usize::from_le_bytes(data[0..8].try_into().unwrap());
                    let pre_alloc = usize::from_le_bytes(data[8..16].try_into().unwrap());
                    let max_elements = i32::from_le_bytes(data[16..20].try_into().unwrap());
                    let num_elements = i32::from_le_bytes(data[20..24].try_into().unwrap());
                    let max_chunks = i32::from_le_bytes(data[24..28].try_into().unwrap());
                    let num_chunks = i32::from_le_bytes(data[28..32].try_into().unwrap());

                    // 有効な FChunkedFixedUObjectArray かチェック
                    if objects_ptr > 0x10000 && objects_ptr < 0x7FFFFFFFFFFF
                        && max_elements > 0 && max_elements < 10_000_000
                        && num_elements > 0 && num_elements <= max_elements
                        && max_chunks > 0 && max_chunks < 1000
                        && num_chunks > 0 && num_chunks <= max_chunks
                    {
                        tracing::info!("Found potential FChunkedFixedUObjectArray at 0x{:X} (offset {} from candidate):", addr, offset);
                        tracing::info!("  Objects=0x{:X}, NumElements={}, NumChunks={}", objects_ptr, num_elements, num_chunks);

                        // 最初のチャンクを読んで検証
                        if let Ok(chunk_data) = read_process_memory(handle, objects_ptr, 8) {
                            let first_chunk = usize::from_le_bytes(chunk_data[..8].try_into().unwrap());
                            if first_chunk > 0x10000 && first_chunk < 0x7FFFFFFFFFFF {
                                tracing::info!("  First chunk at 0x{:X}", first_chunk);

                                // 最初の FUObjectItem を読む
                                if let Ok(item) = FUObjectItem::read(handle, first_chunk) {
                                    tracing::info!("  First FUObjectItem: object=0x{:X}, flags={}, cluster={}, serial={}",
                                        item.object, item.flags, item.cluster_root_index, item.serial_number);

                                    if self.is_valid_fuobject_item(&item) {
                                        tracing::info!("  ==> Valid FUObjectItem! Returning objects_ptr");
                                        return Ok(objects_ptr);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // 各候補から再帰的にポインタを辿って UObject を見つける
        for &candidate in &all_candidates {
            // 候補周辺のオフセットも試す
            for base_offset in [-64i64, -32, -16, 0, 16, 32, 64] {
                let base_addr = match (candidate as i64).checked_add(base_offset) {
                    Some(addr) if addr > 0 => addr as usize,
                    _ => continue,
                };

                if base_addr < module_base {
                    continue;
                }

                // このアドレスから深さ4までポインタを辿る
                if let Some((gobjects_addr, objects_ptr, first_object)) =
                    self.chase_pointers_for_uobject(handle, base_addr, 4)
                {
                    tracing::info!("Found valid GObjects structure!");
                    tracing::info!("  Base address: 0x{:X}", gobjects_addr);
                    tracing::info!("  Objects pointer: 0x{:X}", objects_ptr);
                    tracing::info!("  First UObject: 0x{:X}", first_object);

                    // 追加検証: 実際に複数のオブジェクトが読めるか確認
                    let valid_count = self.count_valid_objects(handle, objects_ptr, 10);
                    if valid_count >= 3 {
                        tracing::info!("  Verified: {} valid objects in first 10 slots", valid_count);
                        // objects_ptr を返す（これが FChunkedFixedUObjectArray.Objects の位置）
                        // get_all_objects_impl はこのアドレスから直接チャンクを読む
                        return Ok(objects_ptr);
                    } else {
                        tracing::warn!("  Only {} valid objects found, continuing search...", valid_count);
                    }
                }
            }
        }

        // 最後の手段: データセクション全体をスキャンして FUObjectItem の配列パターンを探す
        tracing::info!("Pattern matching failed, trying direct memory scan for UObject arrays...");

        if let Some(addr) = self.scan_for_uobject_array(handle) {
            return Ok(addr);
        }

        Err(EngineError::InitializationFailed(
            "GObjects not found after exhaustive search".into(),
        ))
    }

    /// ポインタを再帰的に辿って有効な UObject を見つける
    /// 返り値: (GObjects構造体のアドレス, Objectsポインタ配列のアドレス, 最初のUObjectアドレス)
    fn chase_pointers_for_uobject(
        &self,
        handle: WinHandle,
        start_addr: usize,
        max_depth: usize,
    ) -> Option<(usize, usize, usize)> {
        use super::structures::FUObjectItem;

        if max_depth == 0 {
            return None;
        }

        // 64バイト読んで複数のレイアウトを試す
        let data = read_process_memory(handle, start_addr, 64).ok()?;

        // レイアウト1: FUObjectArray (offset 16 に Objects ポインタ)
        let layout1_objects = usize::from_le_bytes(data[16..24].try_into().unwrap());
        if let Some(result) = self.try_objects_pointer(handle, start_addr, layout1_objects) {
            return Some(result);
        }

        // レイアウト2: FChunkedFixedUObjectArray (offset 0 に Objects ポインタ)
        let layout2_objects = usize::from_le_bytes(data[0..8].try_into().unwrap());
        if let Some(result) = self.try_objects_pointer(handle, start_addr, layout2_objects) {
            return Some(result);
        }

        // レイアウト3: ポインタの先を辿る (間接参照)
        for offset in [0usize, 8, 16, 24] {
            if offset + 8 <= data.len() {
                let ptr = usize::from_le_bytes(data[offset..offset+8].try_into().unwrap());
                if self.is_valid_pointer(ptr) && !Self::looks_like_ascii(ptr) {
                    // このポインタの先を再帰的に探索
                    if let Some(result) = self.chase_pointers_for_uobject(handle, ptr, max_depth - 1) {
                        return Some(result);
                    }
                }
            }
        }

        None
    }

    /// Objects ポインタが有効なチャンク配列を指しているか確認
    fn try_objects_pointer(
        &self,
        handle: WinHandle,
        base_addr: usize,
        objects_ptr: usize,
    ) -> Option<(usize, usize, usize)> {
        use super::structures::FUObjectItem;

        if !self.is_valid_pointer(objects_ptr) {
            return None;
        }

        // Objects[0] = 最初のチャンクへのポインタを読む
        let chunk_ptr_data = read_process_memory(handle, objects_ptr, 8).ok()?;
        let first_chunk = usize::from_le_bytes(chunk_ptr_data[..8].try_into().unwrap());

        if !self.is_valid_pointer(first_chunk) {
            return None;
        }

        // 最初のチャンクから FUObjectItem を読む
        let item = FUObjectItem::read(handle, first_chunk).ok()?;

        // FUObjectItem の検証
        if self.is_valid_fuobject_item(&item) {
            // UObject として読めるか最終確認
            if self.verify_uobject(handle, item.object) {
                return Some((base_addr, objects_ptr, item.object));
            }
        }

        // もし first_chunk の先がまだポインタの場合、もう一段間接参照を試す
        // これは PreAllocatedObjects を使用している場合に必要
        if self.is_valid_pointer(item.object) {
            // item.object がポインタとして解釈されている可能性
            // first_chunk の値自体がさらにポインタの配列の可能性
            let second_ptr_data = read_process_memory(handle, first_chunk, 8).ok()?;
            let actual_chunk = usize::from_le_bytes(second_ptr_data[..8].try_into().unwrap());

            if self.is_valid_pointer(actual_chunk) && actual_chunk != first_chunk {
                if let Ok(item2) = FUObjectItem::read(handle, actual_chunk) {
                    if self.is_valid_fuobject_item(&item2) && self.verify_uobject(handle, item2.object) {
                        // objects_ptr の先がさらにポインタ配列だった場合
                        return Some((base_addr, first_chunk, item2.object));
                    }
                }
            }
        }

        None
    }

    /// FUObjectItem が妥当な値を持っているか検証（緩い版）
    fn is_valid_fuobject_item(&self, item: &super::structures::FUObjectItem) -> bool {
        // object は有効なヒープポインタ
        if item.object == 0 || !self.is_valid_pointer(item.object) {
            return false;
        }

        // 16バイト版では flags と cluster_root_index のみチェック
        // flags は EObjectFlags - 通常0だが、いくつかのビットが設定されることがある
        // 負の値（符号ビット設定）はアドレスの一部の可能性が高いので除外
        if item.flags < 0 {
            return false;
        }

        true
    }

    /// UObject が有効かどうか確認
    fn verify_uobject(&self, handle: WinHandle, obj_addr: usize) -> bool {
        use super::structures::UObject;

        if let Ok(obj) = UObject::read(handle, obj_addr) {
            // vtable が有効なコードポインタであること
            let vtable_valid = obj.vtable > self.module_base
                && obj.vtable < self.module_base + self.module_size;

            // class ポインタが有効であること（ヒープ上）
            let class_valid = self.is_valid_pointer(obj.class);

            // name.comparison_index が妥当な範囲であること
            let name_valid = obj.name.comparison_index < 10_000_000;

            return vtable_valid && class_valid && name_valid;
        }
        false
    }

    /// ポインタが有効なアドレス範囲かチェック
    fn is_valid_pointer(&self, ptr: usize) -> bool {
        ptr > 0x10000 && ptr < 0x7FFFFFFFFFFF
    }

    /// 最初のN個のスロットで有効なオブジェクトをカウント
    fn count_valid_objects(&self, handle: WinHandle, objects_ptr: usize, count: usize) -> usize {
        use super::structures::FUObjectItem;

        let mut valid = 0;

        // 最初のチャンクを読む
        let chunk_ptr_data = match read_process_memory(handle, objects_ptr, 8) {
            Ok(data) => data,
            Err(_) => return 0,
        };
        let first_chunk = usize::from_le_bytes(chunk_ptr_data[..8].try_into().unwrap());

        if !self.is_valid_pointer(first_chunk) {
            return 0;
        }

        for i in 0..count {
            let item_addr = first_chunk + i * FUObjectItem::SIZE_UE5;
            if let Ok(item) = FUObjectItem::read(handle, item_addr) {
                // FUObjectItem の検証を追加
                if self.is_valid_fuobject_item(&item) && self.verify_uobject(handle, item.object) {
                    valid += 1;
                }
            }
        }

        valid
    }

    /// チャンク配列から全オブジェクトを読み取る
    fn read_objects_from_chunk_array(&self, handle: WinHandle, chunk_array_ptr: usize) -> Result<Vec<usize>> {
        use super::structures::FUObjectItem;

        let mut objects = Vec::new();
        const ELEMENTS_PER_CHUNK: usize = 64 * 1024;
        const MAX_CHUNKS: usize = 20;

        for chunk_index in 0..MAX_CHUNKS {
            let chunk_ptr_addr = chunk_array_ptr + (chunk_index * 8);
            let chunk_data = match read_process_memory(handle, chunk_ptr_addr, 8) {
                Ok(data) => data,
                Err(_) => break,
            };
            let chunk_ptr = usize::from_le_bytes(chunk_data[..8].try_into().unwrap());

            // チャンク終端または不正なポインタ
            if chunk_ptr == 0 {
                tracing::info!("Chunk array ends at index {} (null)", chunk_index);
                break;
            }

            // 有効なヒープポインタかチェック（より厳しく）
            if chunk_ptr < 0x100000 || chunk_ptr > 0x7FFFFFFFFFFF {
                tracing::info!("Chunk array ends at index {} (invalid ptr 0x{:X})", chunk_index, chunk_ptr);
                break;
            }

            // 最初のアイテムを検証して、これが本当にFUObjectItem配列か確認
            if chunk_index == 0 {
                if let Ok(first_item) = FUObjectItem::read(handle, chunk_ptr) {
                    if !self.is_valid_fuobject_item(&first_item) {
                        tracing::warn!("First FUObjectItem validation failed: flags=0x{:X}, cluster={}, serial={}",
                            first_item.flags, first_item.cluster_root_index, first_item.serial_number);
                        return Err(EngineError::InitializationFailed(
                            "Invalid FUObjectItem structure detected".into(),
                        ));
                    }
                }
            }

            // このチャンク内のオブジェクトを読む
            let mut chunk_objects = 0;
            let mut consecutive_empty = 0;
            for within_chunk in 0..ELEMENTS_PER_CHUNK {
                let item_addr = chunk_ptr + (within_chunk * FUObjectItem::SIZE_UE5);
                match FUObjectItem::read(handle, item_addr) {
                    Ok(item) => {
                        if item.is_valid() && self.is_valid_fuobject_item(&item) {
                            objects.push(item.object);
                            chunk_objects += 1;
                            consecutive_empty = 0;
                        } else {
                            consecutive_empty += 1;
                            // 連続100個空なら終了
                            if consecutive_empty > 100 {
                                break;
                            }
                        }
                    }
                    Err(_) => break,
                }
            }
            tracing::info!("Chunk {} at 0x{:X}: {} valid objects", chunk_index, chunk_ptr, chunk_objects);
        }

        tracing::info!("Total: {} objects from chunk array", objects.len());

        if objects.is_empty() {
            return Err(EngineError::InitializationFailed(
                "No objects found in chunk array".into(),
            ));
        }

        Ok(objects)
    }

    /// データセクションをスキャンして UObject 配列を直接探す
    fn scan_for_uobject_array(&self, handle: WinHandle) -> Option<usize> {
        use super::structures::FUObjectItem;

        // モジュールの .data セクションあたりをスキャン
        // GUObjectArray は通常 .data セクションにある
        // スキャン範囲を狭めて高速化
        let scan_start = self.module_base + (self.module_size * 3 / 4);  // モジュール後半1/4から
        let scan_end = self.module_base + self.module_size;
        let step = 0x1000;  // 4KB単位で探す

        tracing::info!("Scanning data sections from 0x{:X} to 0x{:X} (limited range)...", scan_start, scan_end);

        for addr in (scan_start..scan_end).step_by(step) {
            if let Ok(data) = read_process_memory(handle, addr, step) {
                // 8バイトアラインメントでポインタっぽい値を探す
                for offset in (0..data.len() - 64).step_by(8) {
                    let ptr1 = usize::from_le_bytes(data[offset..offset+8].try_into().unwrap());

                    // ヒープポインタっぽい値を見つけたら
                    if ptr1 > 0x100000 && ptr1 < 0x7FFFFFFFFFFF && !Self::looks_like_ascii(ptr1) {
                        // そのポインタの先がチャンク配列かどうか確認
                        if let Some(result) = self.try_objects_pointer(handle, addr + offset, ptr1) {
                            let valid_count = self.count_valid_objects(handle, ptr1, 10);
                            if valid_count >= 5 {
                                tracing::info!("Found UObject array at scan offset 0x{:X} with {} valid objects",
                                    addr + offset, valid_count);
                                tracing::info!("  ptr1 (Objects) = 0x{:X}", ptr1);
                                // ptr1 を直接返す（これがチャンク配列へのポインタ配列）
                                return Some(ptr1);
                            }
                        }
                    }
                }
            }
        }

        tracing::info!("Direct scan completed, no valid UObject array found");
        None
    }

    /// ProcessEvent のアドレスを検索
    pub(super) fn find_process_event_impl(&self) -> Result<usize> {
        let handle = unsafe { std::mem::transmute::<usize, WinHandle>(self.process_handle) };

        let module_base = self.module_base;
        let module_size = self.module_size;

        let patterns = VersionSignatures::all();

        for pattern_str in patterns.process_event_patterns {
            let pattern = Pattern::from_string(pattern_str);
            if let Ok(results) = scan_pattern(handle, &pattern, module_base, module_size) {
                if let Some(result) = results.first() {
                    tracing::info!("Found ProcessEvent at 0x{:X}", result.address);
                    return Ok(result.address);
                }
            }
        }

        Err(EngineError::InitializationFailed(
            "ProcessEvent not found".into(),
        ))
    }

    /// FName から文字列を取得
    ///
    /// UE5.5 の FNameEntryId:
    /// - Block = id >> 16
    /// - Offset = id & 0xFFFF
    /// - entry_addr = Blocks[Block] + Offset * 2
    pub(super) fn get_fname_impl(&self, index: u32) -> Result<String> {
        use super::structures::FNameEntryAllocator;

        let handle = unsafe { std::mem::transmute::<usize, WinHandle>(self.process_handle) };

        // デバッグ：最初の数回だけログ出力
        static CALL_COUNT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let count = CALL_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let should_log = count < 3;

        if should_log {
            tracing::info!("get_fname_impl: index=0x{:X} ({}), gnames=0x{:X}", index, index, self.gnames);

            // GNames周辺のデータをダンプ（もっと広い範囲）
            if let Ok(raw) = read_process_memory(handle, self.gnames, 128) {
                tracing::info!("  GNames raw data (128 bytes):");
                for i in 0..16 {
                    let offset = i * 8;
                    let val = usize::from_le_bytes(raw[offset..offset+8].try_into().unwrap());
                    tracing::info!("    [{}] 0x{:02X}: {:02X?} = 0x{:X}", i, offset, &raw[offset..offset+8], val);
                }

                // ポインタっぽい値（0x7FF... や大きなヒープアドレス）を探す
                for i in 0..16 {
                    let offset = i * 8;
                    let val = usize::from_le_bytes(raw[offset..offset+8].try_into().unwrap());
                    if val > 0x10000000000 && val < 0x800000000000 {
                        // これは有効なポインタかもしれない - さらに読んでみる
                        if let Ok(inner) = read_process_memory(handle, val, 16) {
                            let inner_val = usize::from_le_bytes(inner[0..8].try_into().unwrap());
                            tracing::info!("    [{}] -> 0x{:X} contains: {:02X?} (ptr: 0x{:X})", i, val, &inner[..8], inner_val);
                        }
                    }
                }
            }
        }

        // GNames が FNamePool を指している場合:
        // FNamePool の最初のメンバーは FNameEntryAllocator Entries
        // FNameEntryAllocator の構造:
        // - FRWLock Lock (Windows SRWLOCK = 8 bytes)
        // - uint32 CurrentBlock (4 bytes)
        // - uint32 CurrentByteCursor (4 bytes)
        // - uint8* Blocks[8192]
        //
        // したがって Blocks は GNames + 16 から始まる
        //
        // ただし、パターンが間違った場所を指している可能性がある
        // 複数のオフセットを試す

        // FNamePool/FNameEntryAllocator の Blocks 配列を見つける
        // GNames が指す構造は:
        // - FRWLock Lock (8 bytes on Windows)
        // - uint32 CurrentBlock
        // - uint32 CurrentByteCursor
        // - uint8* Blocks[8192]
        //
        // ただし、GNames パターンが間違った場所を指している場合がある
        // 正しい Blocks を見つけるため、複数のオフセットとアドレス周辺を探索

        // まず index=0 のエントリ (通常 "None") を読める正しい Blocks を探す
        let mut blocks_addr = self.gnames + 16;  // デフォルト
        let offsets_to_try: &[i64] = &[16, 0, 32, 8, 24, -16, -32, -8, 48, 64];

        for &offset in offsets_to_try {
            let try_addr = match (self.gnames as i64).checked_add(offset) {
                Some(a) if a > 0 => a as usize,
                _ => continue,
            };

            // ポインタを読む
            let ptr_data = match read_process_memory(handle, try_addr, 8) {
                Ok(data) => data,
                Err(_) => continue,
            };
            let block0 = usize::from_le_bytes(ptr_data[..8].try_into().unwrap());

            // ヒープアドレスでないと Blocks ではない
            // 0x7F0000000000 以上はカーネル空間
            if block0 < 0x10000 || block0 >= 0x7F0000000000 {
                continue;
            }

            // Block0 の先頭 (FNameEntry header) を読む
            let entry_data = match read_process_memory(handle, block0, 8) {
                Ok(data) => data,
                Err(_) => continue,
            };

            let header = u16::from_le_bytes([entry_data[0], entry_data[1]]);
            let is_wide = (header & 1) != 0;
            let len = (header >> 6) as usize;

            // 最初のエントリは "None" (長さ 4, ANSI)
            // または短い名前であるべき
            if len == 0 || len > 64 {
                continue;
            }

            // 文字列データを読んで検証
            let str_bytes = if is_wide { len * 2 } else { len };
            let str_data = match read_process_memory(handle, block0 + 2, str_bytes) {
                Ok(data) => data,
                Err(_) => continue,
            };

            // ASCII で印刷可能な文字列かチェック
            let mut valid_string = true;
            if !is_wide {
                for &b in &str_data {
                    if !b.is_ascii_alphanumeric() && b != b'_' && b != b' ' {
                        valid_string = false;
                        break;
                    }
                }
            }

            if valid_string && should_log {
                let name = if is_wide {
                    let chars: Vec<u16> = str_data.chunks_exact(2)
                        .map(|c| u16::from_le_bytes([c[0], c[1]]))
                        .collect();
                    String::from_utf16_lossy(&chars)
                } else {
                    String::from_utf8_lossy(&str_data).to_string()
                };
                tracing::info!("  Found valid Blocks at offset {}: addr=0x{:X}, Blocks[0]=0x{:X}",
                    offset, try_addr, block0);
                tracing::info!("    First entry: header=0x{:04X}, len={}, wide={}, name='{}'",
                    header, len, is_wide, name);

                // "None" または他の既知の名前かチェック
                if name == "None" || name.starts_with("ByteProperty") || name.starts_with("Int") {
                    blocks_addr = try_addr;
                    break;
                }
            }

            // 最初に見つかった有効な Blocks を使用
            if valid_string {
                blocks_addr = try_addr;
                if should_log {
                    tracing::info!("  Using blocks_addr=0x{:X}", blocks_addr);
                }
                break;
            }
        }

        let entry_addr = FNameEntryAllocator::get_entry_address(blocks_addr, handle, index)?;

        let entry_header_data = read_process_memory(handle, entry_addr, 2)?;
        let header = u16::from_le_bytes([entry_header_data[0], entry_header_data[1]]);

        let is_wide = (header & 1) != 0;

        // UE5.5 での長さビット:
        // WITH_CASE_PRESERVING_NAME=0 の場合: LowercaseProbeHash(5bits) + Len(10bits) = bits 1-15
        // WITH_CASE_PRESERVING_NAME=1 の場合: Len(15bits) = bits 1-15
        // ランタイムビルドは通常 WITH_CASE_PRESERVING_NAME=0
        // header >> 6 で Len を取得 (5bits hash + 10bits len, hash は bit 1-5)
        let len = (header >> 6) as usize;

        if len == 0 {
            return Ok(String::new());
        }

        // 長さが異常に大きい場合はエラー
        if len > 1024 {
            return Err(EngineError::InitializationFailed(
                format!("FName entry length too large: {} (header=0x{:04X})", len, header)
            ));
        }

        let string_data = read_process_memory(handle, entry_addr + 2, if is_wide { len * 2 } else { len })?;

        if is_wide {
            let wide_chars: Vec<u16> = string_data
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            Ok(String::from_utf16_lossy(&wide_chars))
        } else {
            Ok(String::from_utf8_lossy(&string_data).to_string())
        }
    }

    /// UObject の名前を取得
    pub(super) fn get_object_name_impl(&self, obj_addr: usize) -> Result<String> {
        let handle = unsafe { std::mem::transmute::<usize, WinHandle>(self.process_handle) };

        let obj = UObject::read(handle, obj_addr)?;
        self.get_fname_impl(obj.name.comparison_index)
    }

    /// GObjects から全オブジェクトを取得
    pub(super) fn get_all_objects_impl(&self) -> Result<Vec<usize>> {
        use super::structures::{FChunkedFixedUObjectArray, FUObjectItem};
        use crate::platform::windows::read_process_memory;

        let handle = unsafe { std::mem::transmute::<usize, WinHandle>(self.process_handle) };

        tracing::info!("get_all_objects_impl: gobjects = 0x{:X}", self.gobjects);

        // デバッグ: gobjects周辺のメモリダンプ
        if let Ok(raw) = read_process_memory(handle, self.gobjects, 64) {
            tracing::info!("Raw data at gobjects 0x{:X}:", self.gobjects);
            tracing::info!("  0-8:   {:02X?} (ptr: 0x{:X})", &raw[0..8], usize::from_le_bytes(raw[0..8].try_into().unwrap()));
            tracing::info!("  8-16:  {:02X?} (ptr: 0x{:X})", &raw[8..16], usize::from_le_bytes(raw[8..16].try_into().unwrap()));
            tracing::info!("  16-24: {:02X?} (i32s: {}, {})", &raw[16..24],
                i32::from_le_bytes(raw[16..20].try_into().unwrap()),
                i32::from_le_bytes(raw[20..24].try_into().unwrap()));
            tracing::info!("  24-32: {:02X?} (i32s: {}, {})", &raw[24..32],
                i32::from_le_bytes(raw[24..28].try_into().unwrap()),
                i32::from_le_bytes(raw[28..32].try_into().unwrap()));
        }

        // まず gobjects が直接チャンク配列へのポインタ配列を指しているか確認
        // (find_gobjects_impl は objects_ptr を返すようになっている)
        if let Ok(chunk_data) = read_process_memory(handle, self.gobjects, 8) {
            let first_chunk = usize::from_le_bytes(chunk_data[..8].try_into().unwrap());
            tracing::info!("First value at gobjects: 0x{:X}", first_chunk);

            // first_chunk がヒープポインタっぽければ、gobjects はチャンク配列を指している
            if first_chunk > 0x100000 && first_chunk < 0x7FFFFFFFFFFF {
                // デバッグ: first_chunk のデータを出力
                if let Ok(chunk_raw) = read_process_memory(handle, first_chunk, 48) {
                    tracing::info!("Raw data at first_chunk 0x{:X}:", first_chunk);
                    tracing::info!("  0-8:   {:02X?} (ptr: 0x{:X})", &chunk_raw[0..8], usize::from_le_bytes(chunk_raw[0..8].try_into().unwrap()));
                    tracing::info!("  8-16:  {:02X?} (i32s: 0x{:X}, 0x{:X})", &chunk_raw[8..16],
                        i32::from_le_bytes(chunk_raw[8..12].try_into().unwrap()),
                        i32::from_le_bytes(chunk_raw[12..16].try_into().unwrap()));
                    tracing::info!("  16-24: {:02X?} (i32s: {}, {})", &chunk_raw[16..24],
                        i32::from_le_bytes(chunk_raw[16..20].try_into().unwrap()),
                        i32::from_le_bytes(chunk_raw[20..24].try_into().unwrap()));
                }

                // 最初の FUObjectItem を読んでみる
                if let Ok(item) = FUObjectItem::read(handle, first_chunk) {
                    tracing::info!("First FUObjectItem: object=0x{:X}, flags=0x{:X}, cluster={}, serial={}, refcount={}",
                        item.object, item.flags, item.cluster_root_index, item.serial_number, item.ref_count);

                    if item.object != 0 && item.object > 0x10000 {
                        // gobjects はチャンク配列を直接指している
                        tracing::info!("gobjects is a direct chunk array pointer, reading objects...");
                        return self.read_objects_from_chunk_array(handle, self.gobjects);
                    }
                }
            }
        }

        // まず FUObjectArray として読んでみる
        match FUObjectArray::read(handle, self.gobjects) {
            Ok(uobject_array) => {
                // ObjFirstGCIndex が妥当な値かチェック
                if uobject_array.obj_first_gc_index >= 0
                    && uobject_array.obj_first_gc_index < 1_000_000
                    && uobject_array.obj_objects.num_elements > 0
                    && uobject_array.obj_objects.num_chunks > 0
                    && uobject_array.obj_objects.num_chunks <= uobject_array.obj_objects.max_chunks
                {
                    tracing::info!("Reading {} objects from FUObjectArray", uobject_array.obj_objects.num_elements);
                    return Ok(uobject_array.get_all_objects(handle));
                }
                tracing::warn!("FUObjectArray has invalid fields (ObjFirstGCIndex={}, NumElements={}, NumChunks={}), trying alternatives",
                    uobject_array.obj_first_gc_index,
                    uobject_array.obj_objects.num_elements,
                    uobject_array.obj_objects.num_chunks);
            }
            Err(e) => {
                tracing::warn!("Failed to read FUObjectArray: {}", e);
            }
        }

        // FChunkedFixedUObjectArray として直接読んでみる
        if let Ok(chunked_array) = FChunkedFixedUObjectArray::read(handle, self.gobjects) {
            tracing::info!("FChunkedFixedUObjectArray: objects=0x{:X}, num_elements={}, num_chunks={}, max_chunks={}",
                chunked_array.objects, chunked_array.num_elements, chunked_array.num_chunks, chunked_array.max_chunks);

            if chunked_array.num_elements > 0
                && chunked_array.num_chunks > 0
                && chunked_array.num_chunks <= chunked_array.max_chunks
            {
                tracing::info!("Reading {} objects from FChunkedFixedUObjectArray", chunked_array.num_elements);

                // 最初のチャンクを確認
                if let Ok(chunk_data) = read_process_memory(handle, chunked_array.objects, 8) {
                    let first_chunk = usize::from_le_bytes(chunk_data[..8].try_into().unwrap());
                    tracing::info!("First chunk pointer: 0x{:X}", first_chunk);

                    // 最初のアイテムを読んでみる
                    if first_chunk > 0x10000 {
                        if let Ok(item) = FUObjectItem::read(handle, first_chunk) {
                            tracing::info!("First FUObjectItem: object=0x{:X}, flags=0x{:X}, valid={}",
                                item.object, item.flags, item.is_valid());
                        }
                    }
                }

                let mut objects = Vec::new();
                let mut failed_count = 0;
                for i in 0..chunked_array.num_elements {
                    match chunked_array.get_object_item_address(handle, i) {
                        Ok(item_addr) => {
                            match FUObjectItem::read(handle, item_addr) {
                                Ok(item) => {
                                    if item.is_valid() {
                                        objects.push(item.object);
                                    }
                                }
                                Err(_) => { failed_count += 1; continue; }
                            }
                        }
                        Err(_) => { failed_count += 1; continue; }
                    }
                }

                tracing::info!("Read {} valid objects, {} failed", objects.len(), failed_count);

                if !objects.is_empty() {
                    return Ok(objects);
                }
            }
        }

        // 代替レイアウト: PreAllocatedObjects がない構造
        // Objects(8) + MaxElements(4) + NumElements(4) + MaxChunks(4) + NumChunks(4)
        if let Ok(data) = read_process_memory(handle, self.gobjects, 24) {
            let objects_ptr = usize::from_le_bytes(data[0..8].try_into().unwrap());
            let max_elements = i32::from_le_bytes(data[8..12].try_into().unwrap());
            let num_elements = i32::from_le_bytes(data[12..16].try_into().unwrap());
            let max_chunks = i32::from_le_bytes(data[16..20].try_into().unwrap());
            let num_chunks = i32::from_le_bytes(data[20..24].try_into().unwrap());

            if objects_ptr != 0
                && num_elements > 0
                && num_elements < 10_000_000
                && num_chunks > 0
                && num_chunks <= max_chunks
            {
                tracing::info!("Reading {} objects from alternative layout (Objects=0x{:X}, NumChunks={})",
                    num_elements, objects_ptr, num_chunks);

                let mut objects = Vec::new();
                const ELEMENTS_PER_CHUNK: i32 = 64 * 1024;

                for i in 0..num_elements {
                    let chunk_index = i / ELEMENTS_PER_CHUNK;
                    let within_chunk = i % ELEMENTS_PER_CHUNK;

                    // チャンクポインタを読む
                    let chunk_ptr_addr = objects_ptr + (chunk_index as usize * 8);
                    if let Ok(chunk_data) = read_process_memory(handle, chunk_ptr_addr, 8) {
                        let chunk_ptr = usize::from_le_bytes(chunk_data[..8].try_into().unwrap());
                        if chunk_ptr != 0 {
                            let item_addr = chunk_ptr + (within_chunk as usize * FUObjectItem::SIZE_UE5);
                            if let Ok(item) = FUObjectItem::read(handle, item_addr) {
                                if item.is_valid() {
                                    objects.push(item.object);
                                }
                            }
                        }
                    }
                }

                if !objects.is_empty() {
                    return Ok(objects);
                }
            }
        }

        // 最後の手段: gobjects が Objects ポインタ配列を直接指している場合
        // (refresh_gobjects の "last resort" で設定された場合)
        tracing::info!("Trying direct Objects array access at 0x{:X}...", self.gobjects);

        if let Ok(first_ptr_data) = read_process_memory(handle, self.gobjects, 8) {
            let objects_ptr = usize::from_le_bytes(first_ptr_data[..8].try_into().unwrap());

            if objects_ptr != 0 && objects_ptr > 0x10000 {
                // objects_ptr がチャンク配列のポインタ配列を指していると仮定
                // 最大チャンク数を推定（通常は数個〜数十個）
                let mut objects = Vec::new();
                const ELEMENTS_PER_CHUNK: usize = 64 * 1024;
                const MAX_CHUNKS_TO_TRY: usize = 20;

                for chunk_index in 0..MAX_CHUNKS_TO_TRY {
                    let chunk_ptr_addr = objects_ptr + (chunk_index * 8);
                    if let Ok(chunk_data) = read_process_memory(handle, chunk_ptr_addr, 8) {
                        let chunk_ptr = usize::from_le_bytes(chunk_data[..8].try_into().unwrap());
                        if chunk_ptr == 0 {
                            // チャンクが終わり
                            break;
                        }
                        if chunk_ptr < 0x10000 {
                            continue;
                        }

                        // このチャンク内のオブジェクトを読む
                        for within_chunk in 0..ELEMENTS_PER_CHUNK {
                            let item_addr = chunk_ptr + (within_chunk * FUObjectItem::SIZE_UE5);
                            match FUObjectItem::read(handle, item_addr) {
                                Ok(item) => {
                                    if item.is_valid() {
                                        objects.push(item.object);
                                    } else if item.object == 0 && within_chunk > 0 {
                                        // 空のスロットが続いたら次のチャンクへ
                                        // (ただし最初のスロットは空でも続ける)
                                        break;
                                    }
                                }
                                Err(_) => break,
                            }
                        }
                    } else {
                        break;
                    }
                }

                if !objects.is_empty() {
                    tracing::info!("Found {} objects via direct access", objects.len());
                    return Ok(objects);
                }
            }
        }

        Err(EngineError::InitializationFailed(
            format!("Failed to read objects from GObjects at 0x{:X}", self.gobjects)
        ))
    }

    /// クラス名で UClass を検索
    pub(super) fn find_class_by_name_impl(&self, name: &str) -> Result<usize> {
        let all_objects = self.get_all_objects_impl()?;

        for obj_addr in all_objects {
            if let Ok(obj_name) = self.get_object_name_impl(obj_addr) {
                if obj_name == name {
                    // UClass かどうかを確認（Class->Class == Class なら UClass）
                    let handle =
                        unsafe { std::mem::transmute::<usize, WinHandle>(self.process_handle) };
                    let obj = UObject::read(handle, obj_addr)?;

                    if obj.class != 0 {
                        let class_obj = UObject::read(handle, obj.class)?;
                        if class_obj.class == obj.class {
                            // これは UClass
                            return Ok(obj_addr);
                        }
                    }
                }
            }
        }

        Err(EngineError::ClassNotFound(name.to_string()))
    }
}
