/// Unreal Engine internal structures

use crate::platform::windows::{read_process_memory, HANDLE};

/// UObject 基底クラス
#[repr(C)]
#[derive(Clone, Copy)]
pub struct UObject {
    pub vtable: usize,
    pub object_flags: u32,
    pub internal_index: i32,
    pub class: usize, // UClass*
    pub name: FName,
    pub outer: usize, // UObject*
}

impl UObject {
    pub fn read(handle: HANDLE, address: usize) -> Result<Self, anyhow::Error> {
        let data = read_process_memory(handle, address, std::mem::size_of::<Self>())?;
        Ok(unsafe { std::ptr::read(data.as_ptr() as *const Self) })
    }
}

/// FName - UE の文字列表現
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FName {
    pub comparison_index: u32,
    pub number: u32,
}

impl FName {
    pub fn read(handle: HANDLE, address: usize) -> Result<Self, anyhow::Error> {
        let data = read_process_memory(handle, address, std::mem::size_of::<Self>())?;
        Ok(unsafe { std::ptr::read(data.as_ptr() as *const Self) })
    }
}

/// FNameEntry - GNames の要素 (UE4.23+)
#[repr(C)]
pub struct FNameEntry {
    pub header: u16,   // フラグ + 長さ
    pub name: [u8; 1024], // 可変長だが固定サイズで近似
}

impl FNameEntry {
    pub fn read(handle: HANDLE, address: usize) -> Result<Self, anyhow::Error> {
        let data = read_process_memory(handle, address, std::mem::size_of::<Self>())?;
        Ok(unsafe { std::ptr::read(data.as_ptr() as *const Self) })
    }

    pub fn is_wide(&self) -> bool {
        (self.header & 1) != 0
    }

    pub fn len(&self) -> usize {
        (self.header >> 6) as usize
    }

    pub fn get_string(&self) -> String {
        let len = self.len();
        if len == 0 {
            return String::new();
        }

        if self.is_wide() {
            // UTF-16
            let wide_chars: Vec<u16> = self.name[..len * 2]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            String::from_utf16_lossy(&wide_chars)
        } else {
            // ASCII
            String::from_utf8_lossy(&self.name[..len]).to_string()
        }
    }
}

/// FNameEntryAllocator - UE5の名前エントリアロケータ
/// GNames が指す実際の構造
///
/// UE5.5 での構造:
/// - FRWLock Lock (サイズは実装依存、通常8-16バイト)
/// - uint32 CurrentBlock
/// - uint32 CurrentByteCursor
/// - uint8* Blocks[8192]
///
/// ただし、パターンマッチで見つかるアドレスは Blocks 配列を直接指す場合が多い
#[repr(C)]
pub struct FNameEntryAllocator {
    // Blocks配列のアドレス（GNamesが直接これを指す場合が多い）
    pub blocks_addr: usize,
}

impl FNameEntryAllocator {
    /// UE5.5 の定数
    pub const BLOCK_OFFSET_BITS: u32 = 16;
    pub const BLOCK_OFFSETS: u32 = 1 << Self::BLOCK_OFFSET_BITS;  // 65536
    pub const STRIDE: usize = 2;  // alignof(FNameEntry)

    /// FNameEntryId から Block と Offset を取得
    pub fn decode_id(id: u32) -> (u32, u32) {
        let block = id >> Self::BLOCK_OFFSET_BITS;
        let offset = id & (Self::BLOCK_OFFSETS - 1);
        (block, offset)
    }

    /// FName index から FNameEntry のアドレスを取得
    /// blocks_addr は Blocks[8192] 配列の先頭アドレス
    pub fn get_entry_address(
        blocks_addr: usize,
        handle: HANDLE,
        index: u32,
    ) -> Result<usize, anyhow::Error> {
        let (block_index, offset) = Self::decode_id(index);

        // Blocks[block_index] を読み取る
        let block_ptr_addr = blocks_addr + (block_index as usize * 8);
        let block_ptr_data = read_process_memory(handle, block_ptr_addr, 8)?;
        let block_ptr = usize::from_le_bytes(block_ptr_data[..8].try_into().unwrap());

        if block_ptr == 0 {
            return Err(anyhow::anyhow!("Block {} is null (index=0x{:X})", block_index, index));
        }

        // entry_addr = Blocks[block] + offset * Stride
        let entry_addr = block_ptr + (offset as usize * Self::STRIDE);

        Ok(entry_addr)
    }
}

/// FNamePool - 後方互換性のためのエイリアス
pub type FNamePool = FNameEntryAllocator;

/// FUObjectItem - GObjects の要素
/// UE5.5では構造が変更されている可能性あり
/// 実際のサイズは実行時に検出する
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FUObjectItem {
    pub object: usize,          // UObject* (8 bytes)
    pub flags: i32,             // (4 bytes)
    pub cluster_root_index: i32, // (4 bytes)
    pub serial_number: i32,     // (4 bytes) - might not exist in some versions
    pub ref_count: i32,         // UE5.5で追加? (4 bytes)
}

impl FUObjectItem {
    /// UE5.5用のサイズ - 実際は16バイトかもしれない
    /// Object(8) + Flags(4) + ClusterRootIndex(4) = 16 bytes
    pub const SIZE_UE5: usize = 16;  // Changed from 24 to 16

    /// UE4用のサイズ (24 bytes with serial + padding)
    #[allow(dead_code)]
    pub const SIZE_UE4: usize = 24;

    /// 最小サイズでの読み取り（16バイト版）
    pub fn read(handle: HANDLE, address: usize) -> Result<Self, anyhow::Error> {
        let data = read_process_memory(handle, address, 16)?;
        Ok(Self {
            object: usize::from_le_bytes(data[0..8].try_into().unwrap()),
            flags: i32::from_le_bytes(data[8..12].try_into().unwrap()),
            cluster_root_index: i32::from_le_bytes(data[12..16].try_into().unwrap()),
            serial_number: 0,  // Not present in 16-byte version
            ref_count: 0,      // Not present in 16-byte version
        })
    }

    /// 24バイト版での読み取り
    pub fn read_24(handle: HANDLE, address: usize) -> Result<Self, anyhow::Error> {
        let data = read_process_memory(handle, address, 24)?;
        Ok(unsafe { std::ptr::read(data.as_ptr() as *const Self) })
    }

    pub fn is_valid(&self) -> bool {
        self.object != 0 && (self.flags & 1) == 0 // RF_NoFlags
    }
}

/// FChunkedFixedUObjectArray - UE5のチャンク配列
/// GUObjectArray.ObjObjects の実際の型
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FChunkedFixedUObjectArray {
    pub objects: usize,              // FUObjectItem** - チャンクへのポインタ配列
    pub pre_allocated_objects: usize, // FUObjectItem* - 事前割り当てメモリ
    pub max_elements: i32,
    pub num_elements: i32,
    pub max_chunks: i32,
    pub num_chunks: i32,
}

impl FChunkedFixedUObjectArray {
    pub const NUM_ELEMENTS_PER_CHUNK: usize = 64 * 1024;

    pub fn read(handle: HANDLE, address: usize) -> Result<Self, anyhow::Error> {
        let data = read_process_memory(handle, address, std::mem::size_of::<Self>())?;
        Ok(unsafe { std::ptr::read(data.as_ptr() as *const Self) })
    }

    /// インデックスから FUObjectItem のアドレスを取得
    pub fn get_object_item_address(&self, handle: HANDLE, index: i32) -> Result<usize, anyhow::Error> {
        if index < 0 || index >= self.num_elements {
            return Err(anyhow::anyhow!("Index {} out of bounds (max: {})", index, self.num_elements));
        }

        let chunk_index = (index as usize) / Self::NUM_ELEMENTS_PER_CHUNK;
        let within_chunk_index = (index as usize) % Self::NUM_ELEMENTS_PER_CHUNK;

        // objects[chunk_index] を読み取ってチャンクのアドレスを取得
        let chunk_ptr_addr = self.objects + (chunk_index * 8);
        let chunk_ptr_data = read_process_memory(handle, chunk_ptr_addr, 8)
            .map_err(|e| anyhow::anyhow!("Failed to read chunk pointer at 0x{:X}: {}", chunk_ptr_addr, e))?;
        let chunk_ptr = usize::from_le_bytes(chunk_ptr_data[..8].try_into().unwrap());

        if chunk_ptr == 0 {
            return Err(anyhow::anyhow!("Chunk {} is null at 0x{:X}", chunk_index, chunk_ptr_addr));
        }

        // chunk[within_chunk_index] のアドレスを計算
        let item_addr = chunk_ptr + (within_chunk_index * FUObjectItem::SIZE_UE5);
        Ok(item_addr)
    }
}

/// FUObjectArray - GObjects の実体 (UE5.5)
/// これはGUObjectArrayグローバル変数の構造
#[repr(C)]
#[derive(Debug)]
pub struct FUObjectArray {
    pub obj_first_gc_index: i32,           // 4 bytes
    pub obj_last_non_gc_index: i32,        // 4 bytes
    pub max_objects_not_consid_by_gc: i32, // 4 bytes
    pub open_for_disregard_for_gc: bool,   // 1 byte + padding (4 bytes total with alignment)
    _padding: [u8; 3],                      // padding
    // ここから FChunkedFixedUObjectArray が埋め込まれる
    pub obj_objects: FChunkedFixedUObjectArray,
}

impl FUObjectArray {
    pub fn read(handle: HANDLE, address: usize) -> Result<Self, anyhow::Error> {
        // まず生データを読む
        let data = read_process_memory(handle, address, 64)?;

        // 構造を手動でパース
        let obj_first_gc_index = i32::from_le_bytes(data[0..4].try_into().unwrap());
        let obj_last_non_gc_index = i32::from_le_bytes(data[4..8].try_into().unwrap());
        let max_objects_not_consid_by_gc = i32::from_le_bytes(data[8..12].try_into().unwrap());
        let open_for_disregard_for_gc = data[12] != 0;

        // FChunkedFixedUObjectArray は 16バイト目から始まる (alignment考慮)
        let obj_objects_offset = 16;
        let obj_objects = FChunkedFixedUObjectArray {
            objects: usize::from_le_bytes(data[obj_objects_offset..obj_objects_offset+8].try_into().unwrap()),
            pre_allocated_objects: usize::from_le_bytes(data[obj_objects_offset+8..obj_objects_offset+16].try_into().unwrap()),
            max_elements: i32::from_le_bytes(data[obj_objects_offset+16..obj_objects_offset+20].try_into().unwrap()),
            num_elements: i32::from_le_bytes(data[obj_objects_offset+20..obj_objects_offset+24].try_into().unwrap()),
            max_chunks: i32::from_le_bytes(data[obj_objects_offset+24..obj_objects_offset+28].try_into().unwrap()),
            num_chunks: i32::from_le_bytes(data[obj_objects_offset+28..obj_objects_offset+32].try_into().unwrap()),
        };

        Ok(Self {
            obj_first_gc_index,
            obj_last_non_gc_index,
            max_objects_not_consid_by_gc,
            open_for_disregard_for_gc,
            _padding: [0; 3],
            obj_objects,
        })
    }

    /// インデックスから UObject のアドレスを取得
    pub fn get_object_address(&self, handle: HANDLE, index: i32) -> Result<usize, anyhow::Error> {
        let item_addr = self.obj_objects.get_object_item_address(handle, index)?;
        let item = FUObjectItem::read(handle, item_addr)?;

        if !item.is_valid() {
            return Err(anyhow::anyhow!("Invalid object at index {}", index));
        }

        Ok(item.object)
    }

    /// すべての有効な UObject のアドレスを取得
    pub fn get_all_objects(&self, handle: HANDLE) -> Vec<usize> {
        let mut objects = Vec::new();

        for i in 0..self.obj_objects.num_elements {
            if let Ok(addr) = self.get_object_address(handle, i) {
                objects.push(addr);
            }
        }

        objects
    }
}

/// UField - メタデータの基底
#[repr(C)]
pub struct UField {
    // UObject を継承 (省略)
    pub next: usize, // UField*
}

/// UStruct - 構造化された型情報
#[repr(C)]
pub struct UStruct {
    // UField を継承
    pub super_struct: usize, // UStruct*
    pub children: usize,     // UField*
    pub child_properties: usize,
    pub properties_size: i32,
    pub min_alignment: i32,
}

impl UStruct {
    pub fn read(handle: HANDLE, address: usize) -> Result<Self, anyhow::Error> {
        // UObject のサイズを飛ばして UStruct 部分を読む
        let offset = std::mem::size_of::<UObject>();
        let data = read_process_memory(handle, address + offset, std::mem::size_of::<Self>())?;
        Ok(unsafe { std::ptr::read(data.as_ptr() as *const Self) })
    }
}

/// UFunction - 関数情報
#[repr(C)]
pub struct UFunction {
    pub function_flags: u32,
    pub num_params: u8,
    pub params_size: u16,
    pub return_value_offset: u16,
    pub rpc_id: u16,
    pub rpc_response_id: u16,
    pub first_property_to_init: usize, // UProperty*
    pub native_func: usize,            // 関数ポインタ
}

impl UFunction {
    /// UFunction の flag をチェック
    pub fn is_native(&self) -> bool {
        (self.function_flags & 0x00000400) != 0 // FUNC_Native
    }

    pub fn is_blueprint_callable(&self) -> bool {
        (self.function_flags & 0x00000001) != 0 // FUNC_BlueprintCallable
    }
}
