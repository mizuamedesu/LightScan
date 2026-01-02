/// Signature patterns for UE structure detection

pub struct UESignatures;

impl UESignatures {
    /// GNames パターン (UE4.23+, UE5)
    /// mov rax, qword ptr [rip + offset]
    pub const GNAMES: &'static str = "48 8B 05 ?? ?? ?? ?? 48 85 C0 75 ?? 48 8D";

    /// GNames 代替パターン
    pub const GNAMES_ALT: &'static str = "48 8B 1D ?? ?? ?? ?? 48 85 DB 75 ?? B9";

    /// GNames パターン3 (UE5+)
    pub const GNAMES_ALT2: &'static str = "48 89 5C 24 ?? 48 89 74 24 ?? 55 57 41 56 48 8D 6C 24 ?? 48 81 EC ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ??";

    /// GNames パターン4 (短縮版)
    pub const GNAMES_ALT3: &'static str = "48 8B 05 ?? ?? ?? ?? 48 85 C0";

    /// GNames パターン5 (lea命令版 - UE5.1+)
    pub const GNAMES_ALT4: &'static str = "48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? C6 05";

    /// GNames パターン6 (FName::ToString内部)
    pub const GNAMES_ALT5: &'static str = "48 8B 1D ?? ?? ?? ?? 48 85 DB 74";

    /// GNames パターン7 (UE5 - FName::AppendString)
    pub const GNAMES_UE5_1: &'static str = "48 8B 05 ?? ?? ?? ?? 4C 8B C3 48 8B D7";

    /// GNames パターン8 (UE5 - 別のアプローチ)
    pub const GNAMES_UE5_2: &'static str = "48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B D8 48 85 C0 74";

    /// GUObjectArray (GObjects) パターン
    /// mov rcx, qword ptr [rip + offset]
    pub const GOBJECTS: &'static str = "48 8B 0D ?? ?? ?? ?? 48 8D 14 C1";

    /// GObjects 代替パターン
    pub const GOBJECTS_ALT: &'static str = "48 8B 05 ?? ?? ?? ?? 48 8B 0C C8 48 8D 04 D1";

    /// GObjects UE5パターン
    pub const GOBJECTS_UE5: &'static str = "48 8B 05 ?? ?? ?? ?? 48 63 0C 88";

    /// GObjects UE5.5パターン - FUObjectArray::IndexToObject関連
    /// mov rax/rcx, [rip+offset] followed by movsxd (sign-extend index)
    pub const GOBJECTS_UE5_INDEXTO: &'static str = "48 8B 0D ?? ?? ?? ?? 48 63 C2 48 8D";

    /// GObjects UE5.5パターン2 - ObjObjects.Num()
    /// movsxd rax, dword ptr [rip + offset] - NumElementsを読む
    pub const GOBJECTS_UE5_NUM: &'static str = "48 63 05 ?? ?? ?? ?? 39";

    /// GObjects UE5.5パターン3 - GetObjectItemArrayUnsafe
    /// mov rax, qword ptr [rip + offset] followed by specific operations
    pub const GOBJECTS_UE5_GETARRAY: &'static str = "48 8B 05 ?? ?? ?? ?? 4C 8D ?? 48";

    /// ProcessEvent パターン (UE4.20+)
    /// 関数プロローグ: push rbp; push rsi; push rdi; push r12-r15; sub rsp, ???
    pub const PROCESS_EVENT: &'static str =
        "40 55 56 57 41 54 41 55 41 56 41 57 48 81 EC ?? ?? ?? ??";

    /// ProcessEvent 代替パターン
    pub const PROCESS_EVENT_ALT: &'static str =
        "48 89 5C 24 ?? 48 89 74 24 ?? 55 57 41 56 48 8D 6C 24";

    /// FName::ToString パターン（GNames 検証用）
    pub const FNAME_TOSTRING: &'static str =
        "48 89 5C 24 ?? 57 48 83 EC 30 83 79 04 00 48 8B DA";
}

/// UE バージョン別のシグネチャセット
pub struct VersionSignatures {
    pub gnames_patterns: Vec<&'static str>,
    pub gobjects_patterns: Vec<&'static str>,
    pub process_event_patterns: Vec<&'static str>,
}

impl VersionSignatures {
    /// すべてのパターンを試行
    pub fn all() -> Self {
        Self {
            gnames_patterns: vec![
                // UE5専用パターンを最初に
                UESignatures::GNAMES_UE5_1,
                UESignatures::GNAMES_UE5_2,
                // UE4/UE5共通パターン
                UESignatures::GNAMES_ALT,
                UESignatures::GNAMES_ALT5,
                UESignatures::GNAMES_ALT4,
                UESignatures::GNAMES,
                UESignatures::GNAMES_ALT2,
                UESignatures::GNAMES_ALT3,
            ],
            gobjects_patterns: vec![
                // 元のパターン（より特定的）を先に
                UESignatures::GOBJECTS,       // 48 8B 0D + 48 8D 14 C1
                UESignatures::GOBJECTS_ALT,   // 48 8B 05 + 48 8B 0C C8 48 8D 04 D1
                // UE5専用パターン
                UESignatures::GOBJECTS_UE5,   // 48 8B 05 + 48 63 0C 88
                UESignatures::GOBJECTS_UE5_INDEXTO,
                UESignatures::GOBJECTS_UE5_NUM,
                UESignatures::GOBJECTS_UE5_GETARRAY,
            ],
            process_event_patterns: vec![
                UESignatures::PROCESS_EVENT,
                UESignatures::PROCESS_EVENT_ALT,
            ],
        }
    }
}
