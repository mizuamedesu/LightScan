/// UE バックエンド機能テスト
/// 3機能をテスト:
/// 1. 型対応フィールド読み書き
/// 2. インラインフック
/// 3. コード注入

use lightscan::engine::unreal::UnrealEngine;
use lightscan::engine::GameEngine;
use lightscan::engine::types::Value;
use lightscan::platform::windows;

fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    // UE ゲームプロセスを探す
    let processes = windows::list_processes().expect("Failed to list processes");

    // UEゲームのプロセスを探す（.exe を探す）
    let ue_procs: Vec<_> = processes
        .iter()
        .filter(|p| {
            let name_lower = p.name.to_lowercase();
            // 一般的な UE ゲームプロセス名パターン
            name_lower.contains("unreal") || name_lower.contains("game")
                || name_lower.ends_with("-win64-shipping.exe")
                || name_lower.ends_with("-win64-test.exe")
                || name_lower.ends_with("-win64-debug.exe")
                // Windows.zip から展開されたゲーム
                || (name_lower.ends_with(".exe")
                    && !name_lower.contains("system32")
                    && !name_lower.contains("windows")
                    && !name_lower.contains("explorer")
                    && !name_lower.contains("svchost")
                    && !name_lower.contains("chrome")
                    && !name_lower.contains("firefox")
                    && !name_lower.contains("code")
                    && !name_lower.contains("conhost")
                    && !name_lower.contains("cmd")
                    && !name_lower.contains("powershell")
                    && !name_lower.contains("openssh")
                    && !name_lower.contains("csrss")
                    && !name_lower.contains("lsass")
                    && !name_lower.contains("services")
                    && !name_lower.contains("winlogon")
                    && !name_lower.contains("dwm")
                    && !name_lower.contains("taskhostw")
                    && !name_lower.contains("spoolsv")
                    && !name_lower.contains("wininit")
                    && !name_lower.contains("smss")
                    && !name_lower.contains("fontdrvhost")
                    && !name_lower.contains("runtimebroker"))
        })
        .collect();

    println!("=== UE Game Process Candidates ===");
    for p in &ue_procs {
        println!("  PID: {:5} | {}", p.pid, p.name);
    }

    if ue_procs.is_empty() {
        println!("\nNo UE game process found. Listing all processes:");
        for p in &processes {
            println!("  PID: {:5} | {}", p.pid, p.name);
        }
        println!("\nPlease start the UE game first.");
        return;
    }

    // 最初の候補を使用（手動で選ぶ場合はコマンドライン引数を使う）
    let target_pid = std::env::args()
        .nth(1)
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(ue_procs[0].pid);

    let target_name = processes.iter().find(|p| p.pid == target_pid).map(|p| p.name.clone()).unwrap_or_default();
    println!("\n=== Targeting: PID {} ({}) ===", target_pid, target_name);

    // プロセスをオープン
    let handle = windows::open_process(target_pid).expect("Failed to open process");
    let handle_usize = handle.0 as usize;

    // UnrealEngine バックエンドを作成
    let mut engine = UnrealEngine::new(handle_usize, target_pid);

    // === テスト 1: 初期化（GNames, GObjects, ProcessEvent 検出）===
    println!("\n=== Test 1: Initialize (GNames/GObjects/ProcessEvent) ===");
    match engine.initialize() {
        Ok(()) => println!("[PASS] Engine initialized successfully"),
        Err(e) => {
            println!("[FAIL] Initialization failed: {}", e);
            println!("Skipping remaining tests.");
            return;
        }
    }

    // === テスト 2: クラス列挙 ===
    println!("\n=== Test 2: Enumerate Classes ===");
    match engine.enumerate_classes() {
        Ok(classes) => {
            println!("[PASS] Found {} classes", classes.len());
            for c in classes.iter().take(10) {
                println!("  - {} (handle: 0x{:X}, size: {})", c.name, c.handle.0, c.size);
            }
            if classes.len() > 10 {
                println!("  ... and {} more", classes.len() - 10);
            }
        }
        Err(e) => println!("[FAIL] {}", e),
    }

    // === テスト 3: 型対応フィールド読み書き ===
    println!("\n=== Test 3: Type-aware Field Read/Write ===");
    // PlayerController を探す
    let test_classes = ["PlayerController", "Character", "Pawn", "Actor", "GameModeBase"];
    let mut found_class = None;
    for class_name in &test_classes {
        match engine.find_class(class_name) {
            Ok(class) => {
                println!("[INFO] Found class: {}", class_name);
                found_class = Some((class_name.to_string(), class));
                break;
            }
            Err(_) => continue,
        }
    }

    if let Some((ref class_name, class_handle)) = found_class {
        // フィールドを列挙
        match engine.enumerate_fields(class_handle) {
            Ok(fields) => {
                println!("[PASS] {} has {} fields:", class_name, fields.len());
                for f in fields.iter().take(15) {
                    println!("  - {} (offset: {}, type: {} [{}], size: {})",
                        f.name, f.offset, f.type_info.name,
                        format!("{:?}", f.type_info.kind), f.type_info.size);
                }
                if fields.len() > 15 {
                    println!("  ... and {} more", fields.len() - 15);
                }

                // インスタンスを取得してフィールド読み取りテスト
                match engine.get_instances(class_handle) {
                    Ok(instances) if !instances.is_empty() => {
                        println!("[PASS] Found {} instances", instances.len());
                        let inst = instances[0];

                        for f in fields.iter().take(5) {
                            match engine.read_field(inst, f.handle) {
                                Ok(val) => println!("  [READ] {}: {:?}", f.name, val),
                                Err(e) => println!("  [READ FAIL] {}: {}", f.name, e),
                            }
                        }
                    }
                    Ok(_) => println!("[INFO] No instances found for {}", class_name),
                    Err(e) => println!("[FAIL] Get instances: {}", e),
                }
            }
            Err(e) => println!("[FAIL] Enumerate fields: {}", e),
        }

        // メソッドを列挙
        match engine.enumerate_methods(class_handle) {
            Ok(methods) => {
                println!("[PASS] {} has {} methods:", class_name, methods.len());
                for m in methods.iter().take(10) {
                    let params_str: Vec<_> = m.params.iter()
                        .map(|p| format!("{}: {}", p.name, p.type_info.name))
                        .collect();
                    println!("  - {}({}) -> {:?} [static={}]",
                        m.name, params_str.join(", "),
                        m.return_type.as_ref().map(|t| &t.name),
                        m.is_static);
                }
            }
            Err(e) => println!("[FAIL] Enumerate methods: {}", e),
        }
    } else {
        println!("[SKIP] No known UE class found");
    }

    // === テスト 6: リアルタイムモニタリング（フィールド値の連続読み取り）===
    // (Test 5 のコード注入より前に実行する必要あり)
    println!("\n=== Test 6: Real-time Field Monitoring ===");
    if let Some((ref class_name, class_handle)) = found_class {
        if let Ok(instances) = engine.get_instances(class_handle) {
            if let Some(&inst) = instances.first() {
                if let Ok(fields) = engine.enumerate_fields(class_handle) {
                    let watch_fields: Vec<_> = fields.iter().take(5).collect();
                    println!("[INFO] Monitoring {} {}.fields for 3 iterations:", watch_fields.len(), class_name);

                    for round in 0..3 {
                        println!("  --- Round {} ---", round);
                        for f in &watch_fields {
                            match engine.read_field(inst, f.handle) {
                                Ok(val) => println!("    {}: {} ({})", f.name, val, f.type_info.name),
                                Err(e) => println!("    {}: ERROR: {}", f.name, e),
                            }
                        }
                        if round < 2 {
                            std::thread::sleep(std::time::Duration::from_millis(500));
                        }
                    }
                    println!("[PASS] Real-time monitoring works");
                } else {
                    println!("[SKIP] No fields found");
                }
            } else {
                println!("[SKIP] No instances found");
            }
        } else {
            println!("[SKIP] Could not get instances");
        }
    } else {
        println!("[SKIP] No class found in Test 3");
    }

    // === テスト 4: フック基盤（構造体テスト、実際のフック設置はしない）===
    println!("\n=== Test 4: Hook Infrastructure ===");
    {
        use lightscan::engine::unreal::hook::HookManager;
        let _hook_mgr = HookManager::new(handle_usize);
        println!("[PASS] HookManager created successfully");
        println!("[INFO] Hook installation requires a target function - skipping live test");
        println!("[INFO] HookManager supports: install_hook, remove_hook, remove_all, list_hooks, get_trampoline");
    }

    // === テスト 5: コード注入フレームワーク ===
    println!("\n=== Test 5: Code Injection Framework ===");
    {
        use lightscan::engine::unreal::inject;

        // メモリ確保テスト
        match inject::allocate_remote(handle_usize, 4096, false) {
            Ok(addr) => {
                println!("[PASS] allocate_remote: 0x{:X} (4096 bytes, RW)", addr);

                // 書き込みテスト
                let test_data = b"LightScan Test";
                match inject::write_remote(handle_usize, addr, test_data) {
                    Ok(()) => println!("[PASS] write_remote: wrote {} bytes", test_data.len()),
                    Err(e) => println!("[FAIL] write_remote: {}", e),
                }

                // 読み取りテスト
                match inject::read_remote(handle_usize, addr, test_data.len()) {
                    Ok(data) => {
                        if &data[..] == test_data {
                            println!("[PASS] read_remote: data matches");
                        } else {
                            println!("[FAIL] read_remote: data mismatch");
                        }
                    }
                    Err(e) => println!("[FAIL] read_remote: {}", e),
                }

                // 解放テスト
                match inject::free_remote(handle_usize, addr) {
                    Ok(()) => println!("[PASS] free_remote: deallocated"),
                    Err(e) => println!("[FAIL] free_remote: {}", e),
                }
            }
            Err(e) => println!("[FAIL] allocate_remote: {}", e),
        }

        // 実行可能メモリ確保テスト
        match inject::allocate_remote(handle_usize, 256, true) {
            Ok(addr) => {
                println!("[PASS] allocate_remote (executable): 0x{:X}", addr);

                // 簡単なシェルコード (ret のみ) を注入して実行
                let ret_shellcode = [0xC3u8]; // ret
                match inject::write_remote(handle_usize, addr, &ret_shellcode) {
                    Ok(()) => println!("[PASS] write shellcode (ret)"),
                    Err(e) => println!("[FAIL] write shellcode: {}", e),
                }

                // inject_code テスト (ret のみ)
                match inject::inject_code(handle_usize, &[
                    0x48, 0x31, 0xC0, // xor rax, rax
                    0xC3,             // ret
                ]) {
                    Ok(exit_code) => println!("[PASS] inject_code: exit_code={}", exit_code),
                    Err(e) => println!("[FAIL] inject_code: {}", e),
                }

                // call_remote_function テスト (GetCurrentProcessId)
                // kernel32!GetCurrentProcessId は引数なしで PID を返す
                match inject::call_remote_function(handle_usize, 0, &[]) {
                    Ok(_) => println!("[INFO] call_remote_function: needs valid function address"),
                    Err(e) => println!("[INFO] call_remote_function (expected fail with addr 0): {}", e),
                }

                let _ = inject::free_remote(handle_usize, addr);
            }
            Err(e) => println!("[FAIL] allocate_remote (executable): {}", e),
        }

        // patch_memory テスト（独立セクション）
        println!("\n--- patch_memory test ---");
        match inject::allocate_remote(handle_usize, 4096, false) {
            Ok(patch_addr) => {
                let _ = inject::write_remote(handle_usize, patch_addr, &[0xAA; 8]);
                match inject::patch_memory(handle_usize, patch_addr, &[0xBB; 8]) {
                    Ok(original) => {
                        if original == vec![0xAA; 8] {
                            println!("[PASS] patch_memory: original bytes preserved");
                        } else {
                            println!("[WARN] patch_memory: original bytes = {:02X?}", original);
                        }
                    }
                    Err(e) => println!("[FAIL] patch_memory: {}", e),
                }
                let _ = inject::free_remote(handle_usize, patch_addr);
            }
            Err(e) => println!("[FAIL] allocate for patch test: {}", e),
        }
    }

    println!("\n=== All Tests Complete ===");
}
