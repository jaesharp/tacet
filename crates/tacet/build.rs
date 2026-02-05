fn main() {
    // Configure library paths for FFI tests (mbedTLS, wolfSSL)

    // === mbedTLS Configuration ===
    // First check environment variable
    if let Ok(mbedtls_dir) = std::env::var("MBEDTLS_DIR") {
        let lib_path = format!("{}/lib", mbedtls_dir);
        println!("cargo:rustc-link-search=native={}", lib_path);
        println!("cargo:warning=Using MBEDTLS_DIR: {}", mbedtls_dir);
    } else {
        // Try to find mbedTLS in Nix store
        let nix_paths = [
            "/nix/store/rjsl63znrgky1m4vayj5wilxc12kmdap-mbedtls-3.6.5",
            "/nix/store/fbsg0k5w2ay1wb8dis00shbmnwfg3c54-mbedtls-3.6.5",
            "/nix/store/yvdl3n3fn45zh1s5bpp5s0wsi6ni104z-mbedtls-3.6.5",
            "/nix/store/w26jsicdj3l618k3lc2rgiy7a8jqryv4-mbedtls-3.6.5",
            "/nix/store/0j8ydh92l9hdjibg5d24nasxzha9ibvr-mbedtls-3.6.5",
        ];

        let mut found_mbedtls = false;
        for path in &nix_paths {
            if std::path::Path::new(path).exists() {
                let lib_path = format!("{}/lib", path);
                println!("cargo:rustc-link-search=native={}", lib_path);
                println!("cargo:warning=Found mbedTLS at: {}", path);
                found_mbedtls = true;
                break;
            }
        }

        if !found_mbedtls {
            println!("cargo:warning=mbedTLS not found in Nix store. Set MBEDTLS_DIR if needed.");
        }
    }

    // === wolfSSL Configuration ===
    // Check environment variable first
    if let Ok(wolfssl_dir) = std::env::var("WOLFSSL_DIR") {
        let lib_path = format!("{}/lib", wolfssl_dir);
        println!("cargo:rustc-link-search=native={}", lib_path);
        println!("cargo:rustc-link-lib=wolfssl");
        println!("cargo:warning=Using WOLFSSL_DIR: {}", wolfssl_dir);
    } else {
        // Try Homebrew on macOS
        #[cfg(target_os = "macos")]
        {
            let homebrew_paths = [
                "/opt/homebrew/lib", // Apple Silicon
                "/usr/local/lib",    // Intel
            ];

            let mut found_wolfssl = false;
            for path in &homebrew_paths {
                let wolfssl_lib = format!("{}/libwolfssl.dylib", path);
                if std::path::Path::new(&wolfssl_lib).exists() {
                    println!("cargo:rustc-link-search=native={}", path);
                    println!("cargo:rustc-link-lib=wolfssl");
                    println!("cargo:warning=Found wolfSSL at: {}", path);
                    found_wolfssl = true;
                    break;
                }
            }

            if !found_wolfssl {
                println!("cargo:warning=wolfSSL not found. Install with: brew install wolfssl");
            }
        }

        // Try standard library paths on Linux
        #[cfg(target_os = "linux")]
        {
            let linux_paths = ["/usr/lib", "/usr/local/lib", "/usr/lib/x86_64-linux-gnu"];

            let mut found_wolfssl = false;
            for path in &linux_paths {
                let wolfssl_lib = format!("{}/libwolfssl.so", path);
                if std::path::Path::new(&wolfssl_lib).exists() {
                    println!("cargo:rustc-link-search=native={}", path);
                    println!("cargo:rustc-link-lib=wolfssl");
                    println!("cargo:warning=Found wolfSSL at: {}", path);
                    found_wolfssl = true;
                    break;
                }
            }

            if !found_wolfssl {
                println!("cargo:warning=wolfSSL not found. Install development package.");
            }
        }
    }

    // === Botan Configuration ===
    // Check environment variable first
    if let Ok(botan_dir) = std::env::var("BOTAN_DIR") {
        let lib_path = format!("{}/lib", botan_dir);
        println!("cargo:rustc-link-search=native={}", lib_path);
        println!("cargo:rustc-link-lib=botan-3");
        println!("cargo:warning=Using BOTAN_DIR: {}", botan_dir);
    } else {
        // Try Homebrew on macOS
        #[cfg(target_os = "macos")]
        {
            let homebrew_paths = [
                "/opt/homebrew/lib", // Apple Silicon
                "/usr/local/lib",    // Intel
            ];

            let mut found_botan = false;
            for path in &homebrew_paths {
                let botan_lib = format!("{}/libbotan-3.dylib", path);
                if std::path::Path::new(&botan_lib).exists() {
                    println!("cargo:rustc-link-search=native={}", path);
                    println!("cargo:rustc-link-lib=botan-3");
                    println!("cargo:warning=Found Botan at: {}", path);
                    found_botan = true;
                    break;
                }
            }

            if !found_botan {
                println!("cargo:warning=Botan not found. Install with: brew install botan");
            }
        }

        // Try standard library paths on Linux
        #[cfg(target_os = "linux")]
        {
            let linux_paths = ["/usr/lib", "/usr/local/lib", "/usr/lib/x86_64-linux-gnu"];

            let mut found_botan = false;
            for path in &linux_paths {
                let botan_lib = format!("{}/libbotan-3.so", path);
                if std::path::Path::new(&botan_lib).exists() {
                    println!("cargo:rustc-link-search=native={}", path);
                    println!("cargo:rustc-link-lib=botan-3");
                    println!("cargo:warning=Found Botan at: {}", path);
                    found_botan = true;
                    break;
                }
            }

            if !found_botan {
                println!("cargo:warning=Botan not found. Install development package.");
            }
        }
    }
}
