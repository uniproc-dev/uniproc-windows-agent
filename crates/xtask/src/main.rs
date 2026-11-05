//! Workspace tasks. `cargo run -p xtask -- bindings` writes each crate's
//! Win32 bindings from its filter, one name per line, with windows-bindgen.

use std::path::{Path, PathBuf};

/// Each crate's filter and the bindings written from it, from the workspace root.
const BINDINGS: [(&str, &str); 2] = [
    ("src/bindings.txt", "src/bindings.rs"),
    (
        "crates/core/src/bindings.txt",
        "crates/core/src/bindings.rs",
    ),
];

fn main() -> anyhow::Result<()> {
    match std::env::args().nth(1).as_deref() {
        Some("lhm") => {
            let release = std::env::args().skip(2).any(|arg| arg == "--release");
            let status = std::process::Command::new("pwsh.exe")
                .args(["-NoLogo", "-NoProfile", "-File"])
                .arg(root().join("native/lhm/build.ps1"))
                .status()?;
            anyhow::ensure!(status.success(), "LHM NativeAOT build failed");
            let mut cargo = std::process::Command::new(
                std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()),
            );
            cargo
                .current_dir(root())
                .args(["build", "-p", "uniproc-windows-service", "--locked"]);
            if release {
                cargo.arg("--release");
            }
            anyhow::ensure!(cargo.status()?.success(), "Windows service build failed");
            let target = std::env::var_os("CARGO_TARGET_DIR")
                .map(|path| root().join(path))
                .unwrap_or_else(|| root().join("target"));
            let destination = target.join(if release { "release" } else { "debug" });
            for entry in std::fs::read_dir(root().join("target/lhm-native-aot"))? {
                let entry = entry?;
                if entry.path().extension().is_some_and(|ext| ext == "dll") {
                    std::fs::copy(entry.path(), destination.join(entry.file_name()))?;
                }
            }
            let licenses = destination.join("lhm-licenses");
            std::fs::create_dir_all(&licenses)?;
            for name in ["LICENSE", "THIRD-PARTY-NOTICES.txt"] {
                std::fs::copy(
                    root().join("target/lhm-source").join(name),
                    licenses.join(name),
                )?;
            }
            Ok(())
        }
        Some("bindings") => {
            for (filter, output) in present(&root()) {
                generate(&filter, &output);
                println!("{}", output.display());
            }
            Ok(())
        }
        _ => anyhow::bail!("usage: cargo run -p xtask -- bindings | lhm [--release]"),
    }
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("xtask sits two levels below the workspace root")
        .to_path_buf()
}

/// The pairs whose filter exists.
fn present(root: &Path) -> Vec<(PathBuf, PathBuf)> {
    BINDINGS
        .iter()
        .map(|(filter, output)| (root.join(filter), root.join(output)))
        .filter(|(filter, _)| filter.is_file())
        .collect()
}

fn generate(filter: &Path, output: &Path) {
    windows_bindgen::builder()
        .input_default()
        .flat()
        .filter_file(filter)
        .output(output)
        .write();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn squeezed(text: &str) -> String {
        text.split_whitespace().collect()
    }

    #[test]
    fn every_crate_s_bindings_are_what_its_filter_writes() {
        let pairs = present(&root());
        assert!(!pairs.is_empty(), "no crate has a bindings filter");
        for (index, (filter, output)) in pairs.iter().enumerate() {
            let fresh = std::env::temp_dir().join(format!(
                "uniproc-bindings-{}-{index}.rs",
                std::process::id()
            ));
            generate(filter, &fresh);
            let written = std::fs::read_to_string(&fresh).unwrap_or_default();
            let _ = std::fs::remove_file(&fresh);
            let held = std::fs::read_to_string(output).unwrap_or_default();
            assert!(
                !written.is_empty() && squeezed(&held) == squeezed(&written),
                "{} is not what {} writes: run `cargo run -p xtask -- bindings`",
                output.display(),
                filter.display()
            );
        }
    }
}
