//! Utilities for building contractst

use std::path::PathBuf;

use cargo_metadata::MetadataCommand;

/// This points to the git checkout path of `axelar-amplifier`
#[must_use]
pub fn axelar_amplifier_dir() -> PathBuf {
    get_manifest_path_for_git_dep("axelar-wasm-std")
}

/// Get path to the axelar solana repo
#[must_use]
pub fn axelar_solana_dir() -> PathBuf {
    get_manifest_path_for_git_dep("axelar-solana-gateway")
}

/// This points to the git checkout path of `axelar-amplifier`
pub(crate) fn get_manifest_path_for_git_dep(desired_package_name: &str) -> PathBuf {
    let metadata = MetadataCommand::new()
        .exec()
        .expect("Failed to retrieve Cargo metadata");
    let mut pkg = None;
    for package in metadata.packages {
        if package.name.starts_with(desired_package_name) {
            pkg = package
                .manifest_path
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .parent()
                .map(|p| p.to_path_buf().into_std_path_buf());
            tracing::info!(?pkg, "pkg");
            break;
        }
    }
    pkg.unwrap()
}

/// ampd ~/.ampd directory
#[must_use]
pub fn ampd_home_dir() -> PathBuf {
    home_dir().join(".ampd")
}

/// path to the ampd binary
#[must_use]
pub fn ampd_bin() -> PathBuf {
    axelar_amplifier_dir()
        .join("target")
        .join("debug")
        .join("ampd")
}

/// Return the [`PathBuf`] that points to the `[repo]/solana` folder
#[must_use]
pub fn workspace_root_dir() -> PathBuf {
    let dir = std::env::var("CARGO_MANIFEST_DIR")
        .unwrap_or_else(|_| env!("CARGO_MANIFEST_DIR").to_owned());
    PathBuf::from(dir).parent().unwrap().to_owned()
}

/// Return the [`PathBuf`] that points to the `[repo]/script` folder
#[must_use]
pub fn scripts_crate_root_dir() -> PathBuf {
    self::workspace_root_dir().join("script")
}

/// Wrapper function for acquiring the home dir.
#[expect(deprecated)]
#[must_use]
pub fn home_dir() -> PathBuf {
    // Todo, we could use a crate as the std docs recommend, but windows
    // is not a supported target down the road of this CLI.
    std::env::home_dir().unwrap()
}

/// solana contract utilities
pub mod solana {
    use std::path::PathBuf;

    use xshell::{cmd, Shell};

    use crate::axelar_solana_dir;

    /// build the solana programs
    #[tracing::instrument(skip_all)]
    pub fn build_contracts() -> eyre::Result<()> {
        let sh = Shell::new()?;
        sh.change_dir(axelar_solana_dir());
        let contracts = [
            "programs/axelar-solana-gateway/Cargo.toml",
            "programs/axelar-solana-memo-program/Cargo.toml",
            "programs/axelar-solana-multicall/Cargo.toml",
            "programs/axelar-solana-its/Cargo.toml",
            "programs/axelar-solana-governance/Cargo.toml",
            "programs/axelar-solana-gas-service/Cargo.toml",
        ];
        for contract in contracts {
            cmd!(sh, "cargo build-sbf --manifest-path {contract}").run()?;
        }

        Ok(())
    }

    /// get path tho the axelar solana program artifacts
    #[must_use]
    pub fn contracts_artifact_dir() -> PathBuf {
        axelar_solana_dir().join("target").join("deploy")
    }
}

/// cosmwasm contact utilities
pub mod cosmwasm_contract {
    use std::io::Write as _;
    use std::path::{Path, PathBuf};

    use download::{download_wasm_opt, unpack_tar_gz};
    use eyre::Result;
    use toolchain::setup_toolchain;
    use xshell::{cmd, Shell};

    use crate::{axelar_amplifier_dir, workspace_root_dir};

    /// A cosmwasm contract in the amplifier repo
    #[derive(Debug)]
    pub struct WasmContracts {
        /// name
        pub wasm_artifact_name: &'static str,
        /// path in the `contracts` folder
        pub contract_project_folder: &'static str,
    }

    /// All cosmwasm contracts that we need to interact with
    pub const CONTRACTS: [WasmContracts; 3] = [
        WasmContracts {
            wasm_artifact_name: "voting_verifier",
            contract_project_folder: "voting-verifier",
        },
        WasmContracts {
            wasm_artifact_name: "gateway",
            contract_project_folder: "gateway",
        },
        WasmContracts {
            wasm_artifact_name: "multisig_prover",
            contract_project_folder: "multisig-prover",
        },
    ];

    /// build the cosmwasm contracts
    #[tracing::instrument(err)]
    pub async fn build() -> eyre::Result<()> {
        let sh = Shell::new()?;

        // install `wasm-opt` if it doesn't already exist
        if !wasm_opt_binary().exists() {
            tracing::info!("wasm opt does not exist - will download and unpack");
            let binaryen_archive = binaryen_tar_file();
            download_wasm_opt(binaryen_archive.as_path()).await?;
            unpack_tar_gz(binaryen_archive.as_path(), binaryen_unpacked().as_path())?;
        }

        // set up `axelar-amplifier`-specific toolchain
        setup_toolchain(&sh)?;
        build_contracts(&sh, &wasm_opt_binary(), &CONTRACTS).await?;

        Ok(())
    }

    /// build the cosmwasm contracts
    #[tracing::instrument(err)]
    async fn build_contracts(
        sh: &Shell,
        wasm_opt: &Path,
        contracts: &[WasmContracts],
    ) -> Result<()> {
        let amplifier_dir = axelar_amplifier_dir();
        let _env_guard = sh.push_env("RUSTFLAGS", "-C link-args=-s");

        for contract in contracts {
            let contract_dir = amplifier_dir
                .join("contracts")
                .join(contract.contract_project_folder);

            tracing::info!(contract_dir = ?contract_dir, "preparing to process cosmwasm contract");
            let in_contract_dir = sh.push_dir(contract_dir.clone());

            tracing::info!("building contract");
            cmd!(sh, "cargo wasm").run()?;

            let wasm_artifact = amplifier_dir
                .join("target")
                .join("wasm32-unknown-unknown")
                .join("release")
                .join(format!("{}.wasm", contract.wasm_artifact_name));
            let wasm_artifact_optimised = optimised_wasm_output(contract.wasm_artifact_name);

            drop(in_contract_dir);
            tracing::info!("applying optimiser");
            cmd!(
                sh,
                "{wasm_opt} -Oz --signext-lowering {wasm_artifact} -o {wasm_artifact_optimised}"
            )
            .run()?;
        }

        Ok(())
    }

    pub(crate) fn optimised_wasm_output(contract_name: &str) -> PathBuf {
        axelar_amplifier_dir()
            .join("target")
            .join("wasm32-unknown-unknown")
            .join("release")
            .join(format!("{contract_name}.optimised.wasm"))
    }

    /// Get the binary to the wasm artifact
    pub fn read_wasm_for_deployment(wasm_artifact_name: &str) -> eyre::Result<Vec<u8>> {
        let wasm = optimised_wasm_output(wasm_artifact_name);
        let wasm = std::fs::read(wasm)?;
        let mut output = Vec::with_capacity(wasm.len());
        flate2::write::GzEncoder::new(&mut output, flate2::Compression::best())
            .write_all(&wasm)
            .unwrap();
        tracing::info!(bytes = output.len(), "wasm module found");
        Ok(output)
    }

    pub(crate) mod toolchain {
        use eyre::Result;
        use xshell::{cmd, Shell};

        use crate::axelar_amplifier_dir;

        // install the cosmwasm target for the amplifier toolchain.
        pub(crate) fn setup_toolchain(sh: &Shell) -> Result<()> {
            let amplifier_dir = axelar_amplifier_dir();
            let _in_ampl_dir = sh.push_dir(amplifier_dir);
            cmd!(sh, "rustup target add wasm32-unknown-unknown").run()?;
            Ok(())
        }
    }

    pub(crate) fn wasm_opt_binary() -> PathBuf {
        binaryen_unpacked()
            .join("binaryen-version_117")
            .join("bin")
            .join("wasm-opt")
    }

    pub(crate) fn binaryen_tar_file() -> PathBuf {
        workspace_root_dir()
            .parent()
            .unwrap()
            .join("target")
            .join("binaryen.tar.gz")
    }

    pub(crate) fn binaryen_unpacked() -> PathBuf {
        workspace_root_dir()
            .parent()
            .unwrap()
            .join("target")
            .join("binaryen")
    }

    pub(crate) mod download {
        use std::fs::create_dir_all;
        use std::io::Write as _;
        use std::path::Path;

        use eyre::Result;
        use flate2::read::GzDecoder;
        use futures::StreamExt as _;
        use tar::Archive;

        #[tracing::instrument(err)]
        pub(crate) async fn download_file(file_path: &Path, url: &str) -> eyre::Result<()> {
            // Todo, this function could be tested.
            let client = reqwest::Client::new();
            let response = client.get(url).send().await?;
            if !response.status().is_success() {
                tracing::error!(url, status = ?response.status(), "Failed to download file");
                eyre::bail!("failed");
            }

            let mut file = std::fs::File::create(file_path)?;
            let mut stream = response.bytes_stream();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk?;
                file.write_all(&chunk)?;
            }

            tracing::info!(file_path = ?file_path, "Downloaded successfully to");
            Ok(())
        }

        #[tracing::instrument(err)]
        pub(crate) async fn download_wasm_opt(file_path: &Path) -> Result<()> {
            let url = determine_download_url();
            download_file(file_path, &url).await
        }

        pub(crate) fn determine_download_url() -> String {
            const DOWNLOAD_BASE: &str =
            "https://github.com/WebAssembly/binaryen/releases/download/version_117/binaryen-version_117-";
            const SUFFIX: &str = if cfg!(target_os = "linux") && cfg!(target_arch = "x86_64") {
                "x86_64-linux.tar.gz"
            } else if cfg!(target_os = "linux") && cfg!(target_arch = "aarch64") {
                "aarch64-linux.tar.gz"
            } else if cfg!(target_os = "macos") && cfg!(target_arch = "x86_64") {
                "x86_64-macos.tar.gz"
            } else if cfg!(target_os = "macos") && cfg!(target_arch = "aarch64") {
                "arm64-macos.tar.gz"
            } else if cfg!(target_os = "windows") && cfg!(target_arch = "x86_64") {
                "x86_64-windows.tar.gz"
            } else {
                panic!("Unsupported OS/Architecture combination");
            };
            format!("{DOWNLOAD_BASE}{SUFFIX}")
        }
        pub(crate) fn unpack_tar_gz(file_path: &Path, output_dir: &Path) -> Result<()> {
            let file = std::fs::File::open(file_path)?;
            let decoder = GzDecoder::new(file);
            let mut archive = Archive::new(decoder);
            create_dir_all(output_dir)?;
            archive.unpack(output_dir)?;

            tracing::info!(output_dir = ?output_dir, "Unpacked successfully");

            Ok(())
        }
    }
}
