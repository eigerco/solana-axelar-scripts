mod message_limits;

use std::collections::BTreeMap;
use std::fmt::Display;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use axelar_message_primitives::U256;
use axelar_rkyv_encoding::types::{PublicKey, VerifierSet, U128};
use eyre::OptionExt;
use gmp_gateway::axelar_auth_weighted::RotationDelaySecs;
use gmp_gateway::instructions::{InitializeConfig, VerifierSetWrapper};
use gmp_gateway::state::GatewayConfig;
pub(crate) use message_limits::generate_message_limits_report;
use solana_client::rpc_client::RpcClient;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Signer;
use tracing::info;
use url::Url;
use xshell::{cmd, Shell};

use super::cosmwasm::cosmos_client::signer::SigningClient;
use super::deployments::{SolanaDeploymentRoot, SolanaMemoProgram};
use super::testnet::solana_interactions::send_solana_tx;
use crate::cli::cmd::deployments::SolanaGatewayDeployment;
use crate::cli::cmd::testnet::multisig_prover_api;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum)]
pub(crate) enum SolanaContract {
    GmpGateway,
    AxelarSolanaMemo,
}

impl SolanaContract {
    /// Provides the predictable output artifact that will be
    /// generated when each contract it's built. This is a helper
    /// method that is normally join'`ed()` with other base directories.
    pub(crate) fn file(self) -> PathBuf {
        match self {
            SolanaContract::GmpGateway => PathBuf::from("gmp_gateway.so"),
            SolanaContract::AxelarSolanaMemo => PathBuf::from("axelar_solana_memo_program.so"),
        }
    }
}

impl Display for SolanaContract {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SolanaContract::GmpGateway => write!(f, "gmp-gateway"),
            SolanaContract::AxelarSolanaMemo => write!(f, "axelar-solana-memo-program"),
        }
    }
}

#[tracing::instrument(skip_all)]
pub(crate) fn deploy(
    contract: SolanaContract,
    program_id: &Path,
    keypair_path: Option<&PathBuf>,
    url: Option<&Url>,
    ws_url: Option<&Url>,
) -> eyre::Result<()> {
    crate::cli::cmd::path::ensure_optional_path_exists(keypair_path, "keypair")?;

    info!("Starting compiling {}", contract);
    build_contracts(None)?;
    info!("Compiled {}", contract);

    info!("Starting deploying {}", contract);
    let pub_key = deploy_contract(contract, program_id, keypair_path, url, ws_url)?;
    info!("Deployed {contract} at {pub_key:?}");
    Ok(())
}

#[tracing::instrument(skip_all)]
pub(crate) async fn init_gmp_gateway(
    cosmwasm_signer: SigningClient,
    previous_signers_retention: u128,
    minimum_rotation_delay: RotationDelaySecs,
    solana_deployment_root: &mut SolanaDeploymentRoot,
) -> eyre::Result<()> {
    let payer_kp = defaults::payer_kp()?;

    let (gateway_config_pda, _bump) = GatewayConfig::pda();

    // Query the cosmwasm multisig prover to get the latest verifier set
    let destination_multisig_prover = cosmrs::AccountId::from_str(
        &solana_deployment_root
            .multisig_prover
            .as_ref()
            .ok_or_eyre("multisig prover not deployed")?
            .address,
    )?;
    let multisig_prover_response = cosmwasm_signer
        .query::<multisig_prover_api::VerifierSetResponse>(
            destination_multisig_prover.clone(),
            serde_json::to_vec(&multisig_prover_api::QueryMsg::CurrentVerifierSet {})?,
        )
        .await?;

    let mut signers = BTreeMap::new();
    for signer in multisig_prover_response.verifier_set.signers.values() {
        let pubkey = PublicKey::new_ecdsa(signer.pub_key.as_ref().try_into()?);
        let weight = U128::from(signer.weight.u128());
        signers.insert(pubkey, weight);
    }
    let verifier_set = VerifierSet::new(
        multisig_prover_response.verifier_set.created_at,
        signers,
        U128::from(multisig_prover_response.verifier_set.threshold.u128()),
        solana_deployment_root.solana_configuration.domain_separator,
    );
    tracing::info!(
        returned = ?multisig_prover_response.verifier_set,
        "returned verifier set"
    );
    tracing::info!(
        reconstructed = ?verifier_set,
        "reconstructed verifier set"
    );
    let verifier_set = VerifierSetWrapper::new_from_verifier_set(verifier_set).unwrap();
    let init_config = InitializeConfig {
        domain_separator: solana_deployment_root.solana_configuration.domain_separator,
        initial_signer_sets: vec![verifier_set],
        minimum_rotation_delay,
        operator: payer_kp.pubkey(),
        previous_signers_retention: U256::from(previous_signers_retention),
    };
    tracing::info!(?init_config, "initting auth weighted");

    let rpc_client = RpcClient::new(defaults::rpc_url()?.to_string());
    send_solana_tx(
        &rpc_client,
        &[gmp_gateway::instructions::initialize_config(
            payer_kp.pubkey(),
            init_config.clone(),
            gateway_config_pda,
        )?],
        &payer_kp,
    )?;

    // save the information in our deployment tracker
    solana_deployment_root.solana_gateway = Some(SolanaGatewayDeployment {
        domain_separator: init_config.domain_separator,
        initial_signer_sets: vec![multisig_prover_response.verifier_set],
        minimum_rotation_delay: init_config.minimum_rotation_delay,
        operator: init_config.operator,
        previous_signers_retention: init_config.previous_signers_retention.to_le_bytes(),
        program_id: gmp_gateway::id(),
        config_pda: gateway_config_pda,
    });

    Ok(())
}

#[tracing::instrument(skip_all)]
pub(crate) fn init_memo_program(
    solana_deployment_root: &mut SolanaDeploymentRoot,
) -> eyre::Result<()> {
    let payer_kp = defaults::payer_kp()?;
    let rpc_client = RpcClient::new(defaults::rpc_url()?.to_string());

    let gateway_root_pda = gmp_gateway::get_gateway_root_config_pda().0;
    let counter = axelar_solana_memo_program::get_counter_pda(&gateway_root_pda);
    let account = rpc_client.get_account(&counter.0);
    if account.is_ok() {
        solana_deployment_root.solana_memo_program = Some(SolanaMemoProgram {
            solana_gateway_root_config_pda: gateway_root_pda,
            program_id: axelar_solana_memo_program::id(),
            counter_pda: counter.0,
        });
        tracing::warn!("counter PDA alradey initialized");
        return Ok(());
    }
    let ix = axelar_solana_memo_program::instruction::initialize(
        &payer_kp.pubkey(),
        &gateway_root_pda,
        &counter,
    )?;
    send_solana_tx(&rpc_client, &[ix], &payer_kp)?;
    solana_deployment_root.solana_memo_program = Some(SolanaMemoProgram {
        solana_gateway_root_config_pda: gateway_root_pda,
        program_id: axelar_solana_memo_program::id(),
        counter_pda: counter.0,
    });

    Ok(())
}

#[tracing::instrument(skip_all)]
pub(crate) fn build_contracts(contracts: Option<&[PathBuf]>) -> eyre::Result<()> {
    let sh = Shell::new()?;
    if let Some(contracts) = contracts {
        for contract in contracts {
            cmd!(sh, "cargo build-sbf --manifest-path {contract}").run()?;
        }
    } else {
        cmd!(sh, "cargo build-sbf").run()?;
    }

    Ok(())
}

#[tracing::instrument(skip_all)]
fn deploy_contract(
    contract: SolanaContract,
    program_id: &Path,
    keypair_path: Option<&PathBuf>,
    url: Option<&Url>,
    ws_url: Option<&Url>,
) -> eyre::Result<Pubkey> {
    let contract_compiled_binary = path::contracts_artifact_dir().join(contract.file());
    let sh = Shell::new()?;
    let deploy_cmd_args = calculate_deploy_cmd_args(
        program_id,
        keypair_path,
        url,
        ws_url,
        &contract_compiled_binary,
    );

    let program_id_output = cmd!(sh, "solana program deploy {deploy_cmd_args...}").read()?;

    parse_program_id(&program_id_output)
}

fn parse_program_id(output: &str) -> eyre::Result<Pubkey> {
    let parts: Vec<&str> = output.split(':').collect();
    let id_part: &&str = parts.get(1).ok_or(eyre::eyre!(
        "Cannot parse programId from parts. Expected second index not found."
    ))?;
    Ok(Pubkey::from_str(id_part.trim())?)
}

#[tracing::instrument(skip_all, ret)]
fn calculate_deploy_cmd_args(
    program_id: &Path,
    keypair_path: Option<&PathBuf>,
    url: Option<&Url>,
    ws_url: Option<&Url>,
    contract_compiled_binary_path: &Path,
) -> Vec<String> {
    let mut cmd = vec![
        "--program-id".to_string(),
        program_id.to_string_lossy().to_string(),
    ];

    if let Some(kp) = keypair_path {
        cmd.push("-k".to_string());
        cmd.push(kp.to_string_lossy().to_string());
    }

    if let Some(url) = url {
        cmd.push("-u".to_string());
        cmd.push(url.to_string());
    }

    if let Some(ws_url) = ws_url {
        cmd.push("--ws".to_string());
        cmd.push(ws_url.to_string());
    }
    let compiled_bin_path = contract_compiled_binary_path.to_string_lossy();
    cmd.push(compiled_bin_path.to_string());
    cmd
}

pub(crate) mod path {
    use std::path::PathBuf;

    use crate::cli::cmd::path::workspace_root_dir;

    pub(crate) fn contracts_artifact_dir() -> PathBuf {
        workspace_root_dir().join("target").join("deploy")
    }

    pub(crate) fn gateway_manifest() -> PathBuf {
        workspace_root_dir()
            .join("programs")
            .join("gateway")
            .join("Cargo.toml")
    }

    pub(crate) fn memo_manifest() -> PathBuf {
        workspace_root_dir()
            .join("programs")
            .join("axelar-solana-memo-program")
            .join("Cargo.toml")
    }
}

pub(crate) mod defaults {

    use std::path::PathBuf;
    use std::str::FromStr;

    use eyre::OptionExt;
    use solana_cli_config::Config;
    use solana_sdk::signature::Keypair;
    use solana_sdk::signer::EncodableKey;
    use url::Url;
    use xshell::{cmd, Shell};

    pub(crate) fn payer_kp() -> eyre::Result<Keypair> {
        let payer_kp_path = PathBuf::from(Config::default().keypair_path);
        crate::cli::cmd::path::ensure_path_exists(&payer_kp_path, "payer keypair")?;
        Keypair::read_from_file(&payer_kp_path)
            .map_err(|_| eyre::Error::msg("Could not read payer key pair"))
    }

    pub(crate) fn rpc_url() -> eyre::Result<Url> {
        let sh = Shell::new()?;
        let rpc_url = cmd!(sh, "solana config get json_rpc_url")
            .read()?
            .as_str()
            .split_whitespace()
            .last()
            .ok_or_eyre("rpc url could not be extracted from solana config")?
            .to_string();

        Ok(Url::from_str(&rpc_url)?)
    }
}

#[cfg(test)]
mod tests {

    use eyre::Ok;

    use super::*;

    #[test]
    fn parse_program_id_from_deploy_output() {
        let expected_output =
            Pubkey::from_str("4gG8FWzYihgixVfEdgGkMSdRTN9q8cGyDbkVwR72ir1g").unwrap();
        let cases = vec![
            (
                "ProgramId: 4gG8FWzYihgixVfEdgGkMSdRTN9q8cGyDbkVwR72ir1g",
                expected_output,
            ),
            (
                "ProgramId:4gG8FWzYihgixVfEdgGkMSdRTN9q8cGyDbkVwR72ir1g",
                expected_output,
            ),
            (
                "ProgramId: 4gG8FWzYihgixVfEdgGkMSdRTN9q8cGyDbkVwR72ir1g    ",
                expected_output,
            ),
            (
                "PROGRAMID: 4gG8FWzYihgixVfEdgGkMSdRTN9q8cGyDbkVwR72ir1g",
                expected_output,
            ),
        ];

        cases
            .into_iter()
            .try_for_each(|(input, expected)| {
                let pubkey = parse_program_id(input)?;
                assert_eq!(
                    pubkey, expected,
                    "We expected input {input} to be parsed to {expected}"
                );
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn calc_deploy_cmd_when_no_params_it_takes_default_solana_cli_config() {
        let kp = None;
        let url = None;
        let ws_url = None;
        let program_id = PathBuf::from_str("~/path/program-id-keypair.json").unwrap();

        let result = calculate_deploy_cmd_args(
            &program_id,
            kp,
            url,
            ws_url,
            &PathBuf::from_str("/contracts/contract.so").unwrap(),
        );

        let expected: Vec<String> = vec![
            "--program-id",
            program_id.to_string_lossy().to_string().as_str(),
            "/contracts/contract.so",
        ]
        .into_iter()
        .map(str::to_string)
        .collect();
        assert_eq!(expected, result);
    }

    #[test]
    fn calc_deploy_cmd_when_only_key_pair() {
        let kp = Some(PathBuf::from_str("/path/keypair.txt").unwrap());
        let url = None;
        let ws_url = None;
        let program_id = PathBuf::from_str("~/path/program-id-keypair.json").unwrap();

        let result = calculate_deploy_cmd_args(
            &program_id,
            kp.as_ref(),
            url,
            ws_url,
            &PathBuf::from_str("/contracts/contract.so").unwrap(),
        );

        let expected: Vec<String> = vec![
            "--program-id",
            program_id.to_string_lossy().to_string().as_str(),
            "-k",
            "/path/keypair.txt",
            "/contracts/contract.so",
        ]
        .into_iter()
        .map(str::to_string)
        .collect();
        assert_eq!(expected, result);
    }

    #[test]
    fn calc_deploy_cmd_when_only_url() {
        let kp = None;
        let url = Some(Url::from_str("http://127.0.0.1:3333/").unwrap());
        let ws_url = None;
        let program_id = PathBuf::from_str("~/path/program-id-keypair.json").unwrap();

        let result = calculate_deploy_cmd_args(
            &program_id,
            kp,
            url.as_ref(),
            ws_url,
            &PathBuf::from_str("/contracts/contract.so").unwrap(),
        );

        let expected: Vec<String> = vec![
            "--program-id",
            program_id.to_string_lossy().to_string().as_str(),
            "-u",
            "http://127.0.0.1:3333/",
            "/contracts/contract.so",
        ]
        .into_iter()
        .map(str::to_string)
        .collect();
        assert_eq!(expected, result);
    }

    #[test]
    fn calc_deploy_cmd_when_only_ws_url() {
        let kp = None;
        let url = None;
        let ws_url = Some(Url::from_str("http://127.0.0.1:3333/").unwrap());
        let program_id = PathBuf::from_str("~/path/program-id-keypair.json").unwrap();

        let result = calculate_deploy_cmd_args(
            &program_id,
            kp,
            url,
            ws_url.as_ref(),
            &PathBuf::from_str("/contracts/contract.so").unwrap(),
        );

        let expected: Vec<String> = vec![
            "--program-id",
            program_id.to_string_lossy().to_string().as_str(),
            "--ws",
            "http://127.0.0.1:3333/",
            "/contracts/contract.so",
        ]
        .into_iter()
        .map(str::to_string)
        .collect();
        assert_eq!(expected, result);
    }

    #[test]
    fn calc_deploy_cmd_when_full_params_provided() {
        let kp = Some(PathBuf::from_str("/path/keypair.txt").unwrap());
        let url = Some(Url::from_str("http://127.0.0.1:2222").unwrap());
        let ws_url = Some(Url::from_str("http://127.0.0.1:3333").unwrap());
        let program_id = PathBuf::from_str("~/path/program-id-keypair.json").unwrap();

        let result = calculate_deploy_cmd_args(
            &program_id,
            kp.as_ref(),
            url.as_ref(),
            ws_url.as_ref(),
            &PathBuf::from_str("/contracts/contract.so").unwrap(),
        );

        let expected: Vec<String> = vec![
            "--program-id",
            program_id.to_string_lossy().to_string().as_str(),
            "-k",
            "/path/keypair.txt",
            "-u",
            "http://127.0.0.1:2222/",
            "--ws",
            "http://127.0.0.1:3333/",
            "/contracts/contract.so",
        ]
        .into_iter()
        .map(str::to_string)
        .collect();
        assert_eq!(expected, result);
    }
}
