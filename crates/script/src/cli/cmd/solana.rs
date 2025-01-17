use std::collections::BTreeMap;
use std::fmt::Display;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use axelar_solana_encoding::hasher::NativeHasher;
use axelar_solana_encoding::types::pubkey::PublicKey;
use axelar_solana_encoding::types::verifier_set::VerifierSet;
use axelar_solana_gateway::get_gateway_root_config_pda;
use axelar_solana_gateway::state::config::RotationDelaySecs;
use contract_builder::solana::contracts_artifact_dir;
use eyre::OptionExt;
use solana_client::rpc_client::RpcClient;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Signer;
use tracing::info;
use url::Url;
use xshell::{cmd, Shell};

use super::cosmwasm::cosmos_client::signer::SigningClient;
use super::deployments::{SolanaDeploymentRoot, SolanaMemoProgram};
use super::testnet::solana_interactions::send_solana_tx;
use crate::cli::cmd::deployments::{GasService, SolanaGatewayDeployment, SolanaIts};
use crate::cli::cmd::testnet::multisig_prover_api;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum)]
pub(crate) enum SolanaContract {
    AxelarSolanaGateway,
    AxelarSolanaMemo,
    AxelarSolanaGasService,
    AxelarSolanaIts,
}

impl SolanaContract {
    /// Provides the predictable output artifact that will be
    /// generated when each contract it's built. This is a helper
    /// method that is normally join'`ed()` with other base directories.
    pub(crate) fn file(self) -> PathBuf {
        match self {
            SolanaContract::AxelarSolanaGateway => PathBuf::from("axelar_solana_gateway.so"),
            SolanaContract::AxelarSolanaMemo => PathBuf::from("axelar_solana_memo_program.so"),
            SolanaContract::AxelarSolanaGasService => PathBuf::from("axelar_solana_gas_service.so"),
            SolanaContract::AxelarSolanaIts => PathBuf::from("axelar_solana_its.so"),
        }
    }
}

impl Display for SolanaContract {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SolanaContract::AxelarSolanaGateway => write!(f, "axelar-solana-gateway"),
            SolanaContract::AxelarSolanaMemo => write!(f, "axelar-solana-memo-program"),
            SolanaContract::AxelarSolanaGasService => write!(f, "axelar-solana-gas-service"),
            SolanaContract::AxelarSolanaIts => write!(f, "axelar-solana-its"),
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
    info!("Starting compiling {}", contract);
    contract_builder::solana::build_contracts()?;
    info!("Compiled {}", contract);

    info!("Starting deploying {}", contract);
    deploy_contract(contract, program_id, keypair_path, url, ws_url)?;
    info!("Deployed {contract}");
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

    let (gateway_config_pda, _bump) = axelar_solana_gateway::get_gateway_root_config_pda();

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
        let pubkey = PublicKey::Secp256k1(signer.pub_key.as_ref().try_into()?);
        let weight = signer.weight.u128();
        signers.insert(pubkey, weight);
    }
    let verifier_set = VerifierSet {
        nonce: multisig_prover_response.verifier_set.created_at,
        signers,
        quorum: multisig_prover_response.verifier_set.threshold.u128(),
    };
    tracing::info!(
        returned = ?multisig_prover_response.verifier_set,
        "returned verifier set"
    );
    tracing::info!(
        reconstructed = ?verifier_set,
        "reconstructed verifier set"
    );

    let rpc_client = RpcClient::new(defaults::rpc_url()?.to_string());
    let verifier_set_hash =
        axelar_solana_encoding::types::verifier_set::verifier_set_hash::<NativeHasher>(
            &verifier_set,
            &solana_deployment_root.solana_configuration.domain_separator,
        )?;
    let ini_tracker_pda = axelar_solana_gateway::get_verifier_set_tracker_pda(verifier_set_hash);
    let upgrade_auth = payer_kp.pubkey();
    let initialize_config = axelar_solana_gateway::instructions::initialize_config(
        payer_kp.pubkey(),
        upgrade_auth,
        solana_deployment_root.solana_configuration.domain_separator,
        vec![(verifier_set_hash, ini_tracker_pda.0)],
        minimum_rotation_delay,
        payer_kp.pubkey(),
        previous_signers_retention.into(),
        gateway_config_pda,
    )?;
    send_solana_tx(&rpc_client, &[initialize_config], &payer_kp)?;

    // save the information in our deployment tracker
    solana_deployment_root.solana_gateway = Some(SolanaGatewayDeployment {
        domain_separator: solana_deployment_root.solana_configuration.domain_separator,
        initial_signer_sets: vec![multisig_prover_response.verifier_set],
        minimum_rotation_delay,
        operator: payer_kp.pubkey(),
        previous_signers_retention,
        program_id: axelar_solana_gateway::id(),
        config_pda: gateway_config_pda,
    });

    Ok(())
}

#[tracing::instrument(skip_all)]
pub(crate) fn init_gas_service(
    solana_deployment_root: &mut SolanaDeploymentRoot,
    authority: String,
    salt: String,
) -> eyre::Result<()> {
    let payer_kp = defaults::payer_kp()?;
    let rpc_client = RpcClient::new(defaults::rpc_url()?.to_string());

    let authority = Pubkey::from_str(authority.as_str())?;
    let salt_hash = solana_sdk::keccak::hash(salt.as_bytes()).0;
    let gas_service_config_pda = axelar_solana_gas_service::get_config_pda(
        &axelar_solana_gas_service::id(),
        &salt_hash,
        &authority,
    );

    let account = rpc_client.get_account(&gas_service_config_pda.0);
    if account.is_ok() {
        solana_deployment_root.gas_service = Some(GasService {
            config_pda: gas_service_config_pda.0,
            program_id: axelar_solana_gas_service::id(),
            authority,
            salt,
            salt_hash,
        });
        tracing::warn!("Config PDA alradey initialized");
        return Ok(());
    }
    let ix = axelar_solana_gas_service::instructions::init_config(
        &axelar_solana_gas_service::id(),
        &payer_kp.pubkey(),
        &authority,
        &gas_service_config_pda.0,
        salt_hash,
    )?;

    send_solana_tx(&rpc_client, &[ix], &payer_kp)?;
    solana_deployment_root.gas_service = Some(GasService {
        config_pda: gas_service_config_pda.0,
        program_id: axelar_solana_gas_service::id(),
        authority,
        salt,
        salt_hash,
    });

    Ok(())
}

#[tracing::instrument(skip_all)]
pub(crate) fn init_its(
    solana_deployment_root: &mut SolanaDeploymentRoot,
    operator: String,
) -> eyre::Result<()> {
    let payer_kp = defaults::payer_kp()?;
    let rpc_client = RpcClient::new(defaults::rpc_url()?.to_string());

    let gateway_root_pda = get_gateway_root_config_pda().0;
    let its_root_pda = axelar_solana_its::find_its_root_pda(&gateway_root_pda);
    let operator = Pubkey::from_str(operator.as_str())?;
    let account = rpc_client.get_account(&its_root_pda.0);
    if account.is_ok() {
        solana_deployment_root.solana_its = Some(SolanaIts {
            solana_gateway_root_config_pda: gateway_root_pda,
            program_id: axelar_solana_its::id(),
            config_pda: its_root_pda.0,
            operator,
        });
        tracing::warn!("counter PDA alradey initialized");
        return Ok(());
    }
    let ix =
        axelar_solana_its::instructions::initialize(payer_kp.pubkey(), gateway_root_pda, operator)?;
    send_solana_tx(&rpc_client, &[ix], &payer_kp)?;
    solana_deployment_root.solana_its = Some(SolanaIts {
        solana_gateway_root_config_pda: gateway_root_pda,
        program_id: axelar_solana_its::id(),
        config_pda: its_root_pda.0,
        operator,
    });

    Ok(())
}

#[tracing::instrument(skip_all)]
pub(crate) fn init_memo_program(
    solana_deployment_root: &mut SolanaDeploymentRoot,
) -> eyre::Result<()> {
    let payer_kp = defaults::payer_kp()?;
    let rpc_client = RpcClient::new(defaults::rpc_url()?.to_string());

    let gateway_root_pda = get_gateway_root_config_pda().0;
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
fn deploy_contract(
    contract: SolanaContract,
    program_id: &Path,
    keypair_path: Option<&PathBuf>,
    url: Option<&Url>,
    ws_url: Option<&Url>,
) -> eyre::Result<()> {
    let contract_compiled_binary = contracts_artifact_dir().join(contract.file());
    let sh = Shell::new()?;
    let deploy_cmd_args = calculate_deploy_cmd_args(
        program_id,
        keypair_path,
        url,
        ws_url,
        &contract_compiled_binary,
    );

    cmd!(sh, "solana program deploy {deploy_cmd_args...}").read()?;
    Ok(())
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

    use super::*;

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
