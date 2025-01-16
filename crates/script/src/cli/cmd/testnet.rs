pub(crate) mod cosmwasm_interactions;
pub(crate) mod evm_interaction;
pub(crate) mod multisig_prover_api;
pub(crate) mod solana_interactions;

use std::str::FromStr;
use std::time::Duration;

use axelar_solana_encoding::types::execute_data::{ExecuteData, MerkleisedPayload};
use axelar_solana_gateway::get_gateway_root_config_pda;
use axelar_solana_gateway::state::GatewayConfig;
use ethers::types::{Address as EvmAddress, H160};
use evm_contracts_test_suite::EvmSigner;
use eyre::OptionExt;
use solana_sdk::signature::Keypair;

use super::axelar_deployments::{AxelarDeploymentRoot, EvmChain};
use super::cosmwasm::cosmos_client::signer::SigningClient;
use super::deployments::SolanaDeploymentRoot;
use crate::cli::cmd::evm::{send_memo_from_evm_to_evm, send_memo_to_solana};

#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
#[tracing::instrument(skip_all)]
pub(crate) async fn evm_to_solana(
    source_chain: &EvmChain,
    source_evm_signer: EvmSigner,
    cosmwasm_signer: SigningClient,
    solana_rpc_client: solana_client::rpc_client::RpcClient,
    solana_keypair: Keypair,
    memo_to_send: String,
    axelar_deployments: &AxelarDeploymentRoot,
    solana_deployments: &mut SolanaDeploymentRoot,
    only_evm_calls: bool,
) -> eyre::Result<()> {
    let destination_chain_name = solana_deployments
        .solana_configuration
        .chain_name_on_axelar_chain
        .as_str();
    let source_axelar_gateway = axelar_deployments
        .axelar
        .contracts
        .gateway
        .networks
        .get(source_chain.axelar_id.as_str())
        .and_then(|x| cosmrs::AccountId::from_str(x.address.as_str()).ok())
        .unwrap();
    let source_axelar_voting_verifier = axelar_deployments
        .axelar
        .contracts
        .voting_verifier
        .networks
        .get(source_chain.axelar_id.as_str())
        .and_then(|x| cosmrs::AccountId::from_str(x.address.as_str()).ok())
        .unwrap();
    let destination_multisig_prover = cosmrs::AccountId::from_str(
        solana_deployments
            .multisig_prover
            .as_ref()
            .ok_or_eyre("multisig prover deployment not found")?
            .address
            .as_str(),
    )
    .unwrap();
    let our_evm_deployment_tracker = solana_deployments
        .evm_deployments
        .get_or_insert_mut(source_chain);

    let root_pda = get_gateway_root_config_pda().0;
    let root_pda = solana_rpc_client.get_account(&root_pda).unwrap();
    // let account_data = GatewayConfig::read(&root_pda.data).unwrap();
    // tracing::info!(?account_data, "solana gateway root pda config");

    // let tx = send_memo_to_solana(
    //     source_evm_signer,
    //     memo_to_send.as_str(),
    //     destination_chain_name,
    //     our_evm_deployment_tracker,
    // )
    // .await?;
    // tracing::info!(
    //     source = source_chain.id,
    //     dest = destination_chain_name,
    //     memo = memo_to_send,
    //     "memo sent"
    // );
    // tracing::info!("sleeping to allow the tx to settle");
    // if only_evm_calls {
    //     return Ok(());
    // }
    // tokio::time::sleep(Duration::from_secs(30)).await;
    // let (payload, message) = evm_interaction::create_axelar_message_from_evm_log(&tx,
    // source_chain); let execute_data = cosmwasm_interactions::wire_cosmwasm_contracts(
    //     source_chain.id.as_str(),
    //     destination_chain_name,
    //     memo_to_send,
    //     &message,
    //     cosmwasm_signer,
    //     &source_axelar_gateway,
    //     &source_axelar_voting_verifier,
    //     &destination_multisig_prover,
    //     &solana_deployments.axelar_configuration,
    // )
    // .await?;
    // let gateway_root_pda = get_gateway_root_config_pda().0;
    // let execute_data = borsh::from_slice::<ExecuteData>(&execute_data)?;

    // // init payload approval session
    // let (session_pda, _bump) = solana_interactions::solana_start_verification_session(
    //     &solana_keypair,
    //     gateway_root_pda,
    //     execute_data.payload_merkle_root,
    //     &solana_rpc_client,
    // )?;

    // // verify each signature
    // for sig in execute_data.signing_verifier_set_leaves {
    //     solana_interactions::solana_verify_signature(
    //         &solana_keypair,
    //         gateway_root_pda,
    //         session_pda,
    //         execute_data.payload_merkle_root,
    //         sig,
    //         &solana_rpc_client,
    //     )?;
    // }

    // // send the actual message
    // match execute_data.payload_items {
    //     MerkleisedPayload::VerifierSetRotation { .. } => todo!(),
    //     MerkleisedPayload::NewMessages { messages } => {
    //         for message in messages {
    //             let message_pda = solana_interactions::solana_approve_message(
    //                 &solana_keypair,
    //                 gateway_root_pda,
    //                 session_pda,
    //                 execute_data.payload_merkle_root,
    //                 message.clone(),
    //                 &solana_rpc_client,
    //             )?;
    //             solana_interactions::solana_call_executable(
    //                 message.leaf.message,
    //                 &payload,
    //                 message_pda,
    //                 &solana_rpc_client,
    //                 &solana_keypair,
    //             )?;
    //         }
    //     }
    // };
    todo!();
    Ok(())
}

#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
#[tracing::instrument(skip_all)]
pub(crate) async fn solana_to_evm(
    destination_chain: &EvmChain,
    destination_evm_signer: EvmSigner,
    cosmwasm_signer: SigningClient,
    destination_memo_contract: EvmAddress,
    solana_rpc_client: solana_client::rpc_client::RpcClient,
    solana_keypair: Keypair,
    memo_to_send: String,
    axelar_deployments: &AxelarDeploymentRoot,
    solana_deployments: &SolanaDeploymentRoot,
    only_solana_calls: bool,
) -> eyre::Result<()> {
    let source_chain_name = solana_deployments
        .solana_configuration
        .chain_name_on_axelar_chain
        .as_str();
    let source_axelar_gateway = cosmrs::AccountId::from_str(
        solana_deployments
            .axelar_gateway
            .as_ref()
            .ok_or_eyre("gateway deployment not found")?
            .address
            .as_str(),
    )
    .unwrap();
    let source_axelar_voting_verifier = cosmrs::AccountId::from_str(
        solana_deployments
            .voting_verifier
            .as_ref()
            .ok_or_eyre("voting verifier deployment not found")?
            .address
            .as_str(),
    )
    .unwrap();
    let destination_multisig_prover = axelar_deployments
        .axelar
        .contracts
        .multisig_prover
        .networks
        .get(destination_chain.axelar_id.as_str())
        .and_then(|x| cosmrs::AccountId::from_str(x.address.as_str()).ok())
        .unwrap();

    let gateway_root_pda = get_gateway_root_config_pda().0;
    let (payload, message) = solana_interactions::send_memo_from_solana(
        &solana_rpc_client,
        &gateway_root_pda,
        &solana_keypair,
        destination_chain,
        source_chain_name,
        destination_memo_contract,
        memo_to_send.as_str(),
    )?;
    if only_solana_calls {
        return Ok(());
    }
    let execute_data = cosmwasm_interactions::wire_cosmwasm_contracts(
        source_chain_name,
        &destination_chain.axelar_id,
        memo_to_send,
        &message,
        cosmwasm_signer,
        &source_axelar_gateway,
        &source_axelar_voting_verifier,
        &destination_multisig_prover,
        &solana_deployments.axelar_configuration,
    )
    .await?;

    // Call the EVM contracts
    let evm_gateway = destination_chain.get_evm_gateway()?;
    evm_interaction::approve_messages_on_evm_gateway(
        evm_gateway,
        execute_data,
        &destination_evm_signer,
    )
    .await?;
    evm_interaction::call_execute_on_destination_evm_contract(
        message,
        destination_memo_contract,
        evm_gateway,
        destination_evm_signer,
        payload.iter().collect::<ethers::types::Bytes>(),
    )
    .await?;

    Ok(())
}

#[allow(clippy::too_many_arguments)]
#[tracing::instrument(skip_all)]
pub(crate) async fn evm_to_evm(
    source_chain: &EvmChain,
    destination_chain: &EvmChain,
    source_evm_signer: EvmSigner,
    destination_evm_signer: EvmSigner,
    memo_to_send: String,
    cosmwasm_signer: SigningClient,
    axelar_deployments: &AxelarDeploymentRoot,
    solana_deployment_root: &mut SolanaDeploymentRoot,
) -> eyre::Result<()> {
    let source_axelar_gateway = axelar_deployments
        .axelar
        .contracts
        .gateway
        .networks
        .get(source_chain.axelar_id.as_str())
        .and_then(|x| cosmrs::AccountId::from_str(x.address.as_str()).ok())
        .unwrap();
    let source_axelar_voting_verifier = axelar_deployments
        .axelar
        .contracts
        .voting_verifier
        .networks
        .get(source_chain.axelar_id.as_str())
        .and_then(|x| cosmrs::AccountId::from_str(x.address.as_str()).ok())
        .unwrap();
    let destination_multisig_prover = axelar_deployments
        .axelar
        .contracts
        .multisig_prover
        .networks
        .get(destination_chain.axelar_id.as_str())
        .and_then(|x| cosmrs::AccountId::from_str(x.address.as_str()).ok())
        .unwrap();

    let source_chain_tracker = &solana_deployment_root
        .evm_deployments
        .get_or_insert_mut(source_chain)
        .clone();
    let destination_chain_tracker = solana_deployment_root
        .evm_deployments
        .get_or_insert_mut(destination_chain);
    let tx = send_memo_from_evm_to_evm(
        source_evm_signer,
        memo_to_send.clone(),
        destination_chain_tracker,
        source_chain_tracker,
    )
    .await?;
    tracing::info!(
        source = source_chain.axelar_id,
        dest = destination_chain.axelar_id,
        memo = memo_to_send,
        "memo sent"
    );
    tracing::info!("sleeping to allow the tx to settle");
    tokio::time::sleep(Duration::from_secs(10)).await;
    let (payload, message) = evm_interaction::create_axelar_message_from_evm_log(&tx, source_chain);

    let execute_data = cosmwasm_interactions::wire_cosmwasm_contracts(
        source_chain.axelar_id.as_str(),
        &destination_chain.axelar_id,
        memo_to_send,
        &message,
        cosmwasm_signer,
        &source_axelar_gateway,
        &source_axelar_voting_verifier,
        &destination_multisig_prover,
        &solana_deployment_root.axelar_configuration,
    )
    .await?;

    // Call the destination chain Gateway
    let evm_gateway = destination_chain.get_evm_gateway()?;
    evm_interaction::approve_messages_on_evm_gateway(
        evm_gateway,
        execute_data,
        &destination_evm_signer,
    )
    .await?;
    let destination_memo_contract = H160::from_str(
        destination_chain_tracker
            .memo_program_address
            .as_ref()
            .ok_or_eyre("memo contract not deployed")?,
    )?;
    evm_interaction::call_execute_on_destination_evm_contract(
        message,
        destination_memo_contract,
        evm_gateway,
        destination_evm_signer,
        payload,
    )
    .await?;

    Ok(())
}
