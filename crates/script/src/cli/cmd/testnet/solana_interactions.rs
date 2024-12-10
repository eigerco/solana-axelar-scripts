use std::str::FromStr;

use axelar_solana_encoding::types::execute_data::{MerkleisedMessage, SigningVerifierSetInfo};
use axelar_solana_gateway::processor::GatewayEvent;
use axelar_solana_gateway::state::incoming_message::command_id;
use eyre::OptionExt;
use gateway_event_stack::{MatchContext, ProgramInvocationState};
use router_api::{Address, ChainName, CrossChainId};
use solana_sdk::commitment_config::CommitmentConfig;
use solana_sdk::compute_budget::ComputeBudgetInstruction;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Keypair;
use solana_sdk::signer::Signer;
use solana_transaction_status::UiTransactionEncoding;

use crate::cli::cmd::axelar_deployments::EvmChain;

pub(crate) fn send_memo_from_solana(
    solana_rpc_client: &solana_client::rpc_client::RpcClient,
    gateway_root_pda: &solana_sdk::pubkey::Pubkey,
    solana_keypair: &Keypair,
    destination_chain: &EvmChain,
    solana_chain_id: &str,
    destination_memo_contract: ethers::types::H160,
    memo: &str,
) -> eyre::Result<(Vec<u8>, router_api::Message)> {
    let hash = solana_rpc_client.get_latest_blockhash()?;
    let tx = solana_sdk::transaction::Transaction::new_signed_with_payer(
        &[
            axelar_solana_memo_program::instruction::call_gateway_with_memo(
                gateway_root_pda,
                &solana_keypair.pubkey(),
                memo.to_string(),
                destination_chain.id.clone(),
                ethers::utils::to_checksum(&destination_memo_contract, None),
                &axelar_solana_gateway::ID,
            )?,
        ],
        Some(&solana_keypair.pubkey()),
        &[&solana_keypair],
        hash,
    );
    let signature = solana_rpc_client.send_and_confirm_transaction(&tx)?;

    // Fetch the transaction details using the signature
    let tx_details = solana_rpc_client.get_transaction_with_config(
        &signature,
        solana_client::rpc_config::RpcTransactionConfig {
            encoding: Some(UiTransactionEncoding::Json),
            commitment: Some(CommitmentConfig::confirmed()),
            max_supported_transaction_version: None,
        },
    )?;

    // Extract log messages from the transaction metadata
    let log_msgs = tx_details
        .transaction
        .meta
        .ok_or_eyre("no meta field")?
        .log_messages
        .ok_or(eyre::eyre!("no log messages"))?;

    for log in &log_msgs {
        tracing::info!(?log, "solana tx log");
    }
    let res = gateway_event_stack::build_program_event_stack(
        &MatchContext::new(axelar_solana_gateway::ID.to_string().as_str()),
        &log_msgs,
        gateway_event_stack::parse_gateway_logs,
    );
    let call_contract = res.into_iter().next().ok_or_eyre("event not present")?;
    let ProgramInvocationState::Succeeded(call_contract) = call_contract else {
        eyre::bail!("unexpected call stack state");
    };
    let (event_idx, gateway_event) = call_contract
        .into_iter()
        .next()
        .ok_or_eyre("event not present")?;
    let GatewayEvent::CallContract(call_contract) = gateway_event else {
        eyre::bail!("unexpected event");
    };

    let payload = call_contract.payload.clone();
    let signature = signature.to_string();
    let message = router_api::Message {
        cc_id: CrossChainId::new(solana_chain_id, format!("{signature}-{event_idx}")).unwrap(),
        source_address: Address::from_str(call_contract.sender_key.to_string().as_str())
            .map_err(|err| eyre::eyre!(format!("invalid pubkey: {}", err.to_string())))?,
        destination_chain: ChainName::from_str(call_contract.destination_chain.as_str())
            .map_err(|err| eyre::eyre!(format!("{}", err.to_string())))?,
        destination_address: Address::from_str(call_contract.destination_contract_address.as_str())
            .map_err(|err| eyre::eyre!(format!("{}", err.to_string())))?,
        payload_hash: call_contract.payload_hash,
    };

    Ok((payload, message))
}

#[tracing::instrument(skip_all)]
pub(crate) fn solana_call_executable(
    message: axelar_solana_encoding::types::messages::Message,
    payload: &[u8],
    gateway_incoming_message_pda: solana_sdk::pubkey::Pubkey,
    solana_rpc_client: &solana_client::rpc_client::RpcClient,
    solana_keypair: &Keypair,
) -> eyre::Result<()> {
    let ix = axelar_executable::construct_axelar_executable_ix(
        message,
        payload,
        gateway_incoming_message_pda,
    )?;

    send_solana_tx(
        solana_rpc_client,
        &[
            ComputeBudgetInstruction::set_compute_unit_limit(1_399_850_u32),
            ix,
        ],
        solana_keypair,
    )?;
    Ok(())
}

#[tracing::instrument(skip_all)]
pub(crate) fn solana_start_verification_session(
    solana_keypair: &Keypair,
    gateway_root_pda: solana_sdk::pubkey::Pubkey,
    payload_merkle_root: [u8; 32],
    solana_rpc_client: &solana_client::rpc_client::RpcClient,
) -> eyre::Result<(solana_sdk::pubkey::Pubkey, u8)> {
    tracing::info!("solana gateway.init_verification_session");

    let (pda, bump) = axelar_solana_gateway::get_signature_verification_pda(
        &gateway_root_pda,
        &payload_merkle_root,
    );
    let ix = axelar_solana_gateway::instructions::initialize_payload_verification_session(
        solana_keypair.pubkey(),
        gateway_root_pda,
        payload_merkle_root,
    )?;

    send_solana_tx(
        solana_rpc_client,
        &[
            ComputeBudgetInstruction::set_compute_unit_limit(1_399_850_u32),
            ix,
        ],
        solana_keypair,
    )?;
    tracing::info!(?pda, "verification session");
    Ok((pda, bump))
}

#[tracing::instrument(skip_all)]
pub(crate) fn solana_verify_signature(
    solana_keypair: &Keypair,
    gateway_root_pda: solana_sdk::pubkey::Pubkey,
    verification_session_tracker_pda: solana_sdk::pubkey::Pubkey,
    payload_merkle_root: [u8; 32],
    verifier_info: SigningVerifierSetInfo,
    solana_rpc_client: &solana_client::rpc_client::RpcClient,
) -> eyre::Result<()> {
    tracing::info!("solana gateway.verify_signature");

    let ix = axelar_solana_gateway::instructions::verify_signature(
        gateway_root_pda,
        verification_session_tracker_pda,
        payload_merkle_root,
        verifier_info,
    )?;

    send_solana_tx(
        solana_rpc_client,
        &[
            ComputeBudgetInstruction::set_compute_unit_limit(1_399_850_u32),
            ix,
        ],
        solana_keypair,
    )?;
    Ok(())
}

#[tracing::instrument(skip_all)]
pub(crate) fn solana_approve_message(
    solana_keypair: &Keypair,
    gateway_root_pda: solana_sdk::pubkey::Pubkey,
    verification_session_tracker_pda: solana_sdk::pubkey::Pubkey,
    payload_merkle_root: [u8; 32],
    merkelised_message: MerkleisedMessage,
    solana_rpc_client: &solana_client::rpc_client::RpcClient,
) -> eyre::Result<Pubkey> {
    tracing::info!("solana gateway.verify_signature");

    let command_id = command_id(
        merkelised_message.leaf.message.cc_id.chain.as_str(),
        merkelised_message.leaf.message.cc_id.id.as_str(),
    );
    let (pda, _bump) = axelar_solana_gateway::get_incoming_message_pda(&command_id);
    let ix = axelar_solana_gateway::instructions::approve_messages(
        merkelised_message,
        payload_merkle_root,
        gateway_root_pda,
        solana_keypair.pubkey(),
        verification_session_tracker_pda,
        pda,
    )?;

    send_solana_tx(
        solana_rpc_client,
        &[
            ComputeBudgetInstruction::set_compute_unit_limit(1_399_850_u32),
            ix,
        ],
        solana_keypair,
    )?;
    Ok(pda)
}

pub(crate) fn send_solana_tx(
    solana_rpc_client: &solana_client::rpc_client::RpcClient,
    ixs: &[solana_sdk::instruction::Instruction],
    solana_keypair: &Keypair,
) -> eyre::Result<()> {
    let hash = solana_rpc_client.get_latest_blockhash()?;
    let tx = solana_sdk::transaction::Transaction::new_signed_with_payer(
        ixs,
        Some(&solana_keypair.pubkey()),
        &[solana_keypair],
        hash,
    );
    let signature = solana_rpc_client.send_and_confirm_transaction_with_spinner(&tx)?;
    let devnet_url = format!("https://explorer.solana.com/tx/{signature:?}?cluster=devnet",);
    tracing::info!(?signature, devnet_url, "solana tx sent");
    Ok(())
}
