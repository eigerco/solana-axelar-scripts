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
use solana_sdk::signature::{Keypair, Signature};
use solana_sdk::signer::Signer;
use solana_transaction_status::UiTransactionEncoding;

use crate::cli::cmd::axelar_deployments::EvmChain;

pub(crate) fn send_memo_from_solana(
    solana_rpc_client: &solana_client::rpc_client::RpcClient,
    gateway_root_pda: &solana_sdk::pubkey::Pubkey,
    memo_counter_pda: &solana_sdk::pubkey::Pubkey,
    solana_keypair: &Keypair,
    destination_chain: &EvmChain,
    solana_chain_id: &str,
    destination_memo_contract: ethers::types::H160,
    memo: &str,
) -> eyre::Result<(Vec<u8>, router_api::Message)> {
    let instruction = axelar_solana_memo_program::instruction::call_gateway_with_memo(
        gateway_root_pda,
        &memo_counter_pda,
        memo.to_string(),
        destination_chain.axelar_id.clone(),
        ethers::utils::to_checksum(&destination_memo_contract, None),
        &axelar_solana_gateway::ID,
    )?;

    let signature = send_solana_tx(solana_rpc_client, &[instruction], solana_keypair)?;

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

pub(crate) fn send_solana_tx(
    solana_rpc_client: &solana_client::rpc_client::RpcClient,
    ixs: &[solana_sdk::instruction::Instruction],
    solana_keypair: &Keypair,
) -> eyre::Result<Signature> {
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
    Ok(signature)
}
