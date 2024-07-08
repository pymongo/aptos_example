#![allow(warnings)]
use aptos_sdk::crypto::ed25519::{Ed25519PublicKey, Ed25519PrivateKey};
use aptos_sdk::crypto::{SigningKey, ValidCryptoMaterialStringExt};
use aptos_sdk::move_types::language_storage::ModuleId;
use aptos_sdk::rest_client::AptosBaseUrl;
use aptos_sdk::types::transaction::authenticator::AuthenticationKey;
use aptos_sdk::types::transaction::{EntryFunction, TransactionPayload};
use aptos_sdk::{
    rest_client::Client,
    transaction_builder::TransactionFactory,
    types::{
        account_address::AccountAddress,
        chain_id::ChainId,
        transaction::{Script, SignedTransaction, TransactionArgument},
        LocalAccount,
    },
};

use serde::Deserialize;

#[tokio::main]
async fn main(){
    main_().await;
}
/// aptos move run --function-id 'default::message::set_message' --args 'string:hello, blockchain'
async fn main_() {
    let home = std::env::var("HOME").unwrap();
    let yml_str = std::fs::read_to_string(format!("{home}/.aptos/config.yaml")).unwrap();
    let config: Config = serde_yml::from_str(&yml_str).unwrap();
    let private_key = config.profiles.default.private_key;

    let client = Client::new(AptosBaseUrl::Testnet.to_url());
    let private_key  = Ed25519PrivateKey::from_encoded_string(&private_key).unwrap();
    let sender_public_key = private_key.verifying_key();

    let mut pub_key = sender_public_key.to_bytes().to_vec();
    pub_key.push(0);
    use sha3::Digest;
    let mut hasher = sha3::Sha3_256::new();
    hasher.update(pub_key);
    let digest = hasher.finalize();
    // let addr = format!("0x{digest:02x}");
    let sender_address = AccountAddress::from_bytes(digest).unwrap();

    // Get sequence number for account
    let (account, state) = client
        .get_account(sender_address)
        .await.unwrap().into_parts();
    let sequence_number = account.sequence_number;
    let chain_id = ChainId::new(state.chain_id);
    // TODO: Check auth key against current private key and provide a better message
    
    /*
    1SUI=10.pow(9)MIST
    1APTOS=10.pow(8)octas
    */    
    let max_gas_octas = 10u64.pow(7);
    let gas_unit_price = client.estimate_gas_price().await.unwrap().into_inner().gas_estimate;

    // Sign and submit transaction
    let transaction_factory = TransactionFactory::new(chain_id)
        .with_gas_unit_price(gas_unit_price)
        .with_max_gas_amount(max_gas_octas);
        // .with_transaction_expiration_time(self.gas_options.expiration_secs);

    let payload = TransactionPayload::EntryFunction(EntryFunction::new(
        // module_id::member_id
        ModuleId::new(sender_address, "hello_blockchain::message".parse().unwrap()),
        "set_message".parse().unwrap(),
        vec![],
        vec![bcs::to_bytes("hello").unwrap()]
    ));
    let sender_account =
        &mut LocalAccount::new(sender_address, private_key, sequence_number);
    let transaction = sender_account
        .sign_with_transaction_builder(transaction_factory.payload(payload));
    let response = client
        .submit_and_wait(&transaction)
        .await
        .unwrap();
    println!("response={response:?}");
}

#[derive(Deserialize)]
struct Config {
    profiles: Profiles,
}
#[derive(Deserialize)]
struct Profiles {
    default: DefaultProfile,
}
#[derive(Deserialize)]
struct DefaultProfile {
    private_key: String,
    // rest_url: String
}
