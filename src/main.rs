use aptos_sdk::crypto::ed25519::Ed25519PrivateKey;
use aptos_sdk::crypto::{SigningKey, ValidCryptoMaterialStringExt};
use aptos_sdk::move_types::language_storage::ModuleId;
use aptos_sdk::rest_client::AptosBaseUrl;
use aptos_sdk::types::transaction::{EntryFunction, TransactionPayload};
use aptos_sdk::{
    rest_client::Client,
    transaction_builder::TransactionFactory,
    types::{account_address::AccountAddress, chain_id::ChainId, LocalAccount},
};
use serde::Deserialize;

fn aptos_pubkey_to_addr(pubkey: [u8; 32]) -> AccountAddress {
    let mut pub_key = pubkey.to_vec();
    pub_key.push(0);
    use sha3::Digest;
    let mut hasher = sha3::Sha3_256::new();
    hasher.update(pub_key);
    let digest = hasher.finalize();
    AccountAddress::from_bytes(digest).unwrap()
}
#[tokio::main]
async fn main() {
    main_().await;
}
/// aptos move run --function-id 'default::message::set_message' --args 'string:hello'
async fn main_() {
    let home = std::env::var("HOME").unwrap();
    let yml_str = std::fs::read_to_string(format!("{home}/.aptos/config.yaml")).unwrap();
    let config: Config = serde_yml::from_str(&yml_str).unwrap();
    let private_key = config.profiles.default.private_key;

    let client = Client::new(AptosBaseUrl::Testnet.to_url());
    let private_key = Ed25519PrivateKey::from_encoded_string(&private_key).unwrap();
    let sender_public_key = private_key.verifying_key();
    let sender_address = aptos_pubkey_to_addr(sender_public_key.to_bytes());

    let (account, state) = client.get_account(sender_address).await.unwrap().into_parts();
    let sequence_number = account.sequence_number;
    let chain_id = ChainId::new(state.chain_id);

    // 1SUI=10.pow(9)MIST 1APTOS=10.pow(8)octas if max_gas/gas_price is too large get MAX_GAS_UNITS_EXCEEDS_MAX_GAS_UNITS_BOUND=13
    let max_gas = 10u64.pow(6);
    // let gas_unit_price = client.estimate_gas_price().await.unwrap().into_inner().gas_estimate;
    let gas_unit_price = 100;

    // Sign and submit transaction
    let transaction_factory = TransactionFactory::new(chain_id)
        .with_gas_unit_price(gas_unit_price)
        .with_max_gas_amount(max_gas);
    // .with_transaction_expiration_time(self.gas_options.expiration_secs);
    // https://explorer.aptoslabs.com/account/0xb411e3fd045765c73deca67f91be38131373dbf9eec0309068403558fe0bc202/modules/code/message?network=testnet
    // module hello_blockchain::message {
    let payload = TransactionPayload::EntryFunction(EntryFunction::new(
        // module_id::member_id
        ModuleId::new(sender_address, "message".parse().unwrap()),
        // if model_id+function_id wrong, get LINKER_ERROR
        "set_message".parse().unwrap(),
        vec![],
        vec![bcs::to_bytes("hello").unwrap()],
    ));
    let sender_account = &mut LocalAccount::new(sender_address, private_key, sequence_number);
    let transaction =
        sender_account.sign_with_transaction_builder(transaction_factory.payload(payload));
    let response = client.submit_and_wait(&transaction).await.unwrap();
    println!("response={response:#?}");
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
