use aptos_sdk::move_types::language_storage::ModuleId;
use aptos_sdk::rest_client::AptosBaseUrl;
use aptos_sdk::types::transaction::{EntryFunction, TransactionPayload};
use aptos_sdk::{
    rest_client::Client,
    transaction_builder::TransactionFactory,
    types::{chain_id::ChainId, LocalAccount},
};

#[tokio::main]
async fn main() {
    main_().await;
}
/// aptos move run --function-id 'default::message::set_message' --args 'string:hello'
async fn main_() {
    let (private_key, addr) = aptos_example::get_private_key_and_addr();
    
    let client = Client::new(AptosBaseUrl::Testnet.to_url());
    let (account, state) = client.get_account(addr).await.unwrap().into_parts();
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
        ModuleId::new(addr, "message".parse().unwrap()),
        // if model_id+function_id wrong, get LINKER_ERROR
        "set_message".parse().unwrap(),
        vec![],
        vec![aptos_sdk::bcs::to_bytes("hello").unwrap()],
    ));
    let sender_account = &mut LocalAccount::new(addr, private_key, sequence_number);
    let transaction =
        sender_account.sign_with_transaction_builder(transaction_factory.payload(payload));
    let response = client.submit_and_wait(&transaction).await.unwrap();
    println!("response={response:#?}");
}
