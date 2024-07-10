use aptos_sdk::crypto::ed25519::Ed25519PrivateKey;
use aptos_sdk::types::account_address::AccountAddress;
pub fn get_private_key_and_addr() -> (Ed25519PrivateKey, AccountAddress) {
    use serde::Deserialize;
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
    
    let home = std::env::var("HOME").unwrap();
    let yml_str = std::fs::read_to_string(format!("{home}/.aptos/config.yaml")).unwrap();
    let config: Config = serde_yml::from_str(&yml_str).unwrap();
    let private_key = config.profiles.default.private_key;

    let private_key = <Ed25519PrivateKey as aptos_sdk::crypto::ValidCryptoMaterialStringExt>::from_encoded_string(&private_key).unwrap();
    let public_key = aptos_sdk::crypto::SigningKey::verifying_key(&private_key);
    // let address = aptos_sdk::types::transaction::authenticator::AuthenticationKey::ed25519(&public_key).account_address();
    let address = aptos_pubkey_to_addr(public_key.to_bytes());
    (private_key, address)
}
fn aptos_pubkey_to_addr(pubkey: [u8; 32]) -> AccountAddress {
    let mut pub_key = pubkey.to_vec();
    pub_key.push(0);
    use sha3::Digest;
    let mut hasher = sha3::Sha3_256::new();
    hasher.update(pub_key);
    let digest = hasher.finalize();
    AccountAddress::from_bytes(digest).unwrap()
}

