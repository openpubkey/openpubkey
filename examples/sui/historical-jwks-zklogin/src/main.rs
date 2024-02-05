// Taken from https://github.com/MystenLabs/sui/blob/main/crates/sui-sdk/examples/read_api.rs

use std::env;
use sui_sdk::SuiClientBuilder;
use sui_sdk::types::base_types::ObjectID;
use sui_sdk::rpc_types::{SuiObjectDataOptions, SuiTransactionBlockResponseOptions, ObjectChange, SuiPastObjectResponse};


// historical-jwks-zklogin % cargo run 5 > oppubkeys5.json
// This script is a modified version of the script from https://github.com/MystenLabs/historical-jwks-zklogin
#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    // Take as input how many past objects to fetch
    let args: Vec<String> = env::args().collect();
    // Fail gracefully if no argument is provided
    if args.len() < 2 {
        println!("Please provide the number of past objects to fetch!");
        return Ok(());
    } 
    let past_objects = args[1].parse::<usize>().unwrap();
    // println!("Fetching {} past JWK objects", past_objects);

    let sui = SuiClientBuilder::default().build(
        "https://fullnode.mainnet.sui.io:443"
    ).await?;

    // The objectID of AuthenticatorStateInner
    let jwk_object_id = ObjectID::from_hex_literal("0xcfecb053c69314e75f36561910f3535dd466b6e2e3593708f370e80424617ae7").unwrap();

    // Fetch the latest object
    let object = sui.read_api().get_object_with_options(
        jwk_object_id,
        SuiObjectDataOptions::default().with_content().with_previous_transaction()
    ).await?;

    println!("{{");

    // println!(" *** Latest Object *** ");
    // println!("{:#?}", object.data.clone().unwrap());
    println!("\"latest-obj\":{}", serde_json::to_string_pretty(&object.data.clone()).unwrap());

    // println!(" *** Latest Object ***\n");
    let mut prev_tx_digest = object.data.clone().unwrap().previous_transaction.unwrap();

    for i in 0..past_objects {
        // Fetch the previous transaction
        let tx = sui.read_api().get_transaction_with_options(
            prev_tx_digest,
            SuiTransactionBlockResponseOptions::default().with_object_changes()
        ).await?;

        // Cast enum to Mutated
        let object_changes = tx.object_changes.unwrap();
        // Find the object_change with the correct object_id
        let object_changes = object_changes.iter().filter(|object_change| {
            match object_change {
                ObjectChange::Mutated { object_id, .. } => {
                    *object_id == jwk_object_id
                },
                _ => false
            }
        }).collect::<Vec<&ObjectChange>>();

        // Make sure that there is only one object_change with the correct object_id
        assert_eq!(object_changes.len(), 1);

        let prev_obj_version = match &object_changes[0] {
            ObjectChange::Mutated { 
                previous_version, 
                object_id,
                ..
            } => {
                assert_eq!(*object_id, jwk_object_id);
                previous_version
            },
            _ => panic!("Expected ObjectChange::Mutated")
        };

        // println!(" *** Previous Object version {} *** ", i);
        // println!(",\"prevobjecti\":\"{}\",", i);
        // println!("\"prevobjectver\":{},", serde_json::to_string_pretty(&prev_obj_version).unwrap());
        // println!("{:#?}", prev_obj_version);
        // println!("{}", serde_json::to_string_pretty(&prev_obj_version).unwrap());
        // println!(" *** Previous Object version {} ***\n", i);
        // println!("\"prevobject\":{},", serde_json::to_string_pretty(&prev_obj_version).unwrap());


        let prev_obj = sui.read_api().try_get_parsed_past_object(
            jwk_object_id,
            *prev_obj_version,
            SuiObjectDataOptions::default().with_content().with_previous_transaction()
        ).await?;

        // println!(" *** Previous Object {} *** ", i);
        // println!("{:#?}", prev_obj);
        println!(",\"{}-{}\":{}", i, serde_json::to_string_pretty(&prev_obj_version).unwrap(), serde_json::to_string_pretty(&prev_obj).unwrap());

        // println!("{},", serde_json::to_string_pretty(&prev_obj).unwrap());
        // println!("{}", serde_json::to_string_pretty(&prev_obj).unwrap());
        // println!(" *** Previous Object {} ***\n", i);

        // Set the object to the previous object
        prev_tx_digest = match prev_obj {
            SuiPastObjectResponse::VersionFound(object) => {
                object.previous_transaction.unwrap()
            },
            _ => panic!("Expected SuiPastObjectResponse::VersionFound")
        }
    }

    println!("}}");

    Ok(())
}
