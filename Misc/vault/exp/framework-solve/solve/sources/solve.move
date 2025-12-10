module solution::solution {

    // [*] Import dependencies
    use sui::tx_context::{Self, TxContext};
    use sui::coin::{Self, Coin, TreasuryCap};
    // use sui::sui::SUI;
    // use std::vector;
    use challenge::vault::{Self, buy_flag, AirdropTracker,request_airdrop,Vault};
    use challenge::vault_coin::VAULT_COIN;
    use sui::transfer;
    use std::debug;
    use std::string;
    use std::bcs;

    public fun solve(vault:&mut Vault, 
                     tracker: &mut AirdropTracker,
                     treasury_cap: &mut TreasuryCap<VAULT_COIN>, 
                     ctx: &mut TxContext
    ) {
        // your solution here.
        request_airdrop(tracker, treasury_cap, ctx);
        let sender = tx_context::sender(ctx);
        let coin = coin::mint(treasury_cap, 100_000_000_000,ctx);
        // transfer::public_transfer(coin, sender);
        buy_flag(tracker,vault,coin,ctx);
    }
}