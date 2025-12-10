module challenge::vault_coin {
    use sui::coin;
    use sui::transfer;
    use sui::tx_context::TxContext;
    use sui::url;

    public struct VAULT_COIN has drop {}

    const INITIAL_SUPPLY: u64 = 95_000_000_000;
    const DECIMALS: u8 = 6;
    const SYMBOL: vector<u8> = b"Vault";
    const NAME: vector<u8> = b"Vault";
    const DESC: vector<u8> = b"Vault";

    fun init(otw: VAULT_COIN, ctx: &mut TxContext) {
        let sender = tx_context::sender(ctx);

        let (mut treasury_cap, metadata) = coin::create_currency(
            otw,
            DECIMALS,
            SYMBOL,
            NAME,
            DESC,
            option::none(),
            ctx,
        );

        transfer::public_freeze_object(metadata);

        let initial_coin = coin::mint(&mut treasury_cap, INITIAL_SUPPLY, ctx);
        transfer::public_transfer(initial_coin, sender);

        transfer::public_share_object(treasury_cap);
    }
}