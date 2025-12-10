module challenge::vault {
    use sui::balance::{Self, Balance};
    use sui::coin::{Self, Coin, TreasuryCap};
    use sui::vec_set::{Self, VecSet};
    use sui::tx_context::{Self, TxContext};
    use sui::object::{Self, UID};
    use sui::transfer;

    use challenge::vault_coin::VAULT_COIN;

    const E_DEPOSIT_ZERO: u64 = 0;
    const E_INSUFFICIENT_PROOF: u64 =1;
    const E_INVALID_ITEM: u64 = 2;
    const E_AIRDROP_ALREADY_CLAIMED: u64 = 3;
    
    const FLAG_TARGET: u64 = 100_000_000_000;
    const AIRDROP_AMOUNT: u64 = 5_000_000_000;

    public struct Vault has key, store {
        id: UID,
        total_balance: Balance<VAULT_COIN>,
        total_shares: u64,
    }

    public struct AdminCap has key, store {
        id: UID,
    }

    public struct VaultShare has key, store {
        id: UID,
        amount: u64,
    }

    public struct AirdropTracker has key, store {
        id: UID,
        recipients: VecSet<address>,
    }

    public struct Flag has key, store {
        id: UID,
        user: address,
        flag: bool
    }

    fun init(ctx: &mut TxContext) {
        let sender = tx_context::sender(ctx);

        let admin_cap = AdminCap { id: object::new(ctx) };

        let vault = Vault {
            id: object::new(ctx),
            total_balance: balance::zero<VAULT_COIN>(),
            total_shares: 1_000_000_000_000,
        };

        let airdrop_tracker = AirdropTracker {
            id: object::new(ctx),
            recipients: vec_set::empty<address>(),
        };

        transfer::share_object(vault);
        transfer::public_transfer(admin_cap, sender);
        transfer::share_object(airdrop_tracker);
    }

    public entry fun request_airdrop(
        tracker: &mut AirdropTracker,
        treasury_cap: &mut TreasuryCap<VAULT_COIN>,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);

        assert!(!vec_set::contains(&tracker.recipients, &sender), E_AIRDROP_ALREADY_CLAIMED);

        vec_set::insert(&mut tracker.recipients, sender);

        let coin = coin::mint(treasury_cap, AIRDROP_AMOUNT, ctx);

        transfer::public_transfer(coin, sender);
    }

    public entry fun deposit(
        vault: &mut Vault,
        coin: Coin<VAULT_COIN>,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);
        let deposit_amount = coin::value(&coin);
        assert!(deposit_amount > 0, E_DEPOSIT_ZERO);

        let total_tokens_in_vault = balance::value(&vault.total_balance);
        let current_total_shares = vault.total_shares;
        let shares_received: u64;

        if (total_tokens_in_vault == 0) {
            shares_received = deposit_amount;
        } else {
            let numerator = deposit_amount * current_total_shares;
            shares_received = numerator / total_tokens_in_vault;
        };

        assert!(shares_received > 0, E_DEPOSIT_ZERO);

        let deposited_balance = coin::into_balance(coin);
        balance::join(&mut vault.total_balance, deposited_balance);
        vault.total_shares = current_total_shares + shares_received;

        let share_cap = VaultShare {
            id: object::new(ctx),
            amount: shares_received
        };
        transfer::public_transfer(share_cap, sender);
    }

    public entry fun withdraw(
        vault: &mut Vault,
        user_shares: VaultShare,
        ctx: &mut TxContext
    ) {
        let recipient = tx_context::sender(ctx);
        let shares_to_burn = user_shares.amount;

        let total_tokens_in_vault = balance::value(&vault.total_balance);
        let current_total_shares = vault.total_shares;

        let token_numerator = shares_to_burn * total_tokens_in_vault;
        let token_received = token_numerator / current_total_shares;

        assert!(token_received > 0, E_DEPOSIT_ZERO); 

        let received_balance = balance::split(&mut vault.total_balance, token_received);
        let received_coin = coin::from_balance(received_balance, ctx);

        let VaultShare { id, amount: _ } = user_shares;
        object::delete(id);

        vault.total_shares = current_total_shares - shares_to_burn;

        transfer::public_transfer(received_coin, recipient);
    }

    public entry fun buy_flag(
        vault: &mut Vault,
        proof_coin: Coin<VAULT_COIN>,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);
        let proof_amount = coin::value(&proof_coin);
        assert!(proof_amount >= FLAG_TARGET, E_INSUFFICIENT_PROOF);
        let deposited_balance = coin::into_balance(proof_coin);
        balance::join(&mut vault.total_balance, deposited_balance);

        transfer::public_transfer(Flag {
            id: object::new(ctx),
            user: sender,
            flag: true
        }, sender);
    }

    public entry fun has_flag(flag: &mut Flag) {
        assert!(flag.flag == true, E_INVALID_ITEM);
    }

}