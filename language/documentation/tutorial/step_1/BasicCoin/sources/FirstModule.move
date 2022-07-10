module 0xCAFE::BasicCoin {
    struct Coin has key {
        value: u64,
    }

    public(script) fun mint(account: signer, value: u64) {
        move_to(&account, Coin { value })
    }
}
