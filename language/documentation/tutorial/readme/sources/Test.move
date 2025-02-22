// sources/Test.move
module 0x2::Test {
    use std::signer;

    struct Resource has key { i: u64 }

    public entry fun publish(account: &signer) {
        move_to(account, Resource { i: 10 })
    }

    public entry fun write(account: &signer, i: u64) acquires Resource {
        borrow_global_mut<Resource>(signer::address_of(account)).i = i;
    }

    public entry fun unpublish(account: &signer) acquires Resource {
        let Resource { i: _ } = move_from(signer::address_of(account));
    }

}