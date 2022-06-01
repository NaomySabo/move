
script {
    use 0x2::Test;
    use 0x1::Signer;
    // use 0x1::UnitTest;
    // use move_core_types::AccountAddress;
    // account:signer
    // use 0x1::move_vm_types::values::Value;
    fun test_script(account:signer) {
        // let a = @0xC;
        // let account: signer = {addr ; 0xC};
        // let accounts = create_signers_for_testing(1);
        // let account = Value::signer(AccountAddress::new(0xC));

        // let account = Signer::address_of(&addr);
        // let account: signer = AccountAddress::from_hex_literal(@0x1234);
        // AccountAddress::from_hex_literal(0x1234);
        // Test::write(&account, 78);

        // let account = accounts[0];
        Test::publish(&account);
        // Test::unpublish(&account);

        Test::write(&account, 78);
        Test::unpublish(&account);
        Signer::address_of(&account);
    }
}