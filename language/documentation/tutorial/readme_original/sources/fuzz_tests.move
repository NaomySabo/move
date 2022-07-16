script {
    use 0x2::Test;
    fun test_script(account: signer) {
        Test::publish(&account);
        Test::write(&account,1345);
        Test::unpublish(&account);
    }
}