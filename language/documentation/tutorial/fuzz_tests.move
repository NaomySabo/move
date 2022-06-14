script {
use 0x00000000000000000000000000000002::Test;
use 0x00000000000000000000000000000001::Signer;
fun test_script(account: signer) {
Test::publish(&account);
Test::unpublish(&account);
Test::write(&account,1345);
}
}
