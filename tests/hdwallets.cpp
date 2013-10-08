#include <iostream>
#include <string.h>

#include "../src/hdwallet.h"

const uchar_vector parent_fingerprint("00000000");

using namespace Coin;

void show(const HDKeychain& keychain, bool showfields = false)
{
    if (showfields) {
        std::cout << keychain.toString();
    }
    std::cout << "extkey: " << toBase58Check(keychain.extkey()) << std::endl;
}

int main()
{
    try {
        // Set version
        HDKeychain::setVersions(0x0488ADE4, 0x0488B21E);

        // Set seed
        HDSeed hdSeed(uchar_vector("000102030405060708090a0b0c0d0e0f"));
        bytes_t k = hdSeed.getMasterKey();
        bytes_t c = hdSeed.getMasterChainCode();


        HDKeychain priv0(0, 0, 0, c, k);
        HDKeychain pub0 = priv0.getPublic();
        show(pub0);
        show(priv0);
        std::cout << "-----------------------------------" << std::endl;

        HDKeychain priv1 = priv0.getChild(0);
        HDKeychain pub1 = priv1.getPublic();
        HDKeychain pub1_ = pub1.getPublic();
        show(priv1);
        show(pub1);
        show(pub1_);

        return 0;
    }
    catch (const std::exception& e) {
        std::cout << "Error: " << e.what() << std::endl;
    } 
    return 1;
}

