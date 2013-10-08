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


        HDKeychain keychain1(0, 0, 0, c, k);
        HDKeychain keychain2(keychain1, true);
        show(keychain2);
        show(keychain1); 

        std::cout << "----------------------------------" << std::endl;

        HDKeychain keychain3;
        if (!keychain1.getChild(keychain3, 0)) {
            throw std::runtime_error("Derivation for i = 0 failed.");
        }

        HDKeychain keychain4;
        if (!keychain2.getChild(keychain4, 0)) {
            throw std::runtime_error("Derivation for i = 0 failed.");
        }
        
        show(keychain3);
        show(keychain4);

        return 0;
    }
    catch (const std::exception& e) {
        std::cout << "Error: " << e.what() << std::endl;
    } 
    return 1;
}

