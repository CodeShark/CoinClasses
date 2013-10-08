#include <iostream>
#include <string.h>

#include "../src/hdwallet.h"

const uchar_vector parent_fingerprint("00000000");

using namespace Coin;

void displayKeychain(const HDKeychain& keychain)
{
    std::cout << std::endl;
    std::cout << keychain.toString();
    std::cout << "extkey: " << toBase58Check(keychain.extkey()) << std::endl;
}

int main()
{
    try {
        uchar_vector seed("000102030405060708090a0b0c0d0e0f");
        
        HDSeed hdSeed(seed);
        bytes_t k = hdSeed.getMasterKey();
        bytes_t c = hdSeed.getMasterChainCode();

        HDKeychain::setVersions(0x0488ADE4, 0x0488B21E);
        HDKeychain keychain1(0, 0, 0, c, k);
        displayKeychain(keychain1);

        HDKeychain keychain2;
        keychain1.getPublic(keychain2);
        displayKeychain(keychain2);

        if (!keychain1.getChild(keychain2, 0)) {
            throw std::runtime_error("Derivation for i = 0 failed.");
        }
        displayKeychain(keychain2);

        std::cout << std::endl;
        return 0;
    }
    catch (const std::exception& e) {
        std::cout << "Error: " << e.what() << std::endl;
    } 
    return 1;
}

