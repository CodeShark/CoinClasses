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
    uchar_vector seed("000102030405060708090a0b0c0d0e0f");
    
    HDSeed hdSeed(seed);
    bytes_t k = hdSeed.getMasterKey();
    bytes_t c = hdSeed.getMasterChainCode();

    HDKeychain::setVersions(0x0488ADE4, 0x0488B21E);
    HDKeychain keychain(0, 0, 0, c, k);
    displayKeychain(keychain);

    std::cout << std::endl;
    return 0;
}

