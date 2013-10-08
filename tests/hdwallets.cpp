#include <iostream>
#include <string.h>

#include "../src/hdwallet.h"

using namespace Coin;
using namespace std;

void show(const HDKeychain& keychain, bool showfields = false)
{
    if (showfields) {
        std::cout << keychain.toString();
    }
    std::cout << "  * ext " << (keychain.isPrivate() ? "prv" : "pub") << ": " << toBase58Check(keychain.extkey()) << std::endl;
//    std::cout << "extkey: " << uchar_vector(keychain.extkey()).getHex() << std::endl;
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

        HDKeychain priv(0, 0, 0, c, k);
        HDKeychain pub = priv.getPublic();
        cout << "* [Chain m]" << endl;
        show(pub);
        show(priv);

        priv = priv.getChild(0x80000000);
        pub = priv.getPublic();
        cout << "* [Chain m/0']" << endl;
        show(pub);
        show(priv);

        HDKeychain pub_ = pub.getChild(0x00000001);
        priv = priv.getChild(0x00000001);
        pub = priv.getPublic();
        cout << "* [Chain m/0'/1]" << endl;
        show(pub);
        show(pub_);
        show(priv);
        return 0;
    }
    catch (const std::exception& e) {
        std::cout << "Error: " << e.what() << std::endl;
    } 
    return 1;
}
