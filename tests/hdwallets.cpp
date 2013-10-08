#include <iostream>
#include <cassert>

#include "../src/hdwallet.h"
#include "../src/Base58Check.h"

using namespace Coin;
using namespace std;

const uchar_vector SEED("000102030405060708090a0b0c0d0e0f");
const uint32_t CHAIN[] = { 0x80000000, 0x00000001, 0x80000002, 0x00000002, 0x3b9aca00 };
const unsigned int CHAIN_LENGTH = sizeof(CHAIN)/sizeof(uint32_t);

void showKey(const HDKeychain& keychain)
{
    cout << "  * ext " << (keychain.isPrivate() ? "prv" : "pub") << ": " << toBase58Check(keychain.extkey()) << endl;
}

void showStep(const string& chainname, const HDKeychain& pub, const HDKeychain& prv)
{
    cout << "* [" << chainname << "]" << endl;
    showKey(pub);
    showKey(prv);
}

int main()
{
    try {
        // Set version
        HDKeychain::setVersions(0x0488ADE4, 0x0488B21E);

        cout << "Master (hex): " << SEED.getHex() << endl;

        // Set seed
        HDSeed hdSeed(SEED);
        bytes_t k = hdSeed.getMasterKey();
        bytes_t c = hdSeed.getMasterChainCode();

        stringstream chainname;
        chainname << "Chain m";

        HDKeychain prv(0, 0, 0, c, k);
        HDKeychain pub = prv.getPublic();
        showStep(chainname.str(), pub, prv);

        HDKeychain oldpub;

        for (unsigned int k = 0; k < CHAIN_LENGTH; k++) {
            chainname << "/" << (CHAIN[k] & 0x7fffffff);
            if (CHAIN[k] & 0x80000000) {
                chainname << "'";
            }
            else {
                oldpub = pub;
            }

            prv = prv.getChild(CHAIN[k]);
            pub = prv.getPublic();
            if (!(CHAIN[k] & 0x80000000)) assert(pub.extkey() == oldpub.getChild(CHAIN[k]).extkey());
            showStep(chainname.str(), pub, prv);
        }

        return 0;
    }
    catch (const std::exception& e) {
        std::cout << "Error: " << e.what() << std::endl;
    } 
    return 1;
}
