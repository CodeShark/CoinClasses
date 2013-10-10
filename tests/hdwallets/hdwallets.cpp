#include <iostream>
#include <cassert>

#include <hdkeys.h>
#include <Base58Check.h>

#include <sstream>

using namespace Coin;
using namespace std;

#define P(i)        0x80000000 | i
#define IS_P(i)     0x80000000 & i

string S(uint32_t i)
{
    stringstream ss;
    ss << (0x7fffffff & i);
    if (IS_P(i)) { ss << "'"; }
    return ss.str();
}

/*
const uchar_vector SEED("000102030405060708090a0b0c0d0e0f");
const uint32_t CHAIN[] = { P(0), 1, P(2), 2, 1000000000 };
*/

const uchar_vector SEED("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542");
const uint32_t CHAIN[] = { 0, P(2147483647), 1, P(2147483646), 2 };

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

        // Create master keychain
        HDKeychain prv(k, c);
        HDKeychain pub = prv.getPublic();
        showStep(chainname.str(), pub, prv);

        HDKeychain parentpub;

        for (unsigned int k = 0; k < CHAIN_LENGTH; k++) {
            // Append subtree label to name
            chainname << "/" << S(CHAIN[k]);

            if (!IS_P(CHAIN[k]))
                parentpub = pub;

            prv = prv.getChild(CHAIN[k]);
            assert(prv);

            pub = prv.getPublic();
            assert(pub);

            // We need to make sure child of pub = pub of child for public derivation 
            if (!IS_P(CHAIN[k]))
                assert(pub.extkey() == parentpub.getChild(CHAIN[k]).extkey());

            showStep(chainname.str(), pub, prv);
        }

        return 0;
    }
    catch (const std::exception& e) {
        std::cout << "Error: " << e.what() << std::endl;
    } 
    return 1;
}
