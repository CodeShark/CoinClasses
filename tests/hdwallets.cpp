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
    std::cout << "extkey: " << toBase58Check(keychain.extkey()) << std::endl;
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


        HDKeychain priv_m(0, 0, 0, c, k);
        HDKeychain pub_m = priv_m.getPublic();
        if (!pub_m) cout << "pub_m is not valid" << endl;
        cout << "[Chain m]" << endl;
        show(pub_m);
        show(priv_m);
        cout << "-----------------------------------" << endl;

        HDKeychain priv_m0 = priv_m.getChild(0x00000000);
        HDKeychain pub_m0 = priv_m0.getPublic();
        if (!pub_m0) cout << "pub_m0 is not valid" << endl;
        HDKeychain pub_m0_ = pub_m.getChild(0x00000000);
        cout << "[Chain m/0']" << endl;
        show(pub_m0);
        show(pub_m0_);
        show(priv_m0);
        cout << "-----------------------------------" << endl;

        HDKeychain priv_m01p = priv_m0.getChild(0x80000001);
        HDKeychain pub_m01p = priv_m01p.getPublic();
        cout << "[Chain m/0'/1]" << endl;
        show(pub_m01p);
        show(priv_m01p);
        return 0;
    }
    catch (const std::exception& e) {
        std::cout << "Error: " << e.what() << std::endl;
    } 
    return 1;
}

/*
Master (hex): 000102030405060708090a0b0c0d0e0f
 * [Chain m]
   * ext pub: xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8
   * ext prv: xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi
 * [Chain m/0']
   * ext pub: xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw
   * ext prv: xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7
 * [Chain m/0'/1]
   * ext pub: xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ
   * ext prv: xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs
 * [Chain m/0'/1/2']
   * ext pub: xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5
   * ext prv: xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM
 * [Chain m/0'/1/2'/2]
   * ext pub: xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV
   * ext prv: xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334
 * [Chain m/0'/1/2'/2/1000000000]
   * ext pub: xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy
   * ext prv: xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76
*/
