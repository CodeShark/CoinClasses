////////////////////////////////////////////////////////////////////////////////
//
// hdwallet.h
//
// Copyright (c) 2013 Eric Lombrozo
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
// Some portions taken from bitcoin/bitcoin,
//      Copyright (c) 2009-2013 Satoshi Nakamoto, the Bitcoin developers

#ifndef __HDWALLET_H_
#define __HDWALLET_H_

#include "hash.h"
#include "Base58Check.h"
#include "secp256k1.h"

namespace Coin {

typedef std::vector<unsigned char> bytes_t;

const uchar_vector BITCOIN_SEED("426974636f696e2073656564"); // key = "Bitcoin seed"

class HDWallet
{
public:
    HDWallet(const bytes_t& seed);

    const bytes_t& getSeed() const { return seed_; }
    const bytes_t& getMasterKey() const { return master_key_; }
    const bytes_t& getMasterChainCode() const { return master_chain_code_; }

private:
    bytes_t seed_;
    bytes_t master_key_;
    bytes_t master_chain_code_;
};

inline HDWallet::HDWallet(const bytes_t& seed)
{
    bytes_t hmac = hmac_sha512(BITCOIN_SEED, seed);
    master_key_.assign(hmac.begin(), hmac.begin() + 32);
    master_chain_code_.assign(hmac.begin() + 32, hmac.end());
}

}

#endif // __HDWALLET_H_1
