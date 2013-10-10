////////////////////////////////////////////////////////////////////////////////
//
// hdkeys.h
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

#ifndef COIN_HDKEYS_H
#define COIN_HDKEYS_H

#include "hash.h"

#include "typedefs.h"

namespace Coin {

const uchar_vector BITCOIN_SEED("426974636f696e2073656564"); // key = "Bitcoin seed"

class HDSeed
{
public:
    HDSeed(const bytes_t& seed)
    {
        bytes_t hmac = hmac_sha512(BITCOIN_SEED, seed);
        master_key_.assign(hmac.begin(), hmac.begin() + 32);
        master_chain_code_.assign(hmac.begin() + 32, hmac.end());
    }

    const bytes_t& getSeed() const { return seed_; }
    const bytes_t& getMasterKey() const { return master_key_; }
    const bytes_t& getMasterChainCode() const { return master_chain_code_; }

private:
    bytes_t seed_;
    bytes_t master_key_;
    bytes_t master_chain_code_;
};


class HDKeychain
{
public:
    HDKeychain() { }
    HDKeychain(const bytes_t& key, const bytes_t& chain_code, uint32_t child_num = 0, uint32_t parent_fp = 0, uint32_t depth = 0);
    HDKeychain(const bytes_t& extkey);

    HDKeychain(HDKeychain&& source);

    HDKeychain& operator=(const HDKeychain& rhs);    

    explicit operator bool() { return valid_; }

    bytes_t extkey() const;

    uint32_t version() const { return version_; }
    int depth() const { return depth_; }
    uint32_t parent_fp() const { return parent_fp_; }
    uint32_t child_num() const { return child_num_; }
    const bytes_t& chain_code() const { return chain_code_; }
    const bytes_t& key() const { return key_; }

    const bytes_t& pubkey() const { return pubkey_; }

    bool isPrivate() const { return ( key_.size() == 33 && key_[0] == 0x00); }
    bytes_t hash() const; // hash is ripemd160(sha256(pubkey))
    uint32_t fp() const; // fingerprint is first 32 bits of hash

    HDKeychain getPublic() const;
    HDKeychain getChild(uint32_t i) const;

    static void setVersions(uint32_t priv_version, uint32_t pub_version) { priv_version_ = priv_version; pub_version_ = pub_version; }

    std::string toString() const;

private:
    static uint32_t priv_version_;
    static uint32_t pub_version_; 

    uint32_t version_;
    unsigned char depth_;
    uint32_t parent_fp_;
    uint32_t child_num_;
    bytes_t chain_code_; // 32 bytes
    bytes_t key_;        // 33 bytes, first byte is 0x00 for private key

    bytes_t pubkey_;

    bool valid_;

    void updatePubkey();
};

}

#endif // COIN_HDKEYS_H
