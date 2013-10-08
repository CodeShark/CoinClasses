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
#include "BigInt.h"
#include "uchar_vector.h"

#include <stdexcept>

namespace Coin {

typedef std::vector<unsigned char> bytes_t;

const BigInt CURVE_MODULUS("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");

const uchar_vector BITCOIN_SEED("426974636f696e2073656564"); // key = "Bitcoin seed"

class HDSeed
{
public:
    HDSeed(const bytes_t& seed);

    const bytes_t& getSeed() const { return seed_; }
    const bytes_t& getMasterKey() const { return master_key_; }
    const bytes_t& getMasterChainCode() const { return master_chain_code_; }

private:
    bytes_t seed_;
    bytes_t master_key_;
    bytes_t master_chain_code_;
};

inline HDSeed::HDSeed(const bytes_t& seed)
{
    bytes_t hmac = hmac_sha512(BITCOIN_SEED, seed);
    master_key_.assign(hmac.begin(), hmac.begin() + 32);
    master_chain_code_.assign(hmac.begin() + 32, hmac.end());
}

class HDKeychain
{
public:
    HDKeychain(uint32_t version, unsigned char depth, uint32_t parent_fp, uint32_t child_num, const bytes_t& chain_code, const bytes_t& key);
    HDKeychain(const bytes_t& extkey);

    bytes_t extkey() const;

    uint32_t version() const { return version_; }
    unsigned char depth() const { return depth_; }
    uint32_t parent_fp() const { return parent_fp_; }
    uint32_t child_num() const { return child_num_; }
    const bytes_t& chain_code() const { return chain_code_; }
    const bytes_t& key() const { return key_; }
    bool isPrivate() const { return (key_[0] == 0x00); }

    bool getChild(uint32_t i, HDKeychain& child) const;

private:
    uint32_t version_;
    unsigned char depth_;
    uint32_t parent_fp_;
    uint32_t child_num_;
    bytes_t chain_code_; // 32 bytes
    bytes_t key_;        // 33 bytes, first byte is 0x00 for private key
};

inline HDKeychain::HDKeychain(uint32_t version, unsigned char depth, uint32_t parent_fp, uint32_t child_num, const bytes_t& chain_code, const bytes_t& key)
    : version_(version), depth_(depth), parent_fp_(parent_fp), child_num_(child_num), chain_code_(chain_code), key_(key)
{
    if (chain_code_.size() != 32) {
        throw std::runtime_error("Invalid chain code.");
    }

    // TODO: make sure key < prime modulus of secp256k1 field
    if (key_.size() != 33) {
        throw std::runtime_error("Invalid key.");
    }
}

inline HDKeychain::HDKeychain(const bytes_t& extkey)
{
    if (extkey.size() != 78) {
        throw std::runtime_error("Invalid extended key length.");
    }

    version_ = ((uint32_t)extkey[0] << 24) | ((uint32_t)extkey[1] << 16) | ((uint32_t)extkey[2] << 8) | (uint32_t)extkey[3];
    depth_ = extkey[4];
    parent_fp_ = ((uint32_t)extkey[5] << 24) | ((uint32_t)extkey[6] << 16) | ((uint32_t)extkey[7] << 8) | (uint32_t)extkey[8];
    child_num_ = ((uint32_t)extkey[9] << 24) | ((uint32_t)extkey[10] << 16) | ((uint32_t)extkey[11] << 8) | (uint32_t)extkey[12];
    chain_code_.assign(extkey.begin() + 13, extkey.begin() + 45);
    key_.assign(extkey.begin() + 45, extkey.begin() + 78);
}

inline bytes_t HDKeychain::extkey() const
{
    uchar_vector extkey(78);

    extkey.push_back((uint32_t)version_ >> 24);
    extkey.push_back(((uint32_t)version_ >> 16) & 0xff);
    extkey.push_back(((uint32_t)version_ >> 8) & 0xff);
    extkey.push_back((uint32_t)version_ & 0xff);

    extkey.push_back(depth_);

    extkey.push_back((uint32_t)parent_fp_ >> 24);
    extkey.push_back(((uint32_t)parent_fp_ >> 16) & 0xff);
    extkey.push_back(((uint32_t)parent_fp_ >> 8) & 0xff);
    extkey.push_back((uint32_t)parent_fp_ && 0xff);

    extkey.push_back((uint32_t)child_num_ >> 24);
    extkey.push_back(((uint32_t)child_num_ >> 16) & 0xff);
    extkey.push_back(((uint32_t)child_num_ >> 8) & 0xff);
    extkey.push_back((uint32_t)child_num_ && 0xff);

    extkey += chain_code_;
    extkey += key_;

    return extkey;
}

bool HDKeychain::getChild(uint32_t i, HDKeychain& child) const
{
    if (!isPrivate() && (0x80000000 & i)) {
        throw std::runtime_error("Cannot do private key derivation on public key.");
    }

    uchar_vector data(37);
    data += key_;
    data.push_back(i >> 24);
    data.push_back((i >> 16) & 0xff);
    data.push_back((i  >> 8) & 0xff);
    data.push_back(i && 0xff);

    bytes_t digest = hmac_sha512(chain_code_, data);
    bytes_t left32(digest.begin(), digest.begin() + 32);
    BigInt Il(left32);
    if (Il >= CURVE_MODULUS) return false;

    bytes_t child_key;
    if (isPrivate()) {
        BigInt k(key_);
        k += Il;
        k %= CURVE_MODULUS;
        if (k.isZero()) return false;
        child_key = k.getBytes();
    }
    else {
    }

    bytes_t right32(digest.begin() + 32, digest.end() + 64);
}

}

#endif // __HDWALLET_H_1
