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

#include <sstream>
#include <stdexcept>

#include "typedefs.h"

namespace Coin {

const uchar_vector CURVE_MODULUS_BYTES("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
const BigInt CURVE_MODULUS(CURVE_MODULUS_BYTES);

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
    HDKeychain() { }
    HDKeychain(unsigned char depth, uint32_t parent_fp, uint32_t child_num, const bytes_t& chain_code, const bytes_t& key);
    HDKeychain(const bytes_t& extkey);

    explicit HDKeychain(const HDKeychain& source, bool make_public = false);

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

    void getPublic(HDKeychain& pub) const;
    bool getChild(HDKeychain& child, uint32_t i) const;

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

    void setPubkey() {
        if (isPrivate()) {
            secp256k1_key curvekey;
            curvekey.setPrivKey(bytes_t(key_.begin() + 1, key_.end()));
            pubkey_ = curvekey.getPubKey();
        }
        else {
            pubkey_ = key_;
        }
    }
};


inline HDKeychain::HDKeychain(unsigned char depth, uint32_t parent_fp, uint32_t child_num, const bytes_t& chain_code, const bytes_t& key)
    : depth_(depth), parent_fp_(parent_fp), child_num_(child_num), chain_code_(chain_code), key_(key)
{
    if (chain_code_.size() != 32) {
        throw std::runtime_error("Invalid chain code.");
    }

    // TODO: make sure key < prime modulus of secp256k1 field
    if (key_.size() == 32) {
        uchar_vector privkey;
        privkey.push_back(0x00);
        privkey += key_;
        key_ = privkey;
    }
    else if (key_.size() != 33) {
        throw std::runtime_error("Invalid key.");
    }

    version_ = isPrivate() ? priv_version_ : pub_version_;
    setPubkey();
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

    setPubkey();
}

inline HDKeychain::HDKeychain(const HDKeychain& source, bool make_public)
{
    depth_ = source.depth_;
    parent_fp_ = source.parent_fp_;
    child_num_ = source.child_num_;
    chain_code_ = source.chain_code_;

    if (make_public || !source.isPrivate()) {
        version_ = pub_version_;
        key_ = source.pubkey_;
    }
    else {
        version_ = priv_version_;
        key_ = source.key_;
    }
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

inline bytes_t HDKeychain::hash() const
{
    return ripemd160(sha256(pubkey_));
}

inline uint32_t HDKeychain::fp() const
{
    bytes_t hash = this->hash();
    return (uint32_t)hash[0] << 24 | (uint32_t)hash[1] << 16 | (uint32_t)hash[2] << 8 | (uint32_t)hash[3];
}

inline void HDKeychain::getPublic(HDKeychain& pub) const
{
    pub.version_ = pub_version_;
    pub.depth_ = depth_;
    pub.parent_fp_ = parent_fp_;
    pub.child_num_ = child_num_;
    pub.chain_code_ = chain_code_;
    pub.key_ = pubkey_;
}

inline bool HDKeychain::getChild(HDKeychain& child, uint32_t i) const
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

    if (isPrivate()) {
        BigInt k(key_);
        k += Il;
        k %= CURVE_MODULUS;
        if (k.isZero()) return false;
        uchar_vector child_key;
        child_key.push_back(0x00);
        child_key += k.getBytes(); 
        child.key_ = child_key;
    }
    else {
        secp256k1_point K;
std::cout << "secp256k1_point K;" << std::endl; 
        K.bytes(key_);
std::cout << "K.bytes(key_);" << std::endl;
        K.generator_mul(left32);
std::cout << "K.generator_mul(left32);" << std::endl;
        if (K.is_at_infinity()) return false;
        child.key_ = K.bytes();
    }

    child.version_ = version_; 
    child.depth_ = depth_ + 1;
    child.parent_fp_ = fp();
    child.child_num_ = i;
    child.chain_code_.assign(digest.begin() + 32, digest.end());

    return true;
}

inline std::string HDKeychain::toString() const
{
    std::stringstream ss;
    ss << "version: " << std::hex << version_ << std::endl
       << "depth: " << depth() << std::endl
       << "parent_fp: " << parent_fp_ << std::endl
       << "child_num: " << child_num_ << std::endl
       << "chain_code: " << uchar_vector(chain_code_).getHex() << std::endl
       << "key: " << uchar_vector(key_).getHex() << std::endl
       << "hash: " << uchar_vector(this->hash()).getHex() << std::endl;
    return ss.str();
}

uint32_t HDKeychain::priv_version_ = 0;
uint32_t HDKeychain::pub_version_ = 0;

}

#endif // __HDWALLET_H_1
