////////////////////////////////////////////////////////////////////////////////
//
// hdkeys.cpp
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

#include "hdkeys.h"

#include "hash.h"
#include "secp256k1.h"
#include "BigInt.h"
#include "uchar_vector.h"

#include <sstream>
#include <stdexcept>

#include "typedefs.h"

using namespace Coin;

const uchar_vector CURVE_ORDER_BYTES("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
const BigInt CURVE_ORDER(CURVE_ORDER_BYTES);


HDKeychain::HDKeychain(const bytes_t& key, const bytes_t& chain_code, uint32_t child_num, uint32_t parent_fp, uint32_t depth)
    : depth_(depth), parent_fp_(parent_fp), child_num_(child_num), chain_code_(chain_code), key_(key)
{
    if (chain_code_.size() != 32) {
        throw std::runtime_error("Invalid chain code.");
    }

   if (key_.size() == 32) {
        BigInt n(key_);
        if (n >= CURVE_ORDER || n.isZero()) {
            throw std::runtime_error("Invalid key.");
        }

        uchar_vector privkey;
        privkey.push_back(0x00);
        privkey += key_;
        key_ = privkey;
    }
    else if (key_.size() != 33) {
        throw std::runtime_error("Invalid key.");
    }

    version_ = isPrivate() ? priv_version_ : pub_version_;
    updatePubkey();

    valid_ = true;
}

HDKeychain::HDKeychain(const bytes_t& extkey)
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

    updatePubkey();

    valid_ = true;
}

HDKeychain::HDKeychain(HDKeychain&& source)
{
    valid_ = source.valid_;
    if (!valid_) return;

    version_ = source.version_;
    depth_ = source.depth_;
    parent_fp_ = source.parent_fp_;
    child_num_ = source.child_num_;
    chain_code_ = source.chain_code_;
    key_ = source.key_;
    updatePubkey();
}

HDKeychain& HDKeychain::operator=(const HDKeychain& rhs)
{
    valid_ = rhs.valid_;
    if (valid_) {
        version_ = rhs.version_;
        depth_ = rhs.depth_;
        parent_fp_ = rhs.parent_fp_;
        child_num_ = rhs.child_num_;
        chain_code_ = rhs.chain_code_;
        key_ = rhs.key_;
        updatePubkey();
    }
    return *this;
}

bool HDKeychain::operator==(const HDKeychain& rhs) const
{
    return (valid_ && rhs.valid_ &&
            version_ == rhs.version_ &&
            depth_ == rhs.depth_ &&
            parent_fp_ == rhs.parent_fp_ &&
            child_num_ == rhs.child_num_ &&
            chain_code_ == rhs.chain_code_ &&
            key_ == rhs.key_);
}

bool HDKeychain::operator!=(const HDKeychain& rhs) const
{
    return !(*this == rhs);
}

bytes_t HDKeychain::extkey() const
{
    uchar_vector extkey;

    extkey.push_back((uint32_t)version_ >> 24);
    extkey.push_back(((uint32_t)version_ >> 16) & 0xff);
    extkey.push_back(((uint32_t)version_ >> 8) & 0xff);
    extkey.push_back((uint32_t)version_ & 0xff);

    extkey.push_back(depth_);

    extkey.push_back((uint32_t)parent_fp_ >> 24);
    extkey.push_back(((uint32_t)parent_fp_ >> 16) & 0xff);
    extkey.push_back(((uint32_t)parent_fp_ >> 8) & 0xff);
    extkey.push_back((uint32_t)parent_fp_ & 0xff);

    extkey.push_back((uint32_t)child_num_ >> 24);
    extkey.push_back(((uint32_t)child_num_ >> 16) & 0xff);
    extkey.push_back(((uint32_t)child_num_ >> 8) & 0xff);
    extkey.push_back((uint32_t)child_num_ & 0xff);

    extkey += chain_code_;
    extkey += key_;

    return extkey;
}

bytes_t HDKeychain::hash() const
{
    return ripemd160(sha256(pubkey_));
}

uint32_t HDKeychain::fp() const
{
    bytes_t hash = this->hash();
    return (uint32_t)hash[0] << 24 | (uint32_t)hash[1] << 16 | (uint32_t)hash[2] << 8 | (uint32_t)hash[3];
}

HDKeychain HDKeychain::getPublic() const
{
    if (!valid_) {
        throw std::runtime_error("Keychain is invalid.");
    }

    HDKeychain pub;
    pub.valid_ = valid_;
    pub.version_ = pub_version_;
    pub.depth_ = depth_;
    pub.parent_fp_ = parent_fp_;
    pub.child_num_ = child_num_;
    pub.chain_code_ = chain_code_;
    pub.key_ = pub.pubkey_ = pubkey_;
    return pub;
}

HDKeychain HDKeychain::getChild(uint32_t i) const
{
    if (!valid_) {
        throw std::runtime_error("Keychain is invalid.");
    }

    bool priv_derivation = 0x80000000 & i;
    if (!isPrivate() && priv_derivation) {
        throw std::runtime_error("Cannot do private key derivation on public key.");
    }

    HDKeychain child;
    child.valid_ = false;

    uchar_vector data;
    data += priv_derivation ? key_ : pubkey_;
    data.push_back(i >> 24);
    data.push_back((i >> 16) & 0xff);
    data.push_back((i >> 8) & 0xff);
    data.push_back(i & 0xff);

    bytes_t digest = hmac_sha512(chain_code_, data);
    bytes_t left32(digest.begin(), digest.begin() + 32);
    BigInt Il(left32);
    if (Il >= CURVE_ORDER) return child;

    if (isPrivate()) {
        BigInt k(key_);
        k += Il;
        k %= CURVE_ORDER;
        if (k.isZero()) return child;

        bytes_t child_key = k.getBytes();
        // pad with 0's to make it 33 bytes
        uchar_vector padded_key(33 - child_key.size(), 0);
        padded_key += child_key;
        child.key_ = padded_key;
        child.updatePubkey();
    }
    else {
        secp256k1_point K;
        K.bytes(pubkey_);
        K.generator_mul(left32);
        if (K.is_at_infinity()) return child;

        child.key_ = child.pubkey_ = K.bytes();
    }

    child.version_ = version_; 
    child.depth_ = depth_ + 1;
    child.parent_fp_ = fp();
    child.child_num_ = i;
    child.chain_code_.assign(digest.begin() + 32, digest.end());

    child.valid_ = true;
    return child;
}

std::string HDKeychain::toString() const
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

void HDKeychain::updatePubkey() {
    if (isPrivate()) {
        secp256k1_key curvekey;
        curvekey.setPrivKey(bytes_t(key_.begin() + 1, key_.end()));
        pubkey_ = curvekey.getPubKey();
    }
    else {
        pubkey_ = key_;
    }
}

uint32_t HDKeychain::priv_version_ = 0;
uint32_t HDKeychain::pub_version_ = 0;
