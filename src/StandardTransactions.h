////////////////////////////////////////////////////////////////////////////////
//
// StandardTransactions.h
//
// Copyright (c) 2011-2012 Eric Lombrozo
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

#ifndef STANDARD_TRANSACTIONS_H__
#define STANDARD_TRANSACTIONS_H__

#include "CoinNodeData.h"
#include "Base58Check.h"
#include "hash.h"

#include <sstream>

const unsigned char BITCOIN_ADDRESS_VERSIONS[] = {0x00, 0x05};

using namespace Coin;

class StandardTxOut : public TxOut
{
public:
    StandardTxOut() { }

    void payToAddress(const std::string& address, uint64_t value, const unsigned char addressVersions[] = BITCOIN_ADDRESS_VERSIONS);
};

void StandardTxOut::payToAddress(const std::string& address, uint64_t value, const unsigned char addressVersions[])
{
    uchar_vector pubKeyHash;
    uint version;
    if (!fromBase58Check(address, pubKeyHash, version))
        throw std::runtime_error("Invalid address checksum.");

    if (version == addressVersions[0]) {
        // pay-to-address
        this->scriptPubKey = uchar_vector("76a914") + pubKeyHash + uchar_vector("88ac");
    }
    else if (version == addressVersions[1]) {
        // pay-to-script-hash
        this->scriptPubKey = uchar_vector("a914") + pubKeyHash + uchar_vector("87");
    }
    else {
        throw std::runtime_error("Invalid address version.");
    }

    if (pubKeyHash.size() != 20) {
        throw std::runtime_error("Invalid hash length.");
    }

    this->value = value;
}

class P2SHTxIn : public TxIn
{
private:
    uchar_vector redeemScript;
    std::vector<uchar_vector> sigs;

public:
    P2SHTxIn() { }
    P2SHTxIn(const uchar_vector& _redeemScript) :
        redeemScript(_redeemScript) { }

    void setRedeemScript(const uchar_vector& redeemScript) { this->redeemScript = redeemScript; }
    const uchar_vector& getRedeemScript() const { return this->redeemScript; }

    void clearSigs() { sigs.clear(); }
    void addSig(const uchar_vector& sig) { sigs.push_back(sig); }

    void setScriptSig();
};

void P2SHTxIn::setScriptSig()
{
}

class MultiSigRedeemScript
{
private:
    uint minSigs;
    std::vector<uchar_vector> pubKeys;

    const unsigned char* addressVersions;
    const char* base58chars;

    mutable uchar_vector redeemScript;
    mutable bool bUpdated;

public:
    MultiSigRedeemScript(uint minSigs = 1,
                         const unsigned char* _addressVersions = BITCOIN_ADDRESS_VERSIONS,
                         const char* _base58chars = BITCOIN_BASE58_CHARS) :
        addressVersions(_addressVersions), base58chars(_base58chars), bUpdated(false) { this->setMinKeys(minSigs); }

    void setMinKeys(uint minSigs);
    uint getMinKeys() const { return minSigs; }

    void setAddressTypes(const unsigned char* addressVersions, const char* base58chars = BITCOIN_BASE58_CHARS)
    {
        this->addressVersions = addressVersions;
        this->base58chars = base58chars;
    }

    void clearPubKeys() { pubKeys.clear(); this->bUpdated = false; }
    void addPubKey(const uchar_vector& pubKey);
    uint getPubKeyCount() const { return pubKeys.size(); }
    std::vector<uchar_vector> getPubKeys() const { return pubKeys; }

    void parseRedeemScript(const uchar_vector& redeemScript);
    uchar_vector getRedeemScript() const;
    std::string getAddress() const;

    std::string toJson(bool bShowPubKeys = false) const;
};

void MultiSigRedeemScript::setMinKeys(uint minSigs)
{
    if (minSigs < 1) {
        throw std::runtime_error("At least one signature is required.");
    }

    if (minSigs > 16) {
        throw std::runtime_error("At most 16 signatures are allowed.");
    }

    this->minSigs = minSigs;
    this->bUpdated = false;
}

void MultiSigRedeemScript::addPubKey(const uchar_vector& pubKey)
{
    if (pubKeys.size() >= 16) {
        throw std::runtime_error("Public key maximum of 16 already reached.");
    }

    if (pubKey.size() > 75) {
        throw std::runtime_error("Public keys can be a maximum of 75 bytes.");
    }

    pubKeys.push_back(pubKey);
    bUpdated = false;
}

void MultiSigRedeemScript::parseRedeemScript(const uchar_vector& redeemScript)
{
    if (redeemScript.size() < 3) {
        throw std::runtime_error("Redeem script is too short.");
    }

    // OP_1 is 0x51, OP_16 is 0x60
    unsigned char mSigs = redeemScript[0];
    if (mSigs < 0x51 || mSigs > 0x60) {
        throw std::runtime_error("Invalid signature minimum.");
    }

    unsigned char nKeys = 0x50;
    uint i = 1;
    std::vector<uchar_vector> _pubKeys;
    while (true) {
        unsigned char byte = redeemScript[i++];
        if (i >= redeemScript.size()) {
            throw std::runtime_error("Script terminates prematurely.");
        }
        if ((byte >= 0x51) && (byte <= 0x60)) {
            // interpret byte as the signature counter.
            if (byte != nKeys) {
                throw std::runtime_error("Invalid signature count.");
            }
            if (nKeys < mSigs) {
                throw std::runtime_error("The required signature minimum exceeds the number of keys.");
            }
            if (redeemScript[i++] != 0xae || i > redeemScript.size()) {
                throw std::runtime_error("Invalid script termination.");
            }
            break;
        }
        // interpret byte as the pub key size
        if ((byte > 0x4b) || (i + byte > redeemScript.size())) {
            std::stringstream ss;
            ss << "Invalid OP at byte " << i - 1 << ".";
            throw std::runtime_error(ss.str());
        }
        nKeys++;
        if (nKeys > 0x60) {
            throw std::runtime_error("Public key maximum of 16 exceeded.");
        }
        _pubKeys.push_back(uchar_vector(redeemScript.begin() + i, redeemScript.begin() + i + byte));
        i += byte;
    }

    minSigs = mSigs - 0x50;
    pubKeys = _pubKeys;
}

uchar_vector MultiSigRedeemScript::getRedeemScript() const
{
    if (!bUpdated) {
        uint nKeys = pubKeys.size();

        if (minSigs > nKeys) {
            throw std::runtime_error("Insufficient public keys.");
        }

        redeemScript.clear();
        redeemScript.push_back((unsigned char)(minSigs + 0x50));
        for (uint i = 0; i < nKeys; i++) {
            redeemScript.push_back(pubKeys[i].size());
            redeemScript += pubKeys[i];
        }
        redeemScript.push_back((unsigned char)(nKeys + 0x50));
        redeemScript.push_back(0xae); // OP_CHECKMULTISIG
        bUpdated = true;
    }

    return redeemScript;
}

std::string MultiSigRedeemScript::getAddress() const
{
    uchar_vector scriptHash = ripemd160(sha256(getRedeemScript()));
    return toBase58Check(scriptHash, addressVersions[1], base58chars);
}

std::string MultiSigRedeemScript::toJson(bool bShowPubKeys) const
{
    uint nKeys = pubKeys.size();
    std::stringstream ss;
    ss <<   "{\n    \"m\" : " << minSigs
       <<   ",\n    \"n\" : " << nKeys
       <<   ",\n    \"address\" : \"" << getAddress()
       << "\",\n    \"redeemScript\" : \"" << getRedeemScript().getHex() << "\"";
    if (bShowPubKeys) {
        ss << ",\n    \"pubKeys\" :\n    [";
        for (uint i = 0; i < nKeys; i++) {
            uchar_vector pubKeyHash = ripemd160(sha256(pubKeys[i]));
            std::string address = toBase58Check(pubKeyHash, addressVersions[0], base58chars);
            if (i > 0) ss << ",";
            ss <<    "\n        {"
               <<    "\n            \"address\" : \"" << address
               << "\",\n            \"pubKey\" : \"" << pubKeys[i].getHex()
               <<  "\"\n        }";
        }
        ss << "\n    ]";
    }
    ss << "\n}";
    return ss.str();
}

#endif // STANDARD_TRANSACTIONS_H__
