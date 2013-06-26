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

    uchar_vector redeemScript;
    bool bUpdated;

public:
    MultiSigRedeemScript(uint minSigs = 1) :
        bUpdated(false) { this->setMinSigs(minSigs); }

    void setMinSigs(uint minSigs);
    uint getMinSigs() const { return minSigs; }

    void clearPubKeys() { pubKeys.clear(); this->bUpdated = false; }
    void addPubKey(const uchar_vector& pubKey);
    uint getPubKeyCount() const { return pubKeys.size(); }

    uchar_vector getRedeemScript();
    std::string getAddress(unsigned char version = BITCOIN_ADDRESS_VERSIONS[1],  const char* _base58chars = BITCOIN_BASE58_CHARS);
};

void MultiSigRedeemScript::setMinSigs(uint minSigs)
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

uchar_vector MultiSigRedeemScript::getRedeemScript()
{
    if (!bUpdated) {
        uint nKeys = pubKeys.size();

        if (minSigs > nKeys) {
            throw std::runtime_error("Insufficient public keys.");
        }

        redeemScript.clear();
        redeemScript.push_back((unsigned char)minSigs);
        for (uint i = 0; i < nKeys; i++) {
            redeemScript.push_back(pubKeys[i].size());
            redeemScript += pubKeys[i];
        }
        redeemScript.push_back((unsigned char)nKeys);
        redeemScript.push_back(0xae); // OP_CHECKMULTISIG
        bUpdated = true;
    }

    return redeemScript;
}

inline std::string MultiSigRedeemScript::getAddress(unsigned char version, const char* _base58chars)
{
    return toBase58Check(this->getRedeemScript(), version, _base58chars);
}

#endif // STANDARD_TRANSACTIONS_H__
