///////////////////////////////////////////////////////////////////////////////
//
// txbuilder.cpp
//
// Copyright (c) 2011-2013 Eric Lombrozo
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

#include <StandardTransactions.h>
#include <CoinKey.h>
#include <numericdata.h>

#include <map>
#include <iostream>

using namespace Coin;

typedef std::vector<std::string>        params_t;
typedef std::string                     (*fAction)(bool, params_t&);
typedef std::map<std::string, fAction>  command_map_t;

// Maps typed-in function names to function addresses
command_map_t command_map;

////////////////////////////////////
//
// Command Functions
//
std::string help(bool bHelp, params_t& params)
{
    if (bHelp || params.size() > 0) {
        return "help - displays help information.";        
    }

    std::string result = "\n";
    command_map_t::iterator it = command_map.begin();
    for (; it != command_map.end(); ++it) {
        result += it->second(true, params) + "\n";
    }
    return result;
}

std::string createmultisig(bool bHelp, params_t& params)
{
    if (bHelp || params.size() < 2) {
        return "createmultisig <nrequired> <key 1> [<key 2> <key 3> ...] - creates a multisignature address.";
    }

    MultiSigRedeemScript multiSig(strtoul(params[0].c_str(), NULL, 10));
    int nKeys = params.size();
    for (int i = 1; i < nKeys; i++) {
        multiSig.addPubKey(params[i]);
    }
    return multiSig.toJson();
}

std::string parsemultisigredeemscript(bool bHelp, params_t& params)
{
    if (bHelp || params.size() != 1) {
        return "parsemultisigredeemscript <redeemScript> - parses a multisignature redeem script.";
    }

    MultiSigRedeemScript multiSig;
    multiSig.parseRedeemScript(params[0]);
    return multiSig.toJson(true);
}

std::string standardtxout(bool bHelp, params_t& params)
{
    if (bHelp || params.size() < 2 || params.size() > 3) {
        return "standardtxout <address> <value> [options] - creates a standard transaction output. Use option -h for serialized hex.";
    }

    bool bHex = false;
    if (params.size() == 3) {
        if (params[2] == "-h") {
            bHex = true;
        }
        else {
            throw std::runtime_error(std::string("Invalid option: ") + params[2]);
        }
    }

    StandardTxOut txOut;
    txOut.set(params[0], strtoull(params[1].c_str(), NULL, 10));

    if (bHex) {
        return txOut.getSerialized().getHex();
    }
    else {
        return txOut.toJson();
    }
}

std::string addoutput(bool bHelp, params_t& params)
{
    if (bHelp || params.size() != 3) {
        return "addoutput <txhex> <address> <value> - add a standard output to a transaction. Pass empty string as txhex to create a new transaction.";
    }

    Transaction tx;
    if (params[0] != "") {
        tx.setSerialized(uchar_vector(params[0]));
    }

    StandardTxOut txOut;
    txOut.set(params[1], strtoull(params[2].c_str(), NULL, 10));

    tx.addOutput(txOut);
    return tx.getSerialized().getHex();
}

// TODO : Make function detect input type automatically.
std::string addp2addressinput(bool bHelp, params_t& params)
{
    if (bHelp || params.size() < 4 || params.size() > 5) {
        return "addp2addressinput <txhex> <outhash> <outindex> <pubkey> [signature] - adds a standard pay-to-address input to a transaction with an optional signature. Pass empty string as txhex to create a new transaction.";
    }

    Transaction tx;
    if (params[0] != "") {
        tx.setSerialized(uchar_vector(params[0]));
    }

    P2AddressTxIn txIn(uchar_vector(params[1]), strtoul(params[2].c_str(), NULL, 10), params[3]);
    if (params.size() == 5) {
        txIn.addSig(uchar_vector(params[3]), uchar_vector(params[4]));
    }
    txIn.setScriptSig(SCRIPT_SIG_EDIT);

    tx.addInput(txIn);
    return tx.getSerialized().getHex();
}

std::string createtransaction(bool bHelp, params_t& params)
{
    if (bHelp || params.size() != 5) {
        return "createtransaction <outhash> <outindex> <redeemscript> <toaddress> <value> - creates a transaction claiming a multisignature input.";
    }

    uchar_vector outHash = params[0];
    uint outIndex = strtoul(params[1].c_str(), NULL, 10);
    uchar_vector redeemScript = params[2];
    std::string toAddress = params[3];
    uint64_t value = strtoull(params[4].c_str(), NULL, 10);

    StandardTxOut txOut;
    txOut.set(toAddress, value);

    MultiSigRedeemScript multiSig;
    multiSig.parseRedeemScript(redeemScript);

    P2SHTxIn txIn(outHash, outIndex, multiSig.getRedeemScript());
    txIn.setScriptSig(SCRIPT_SIG_SIGN);

    Transaction tx;
    tx.addOutput(txOut);
    tx.addInput(txIn);
    uchar_vector hashToSign = tx.getHashWithAppendedCode(1); // SIGHASH_ALL

    for (uint i = 0; i < multiSig.getPubKeyCount(); i++) {
        txIn.addSig(uchar_vector(), uchar_vector(), SIGHASH_ALREADYADDED);
    }

    txIn.setScriptSig(SCRIPT_SIG_EDIT);
    tx.clearInputs();
    tx.addInput(txIn);
    return tx.getSerialized().getHex();
}

std::string signtransaction(bool bHelp, params_t& params)
{
    if (bHelp || params.size() < 6) {
        return "signtransaction <outhash> <outindex> <redeemscript> <toaddress> <value> <privkey1> [<privkey2> <privkey3> ...] - creates and signs a transaction claiming a multisignature input.";
    }

    uchar_vector outHash = params[0];
    uint outIndex = strtoul(params[1].c_str(), NULL, 10);
    uchar_vector redeemScript = params[2];
    std::string toAddress = params[3];
    uint64_t value = strtoull(params[4].c_str(), NULL, 10);

    std::vector<std::string> privKeys;
    for (uint i = 5; i < params.size(); i++) {
        privKeys.push_back(params[i]);
    }

    StandardTxOut txOut;
    txOut.set(toAddress, value);

    MultiSigRedeemScript multiSig;
    multiSig.parseRedeemScript(redeemScript);

    P2SHTxIn txIn(outHash, outIndex, multiSig.getRedeemScript());
    txIn.setScriptSig(SCRIPT_SIG_SIGN);

    Transaction tx;
    tx.addOutput(txOut);
    tx.addInput(txIn);
    uchar_vector hashToSign = tx.getHashWithAppendedCode(1); // SIGHASH_ALL

    // TODO: make sure to wipe all key data if there's any failure
    CoinKey key;
    for (uint i = 0; i < privKeys.size(); i++) {
        if (!key.setWalletImport(privKeys[i])) {
            std::stringstream ss;
            ss << "Private key " << i+1 << " is invalid.";
            throw std::runtime_error(ss.str());
        }

        uchar_vector sig;
        if (!key.sign(hashToSign, sig)) {
            std::stringstream ss;
            ss << "Error signing with key " << i+1 << ".";
            throw std::runtime_error(ss.str());
        }
        txIn.addSig(uchar_vector(), sig);
    }

    if (privKeys.size() < multiSig.getMinSigs()) {
        txIn.setScriptSig(SCRIPT_SIG_EDIT);
    }
    else {
        txIn.setScriptSig(SCRIPT_SIG_BROADCAST);
    }
    tx.clearInputs();
    tx.addInput(txIn);
    return tx.getSerialized().getHex();
}

std::string signmofn(bool bHelp, params_t& params)
{
    if (bHelp || params.size() < 6) {
        return "signmofn <outhash> <outindex> <redeemscript> <toaddress> <value> <privkey1> [<privkey2> <privkey3> ...] - creates and signs a transaction claiming a multisignature input.";
    }

    uchar_vector outHash = params[0];
    uint outIndex = strtoul(params[1].c_str(), NULL, 10);
    uchar_vector redeemScript = params[2];
    std::string toAddress = params[3];
    uint64_t value = strtoull(params[4].c_str(), NULL, 10);

    std::vector<std::string> privKeys;
    for (uint i = 5; i < params.size(); i++) {
        privKeys.push_back(params[i]);
    }

    StandardTxOut txOut;
    txOut.set(toAddress, value);
/*
    MultiSigRedeemScript multiSig;
    multiSig.parseRedeemScript(redeemScript);
*/
    MofNTxIn txIn(outHash, outIndex, redeemScript);
    txIn.setScriptSig(SCRIPT_SIG_SIGN);
/*
    P2SHTxIn txIn(outHash, outIndex, multiSig.getRedeemScript());
    txIn.scriptSig = multiSig.getRedeemScript();
*/

    Transaction tx;
    tx.addOutput(txOut);
    tx.addInput(txIn);
    uchar_vector hashToSign = tx.getHashWithAppendedCode(1); // SIGHASH_ALL

    // TODO: make sure to wipe all key data if there's any failure
    CoinKey key;
    for (uint i = 5; i < params.size(); i++) {
        if (!key.setWalletImport(params[i])) {
            std::stringstream ss;
            ss << "Private key " << i+1 << " is invalid.";
            throw std::runtime_error(ss.str());
        }

        uchar_vector sig;
        if (!key.sign(hashToSign, sig)) {
            std::stringstream ss;
            ss << "Error signing with key " << i+1 << ".";
            throw std::runtime_error(ss.str());
        }
        txIn.addSig(key.getPublicKey(), sig);
    }

    txIn.setScriptSig(SCRIPT_SIG_BROADCAST);
    tx.clearInputs();
    tx.addInput(txIn);
    return tx.getSerialized().getHex();
}

std::string getmissingsigs(bool bHelp, params_t& params)
{
    if (bHelp || params.size() != 1) {
        return "getmissingsigs <txhex>"; 
    }

    TransactionBuilder txBuilder(params[0]);
    return txBuilder.getMissingSigsJson();
}


///////////////////////////////////
//
// Initialization Functions
//
void initCommands()
{
    command_map.clear();
    command_map["help"] = &help;
    command_map["createmultisig"] = &createmultisig;
    command_map["standardtxout"] = &standardtxout;
    command_map["parsemultisigredeemscript"] = &parsemultisigredeemscript;
    command_map["addoutput"] = &addoutput;
    command_map["addp2addressinput"] = &addp2addressinput;
    command_map["createtransaction"] = &createtransaction;
    command_map["signmofn"] = &signmofn;
    command_map["getmissingsigs"] = &getmissingsigs;
}

void getParams(int argc, char* argv[], params_t& params)
{
    params.clear();
    for (int i = 2; i < argc; i++) {
        params.push_back(argv[i]);
    }
}

//////////////////////////////////
//
// Main Program
//
int main(int argc, char* argv[])
{
    initCommands();
    params_t params;

    if (argc == 1) {
        std::cout << help(false, params) << std::endl;
        return 0;
    }

    std::string command = argv[1];
    command_map_t::iterator it = command_map.find(command);
    if (it == command_map.end()) {
        std::cout << "Invalid command: " << command << std::endl;
        std::cout << help(true, params) << std::endl;
        return 0;
    }

    getParams(argc, argv, params);
    try {
        std::cout << it->second(false, params) << std::endl;
    }
    catch (const std::exception& e) {
        std::cout << "Error: " << e.what() << std::endl;
        return -1;
    }

    return 0;
}
