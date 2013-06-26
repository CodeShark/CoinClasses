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
    txOut.payToAddress(params[0], strtoull(params[1].c_str(), NULL, 10));

    if (bHex) {
        return txOut.getSerialized().getHex();
    }
    else {
        return txOut.toJson();
    }
}

std::string signtransaction(bool bHelp, params_t& params)
{
    if (bHelp) {
        return "signtransaction - not defined yet.";
    }

    StandardTxOut txOut;
    txOut.payToAddress("1JnFGnYb9qM8N6wDMB2nZuVgSMGq4G4kWH", 9950000);

    MultiSigRedeemScript multiSig;
    multiSig.parseRedeemScript(uchar_vector("5221037d32081bf4a1be6e8f2d5dbb98ee9408bd0559988f4c5a779dc40d92b6251a8021021574b25c88eb3c407bf2f9d18221a6bf15bf69ed5c120012300706c141f966e952ae"));

    P2SHTxIn txIn(uchar_vector("a9c6269f61ddcf7a71a416976e8f8b96741ad7a6a6a2123adb48da04932e3ba1"), 1, multiSig.getRedeemScript());

    Transaction tx;
    tx.addOutput(txOut);
    tx.addInput(txIn);

/*
    std::stringstream ss;
    ss << "redeemScript: " << multiSig.toJson(true) << std::endl;
    ss << "txOut: " << txOut.toJson() << std::endl;
    return ss.str();*/
    return tx.toJson();
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
    command_map["signtransaction"] = &signtransaction;
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
/*
    if (argc < 3) {
        cout << "Usage: " << argv[0] << " [address] [value]" << endl;
        return 0;
    }

    string address = argv[1];
    uint64_t value = strtoull(argv[2], NULL, 10);

    try {
        StandardTxOut txOut;
        txOut.payToAddress(address, value);
        cout << txOut.toString() << endl;
    }
    catch (const exception& e) {
        cout << "Error: " << e.what() << endl;
        return -1;
    }
*/
}
