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

#include "txbuilder_commands.h"

#include <iostream>

typedef std::map<std::string, fAction>  command_map_t;
command_map_t command_map;

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

///////////////////////////////////
//
// Initialization Functions
//
void initCommands()
{
    command_map.clear();
    command_map["help"] = &help;
    command_map["createmultisig"] = &createmultisig;
    command_map["parsemultisig"] = &parsemultisig;
    command_map["addoutput"] = &addoutput;
    command_map["addaddressinput"] = &addaddressinput;
    command_map["addmofninput"] = &addmofninput;
    command_map["sign"] = &sign;
    command_map["getmissingsigs"] = &getmissingsigs;
    command_map["getbroadcast"] = &getbroadcast;
    command_map["getsign"] = &getsign;
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
