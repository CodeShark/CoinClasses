///////////////////////////////////////////////////////////////////////////////
//
// nodecrawler.cpp
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

#include <CoinNodeAbstractListener.h>

#include <set>
#include <map>
#include <memory>
#include <iostream>

#include <boost/thread/thread.hpp>

using namespace std;
using namespace Coin;

// Change these to use a different network
namespace listener_network
{
    const uint32_t MAGIC_BYTES = 0xd9b4bef9ul;
    const uint32_t PROTOCOL_VERSION = 60002;
    const uint8_t ADDRESS_VERSION = 0x00;
    const uint8_t MULTISIG_ADDRESS_VERSION = 0x05;
};

class AddrListener : public CoinNodeAbstractListener
{
private:
    string name;
    time_t time_connected;
    
public:
    AddrListener(const string& hostname, uint16_t port)
        : CoinNodeAbstractListener(listener_network::MAGIC_BYTES, listener_network::PROTOCOL_VERSION, hostname, port)
    {
        stringstream ss;
        ss << hostname << ":" << port;
        name = ss.str();
    }
    
    void start() { CoinNodeAbstractListener::start(); time_connected = time(NULL); }
    
    virtual void onAddr(AddrMessage& addr);
    
    virtual void onSocketClosed(int code);
};

set<string> g_peers;
map<string, unique_ptr<AddrListener> > g_connections;

string getNodeName(const string& ip, uint16_t port)
{
    stringstream ss;
    ss << ip << ":" << port;
    return ss.str();
}

void tryConnecting(const string& ip, uint16_t port, const string& nodeName)
{
    AddrListener* pListener = new AddrListener(ip, port);

    try
    {
        cout << "Trying " << nodeName << "..." << endl;
        pListener->start();
        cout << "Opened connection to " << nodeName << endl;
        g_connections[nodeName] = unique_ptr<AddrListener>(pListener);
        pListener->askForPeers();
    }
    catch (const exception& e)
    {
        delete pListener;
        cout << e.what() << endl;
    }
}

void AddrListener::onAddr(AddrMessage& addr)
{
    vector<string> ips;
    vector<uint16_t> ports;
    vector<string> nodeNames;
    for (uint i = 0; i < addr.addrList.size(); i++)
    {
        // Only look at ipv4 nodes
        if (!addr.addrList[i].ipv6.isIPv4()) continue;
        
        string ip = addr.addrList[i].ipv6.toIPv4String();
        ips.push_back(ip);
        ports.push_back(addr.addrList[i].port);
        
        string nodeName = getNodeName(ip, addr.addrList[i].port);
        nodeNames.push_back(nodeName);
        g_peers.insert(nodeName);
    }

    if (nodeNames.size() == 0) return;

    cout << "Added " << nodeNames.size() << " address(es) from " << name << endl;
    for (uint i = 0; i < nodeNames.size(); i++)
    {
        if (g_connections.count(nodeNames[i]) == 0)
            boost::thread t(tryConnecting, ips[i], ports[i], nodeNames[i]);
    }
}

void AddrListener::onSocketClosed(int code)
{
    cout << "Closed connection to " << name << " with code " << code << endl;
    g_connections.erase(name);
}

int main(int argc, char* argv[])
{
    if (argc < 3) {
        cout << "Usage: " << argv[0] << " <hostname> <port>" << endl
        << "Example: " << argv[0] << " 127.0.0.1 8333" << endl;
        return 0;
    }
    
    SetAddressVersion(listener_network::ADDRESS_VERSION);
    SetMultiSigAddressVersion(listener_network::MULTISIG_ADDRESS_VERSION);
	
    uint32_t port = strtoul(argv[2], NULL, 0);
    AddrListener listener(argv[1], port);
    try
    {
        cout << "Starting listener..." << flush;
        listener.start();
        cout << "started." << endl << endl;
        listener.askForPeers();
    }
    catch (const exception& e)
    {
        cout << "Error: " << e.what() << endl << endl;
        return -1;
    }
    
    while (true) { sleep(5000); }
    return 0;
}
