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

set<string> g_hosts;
map<string, shared_ptr<AddrListener> > g_connections;

void AddrListener::onAddr(AddrMessage& addr)
{
    cout << "Received addr message from " << name << endl;
    for (uint i = 0; i < addr.addrList.size(); i++)
    {
        // Only look at ipv4 nodes
        if (!addr.addrList[i].ipv6.isIPv4()) continue;

        stringstream ss;
        string ip = addr.addrList[i].ipv6.toIPv4String();
        ss << ip << ":" << addr.addrList[i].port;
        g_hosts.insert(ss.str());
        
        if (g_connections.count(ss.str()) == 0)
        {
            AddrListener* pListener = new AddrListener(ip, addr.addrList[i].port);
            try
            {
                cout << "  Opening connection to " << ss.str() << "..." << flush;
                pListener->start();
                cout << "connected." << endl;
                g_connections[ss.str()] = shared_ptr<AddrListener>(pListener);
                pListener->askForPeers();
            }
            catch (const exception& e)
            {
                delete pListener;
                cout << e.what() << endl;
            }
        }
    }
}

void AddrListener::onSocketClosed(int code)
{
    cout << "Closed connection to " << name << " with code " << code << "." << endl;
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
