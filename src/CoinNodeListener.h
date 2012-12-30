////////////////////////////////////////////////////////////////////////////////
//
// CoinNodeListener.h
//
// Copyright (c) 2012 Eric Lombrozo
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

#ifndef _COIN_NODE_LISTENER_H__
#define _COIN_NODE_LISTENER_H__

#include "CoinNodeSocket.h"

#define CLIENT_VERSION 40000

#define BTC_MAGIC_MAIN 0xd9b4bef9

#define DEFAULT_HOSTNAME "127.0.0.1"
#define DEFAULT_PORT 8333
const unsigned char DEFAULT_Ipv6[] = {0,0,0,0,0,0,0,0,0,0,255,255,127,0,0,1};

namespace Coin
{

class CoinNodeListener;
typedef void (*CoinBlockHandler)(CoinBlock* pBlock, CoinNodeListener* pListener, void* pInstanceData);
typedef void (*CoinTxHandler)(Transaction* pBlock, CoinNodeListener* pListener, void* pInstanceData);

uint64_t getRandomNonce64()
{
    // TODO: Use better RNG
    srand(time(NULL));
    uint64_t nonce = 0;
    for (uint i = 0; i < 4; i++) {
        nonce <<= 8;
        nonce |= rand() % 0xff;
    }
    return nonce;
}

class FullInstanceData
{
public:
    CoinBlockHandler coinBlockHandler;
    CoinTxHandler coinTxHandler;
    CoinNodeListener* pListener;
    void* pInstanceData;
	
    FullInstanceData() : coinBlockHandler(NULL), coinTxHandler(NULL), pListener(NULL), pInstanceData(NULL) { }
};

void coinMessageHandler(CoinNodeSocket* pNodeSocket, const CoinNodeMessage& message)
{
    FullInstanceData* pFullInstanceData = static_cast<FullInstanceData*>(pNodeSocket->pAppData);
	
    try {
        if (std::string(message.getCommand()) == "version") {
            VerackMessage verackMessage;
            CoinNodeMessage msg(pNodeSocket->getMagic(), &verackMessage);
            pNodeSocket->sendMessage(msg);
        }
        else if (std::string(message.getCommand()) == "inv") {
            Inventory* pInventory = static_cast<Inventory*>(message.getPayload());
            GetDataMessage getData(*pInventory);
            CoinNodeMessage msg(pNodeSocket->getMagic(), &getData);
            pNodeSocket->sendMessage(msg);
        }
        else if (std::string(message.getCommand()) == "tx") {
            if (pFullInstanceData->coinTxHandler) {
                Transaction* pTx = static_cast<Transaction*>(message.getPayload());
                pFullInstanceData->coinTxHandler(pTx, pFullInstanceData->pListener, pFullInstanceData->pInstanceData);
            }
        }
        else if (std::string(message.getCommand()) == "block") {
            if (pFullInstanceData->coinBlockHandler) {
                CoinBlock* pBlock = static_cast<CoinBlock*>(message.getPayload());
                pFullInstanceData->coinBlockHandler(pBlock, pFullInstanceData->pListener, pFullInstanceData->pInstanceData);
            }
        }
    }
    catch (const std::string& error) {
        std::cout << "Exception in coinMessageHandler(): " << error << std::endl;
    }
    catch (const char* error) {
        std::cout << "Exception in coinMessageHandler(): " << error << std::endl;
    }
}

class CoinNodeListener
{
private:
    CoinNodeSocket m_nodeSocket;
    uint32_t m_version;
    uint32_t m_magic;
    std::string m_peerHostname;
    NetworkAddress m_listenerAddress;
    NetworkAddress m_peerAddress;
    uint16_t m_port;
    FullInstanceData m_fullInstanceData;
	
public:
    CoinNodeListener(uint32_t magic = BTC_MAGIC_MAIN, const std::string& peerHostname = DEFAULT_HOSTNAME, const unsigned char* peerIpAddress = DEFAULT_Ipv6, uint16_t port = DEFAULT_PORT, const unsigned char* listenerIpAddress = DEFAULT_Ipv6, uint32_t version = CLIENT_VERSION) :
        m_magic(magic),
        m_peerHostname(peerHostname),
        m_port(port),
        m_version(version)
    {
        m_listenerAddress.set(NODE_NETWORK, listenerIpAddress, port);
        m_peerAddress.set(NODE_NETWORK, peerIpAddress, port);
        m_fullInstanceData.pListener = this;
        m_nodeSocket.pAppData = &m_fullInstanceData;
    }
	
    ~CoinNodeListener() { this->stop(); }
	
    void setInstanceData(void* pInstanceData) { m_fullInstanceData.pInstanceData = pInstanceData; }
    void setBlockHandler(CoinBlockHandler coinBlockHandler) { m_fullInstanceData.coinBlockHandler = coinBlockHandler; }
    void setTxHandler(CoinTxHandler coinTxHandler) { m_fullInstanceData.coinTxHandler = coinTxHandler; }	

    uint32_t getMagic() const { return m_magic; }	

    void start()
    {
        m_nodeSocket.open(coinMessageHandler, m_magic, m_version, m_peerHostname.c_str(), m_port);
        m_nodeSocket.doHandshake(m_version, NODE_NETWORK, time(NULL), m_peerAddress, m_listenerAddress, getRandomNonce64(), "", 0);
        m_nodeSocket.waitOnHandshakeComplete();
    }	
    void stop() { m_nodeSocket.close(); }
	
    void sendMessage(const CoinNodeMessage& pMessage) { m_nodeSocket.sendMessage(pMessage); }
};

}; // namespace Coin

#endif // _COIN_NODE_LISTENER_H__
