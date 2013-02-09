////////////////////////////////////////////////////////////////////////////////
//
// CoinNodeAbstractListener.cpp
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

#include "CoinNodeAbstractListener.h"

using namespace Coin;

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

void coinMessageHandler(CoinNodeSocket* pNodeSocket, const CoinNodeMessage& message)
{
    std::string command = message.getCommand();
    
    if (command == "tx" || command == "block")
        pNodeSocket->pListener->lockHandler();

    try {
        if (command == "version") {
            VerackMessage verackMessage;
            CoinNodeMessage msg(pNodeSocket->getMagic(), &verackMessage);
            pNodeSocket->sendMessage(msg);
        }
        else if (command == "inv") {
            Inventory* pInventory = static_cast<Inventory*>(message.getPayload());
            GetDataMessage getData(*pInventory);
            CoinNodeMessage msg(pNodeSocket->getMagic(), &getData);
            pNodeSocket->sendMessage(msg);
        }
        else if (command == "tx") {
            Transaction* pTx = static_cast<Transaction*>(message.getPayload());
            pNodeSocket->pListener->onTx(*pTx);
        }
        else if (command == "block") {
            CoinBlock* pBlock = static_cast<CoinBlock*>(message.getPayload());
            pNodeSocket->pListener->onBlock(*pBlock);
        }
        else if (command == "addr") {
            AddrMessage* pAddr = static_cast<AddrMessage*>(message.getPayload());
            pNodeSocket->pListener->onAddr(*pAddr);
        }
    }
    catch (const std::exception& e) {
        std::cout << "Exception in coinMessageHandler(): " << e.what() << std::endl;
    }

    if (command == "tx" || command == "block")
        pNodeSocket->pListener->unlockHandler();
}

void socketClosedHandler(CoinNodeSocket* pNodeSocket, int code)
{
    pNodeSocket->pListener->onSocketClosed(code);
}

void CoinNodeAbstractListener::start()
{
    m_nodeSocket.setMultithreaded(false);
    m_nodeSocket.open(coinMessageHandler, m_magic, m_version, m_peerHostname.c_str(), m_port, socketClosedHandler);
    m_nodeSocket.doHandshake(m_version, NODE_NETWORK, time(NULL), m_peerAddress, m_listenerAddress, getRandomNonce64(), "", 0);
    m_nodeSocket.waitOnHandshakeComplete();
}	

void CoinNodeAbstractListener::askForBlock(const std::string& hash)
{
    InventoryItem block(MSG_BLOCK, uchar_vector(hash));
    Inventory inv;
    inv.addItem(block);
    GetDataMessage getData(inv);
    CoinNodeMessage msg(this->getMagic(), &getData);
    this->sendMessage(msg);
}

void CoinNodeAbstractListener::askForTx(const std::string& hash)
{
    InventoryItem block(MSG_TX, uchar_vector(hash));
    Inventory inv;
    inv.addItem(block);
    GetDataMessage getData(inv);
    CoinNodeMessage msg(this->getMagic(), &getData);
    this->sendMessage(msg);
}

void CoinNodeAbstractListener::askForPeers()
{
    BlankMessage mempool("getaddr");
    CoinNodeMessage msg(this->getMagic(), &mempool);
    this->sendMessage(msg);
}

void CoinNodeAbstractListener::askForMempool()
{
    BlankMessage mempool("mempool");
    CoinNodeMessage msg(this->getMagic(), &mempool);
    this->sendMessage(msg);
}