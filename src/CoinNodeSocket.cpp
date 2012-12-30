////////////////////////////////////////////////////////////////////////////////
//
// CoinNodeSocket.cpp
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

//#define __DEBUG_OUT__
#define __SHOW_EXCEPTIONS__

#include <CoinNodeSocket.h>
#include <numericdata.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>

#include <stdexcept>

#define SOCKET_BUFFER_SIZE 16384
#define MESSAGE_HEADER_SIZE 20
#define COMMAND_SIZE 12

using namespace Coin;
using namespace std;

void messageLoop(void* param)
{
    try {
#ifdef __DEBUG_OUT__
        fprintf(stdout, "Starting message loop.\n\n");
#endif
        CoinNodeSocket* pNodeSocket = (CoinNodeSocket*) param;
        uchar_vector message;
        uchar_vector magicBytes = pNodeSocket->getMagicBytes();
#ifdef __DEBUG_OUT__
        fprintf(stdout, "Magic Bytes: %s\n", magicBytes.getHex().c_str());
#endif
        int h_socket = pNodeSocket->getSocketHandle();
        MessageProcessor messageProcessor = pNodeSocket->getMessageProcessor();
        CoinMessageHandler messageHandler = pNodeSocket->getMessageHandler();
        unsigned char command[12];
        uchar_vector payload;
        uint payloadLength;
        uchar_vector checksum;
        uint checksumLength;
        unsigned char receivedData[SOCKET_BUFFER_SIZE];
        uint bytesBuffered;
        while (true) {
            try {  
                // Find magic bytes. all magic bytes must exist in a single frame to be recognized.
                uchar_vector::iterator it;
                while ((it = search(message.begin(), message.end(), magicBytes.begin(), magicBytes.end())) == message.end()) {
                    bytesBuffered = recv(h_socket, receivedData, SOCKET_BUFFER_SIZE, 0);
                    message = uchar_vector(receivedData, bytesBuffered);
                }
                message.assign(it, message.end()); // remove everything before magic bytes

                // get rest of header
                while (message.size() < MIN_MESSAGE_HEADER_SIZE) {
                    bytesBuffered = recv(h_socket, receivedData, SOCKET_BUFFER_SIZE, 0);
                    message += uchar_vector(receivedData, bytesBuffered);
                }
                // get command
                uchar_vector(message.begin() + 4, message.begin() + 16).copyToArray(command);

                // get payload length
                payloadLength = vch_to_uint<uint32_t>(uchar_vector(message.begin() + 16, message.begin() + 20), _BIG_ENDIAN);

                // version and verack messages have no checksum - as of Feb 20, 2012, version messages do have a checksum
                /*checksumLength = ((strcmp((char*)command, "version") == 0) ||
                                    (strcmp((char*)command, "verack") == 0)) ? 0 : 4;*/
                // VERSION_CHECKSUM_CHANGE
                checksumLength = (strcmp((char*)command, "verack") == 0) ? 0 : 4;

                // get checksum and payload
                while (message.size() < MIN_MESSAGE_HEADER_SIZE + checksumLength + payloadLength) {
                    bytesBuffered = recv(h_socket, receivedData, SOCKET_BUFFER_SIZE, 0);
                    message += uchar_vector(receivedData, bytesBuffered);
                }

                CoinNodeMessage nodeMessage(message);

#ifdef __DEBUG_OUT__
                if (bytesBuffered > message.size())
                    fprintf(stdout, "Received extra bytes. Buffer dump:\n%s\n", uchar_vector(receivedData, bytesBuffered).getHex().c_str());
#endif

                if (nodeMessage.isChecksumValid()) {
                    // if it's a verack, signal the completion of the handshake
                    if (string((char*)command) == "verack")
                        pthread_cond_signal(&pNodeSocket->m_handshakeComplete);

                    // send the message to be processed.
                    if (messageProcessor) messageProcessor(pNodeSocket, command, payload);
                    if (messageHandler) messageHandler(pNodeSocket, nodeMessage);
                }
                else
                    throw runtime_error("Checksum does not match payload for message of type.");

                // shift message frame over
                message.assign(message.begin() + MESSAGE_HEADER_SIZE + checksumLength + payloadLength, message.end());
            }
            catch (const exception& e) {
                message.assign(message.begin() + MESSAGE_HEADER_SIZE + checksumLength + payloadLength, message.end());
#ifdef __SHOW_EXCEPTIONS__
                fprintf(stdout, "Exception: %s\n", e.what());
#endif
            }
        }
    }
    catch (const exception& e) {
#ifdef __SHOW_EXCEPTIONS__
        fprintf(stdout, "Exception: %s\n", e.what());
#endif
    }
}

CoinNodeSocket::CoinNodeSocket()
{
    this->h_socket = -1;
    this->h_messageThread = 0;
    pthread_mutex_init(&this->m_sendLock, NULL);
    pthread_mutex_init(&this->m_handshakeLock, NULL);
    pthread_mutex_init(&this->m_updateAppDataLock, NULL);
    pthread_cond_init(&this->m_handshakeComplete, NULL);
}

void CoinNodeSocket::open(MessageProcessor callback, uint32_t magic, uint32_t version, const char* hostname, uint port)
{
    if (this->h_socket != -1) throw runtime_error("Connection already open.");

    this->p_host = gethostbyname(hostname);
    if ((this->h_socket = socket(AF_INET, SOCK_STREAM, 0)) == -1)
        throw runtime_error("Error creating socket.");

    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(8333);
    serverAddress.sin_addr = *((struct in_addr*)this->p_host->h_addr);
    bzero(&(serverAddress.sin_zero), 8);

    if (connect(h_socket, (struct sockaddr*)&serverAddress, sizeof(struct sockaddr)) == -1)
        throw runtime_error("Error connecting to socket.");

    this->messageProcessor = callback;
    this->coinMessageHandler = NULL;
    this->m_magic = magic;
    this->m_magicBytes = uint_to_vch(magic, _BIG_ENDIAN);
    this->m_version = version;
    this->m_hostname = hostname;
    this->m_port = port;

    this->h_messageThread = 0;
    int ret = pthread_create(&this->h_messageThread, NULL, (void*(*)(void*))messageLoop, this);

#ifdef __DEBUG_OUT__
    fprintf(stdout, "opened with magic bytes: %s\n", this->m_magicBytes.getHex().c_str());
#endif
    /*this->h_messageThread = *///CreateThread(messageLoop, &params);
    /*if (!this->h_messageThread)
        throw runtime_error("Error creating message thread.");*/
}

void CoinNodeSocket::open(CoinMessageHandler callback, uint32_t magic, uint version, const char* hostname, uint port)
{
    if (this->h_socket != -1) throw runtime_error("Connection already open.");

    this->p_host = gethostbyname(hostname);
    if ((this->h_socket = socket(AF_INET, SOCK_STREAM, 0)) == -1)
        throw runtime_error("Error creating socket.");

    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(port);
    serverAddress.sin_addr = *((struct in_addr*)this->p_host->h_addr);
    bzero(&(serverAddress.sin_zero), 8);

    if (connect(h_socket, (struct sockaddr*)&serverAddress, sizeof(struct sockaddr)) == -1)
        throw runtime_error("Error connecting to socket.");

    this->messageProcessor = NULL;
    this->coinMessageHandler = callback;
    this->m_magic = magic;
    this->m_magicBytes = uint_to_vch(magic, _BIG_ENDIAN);
    this->m_version = version;
    this->m_hostname = hostname;
    this->m_port = port;

    this->h_messageThread = 0;
    int ret = pthread_create(&this->h_messageThread, NULL, (void*(*)(void*))messageLoop, this);

#ifdef __DEBUG_OUT__
    fprintf(stdout, "opened with magic bytes: %s\n", this->m_magicBytes.getHex().c_str());
#endif
    /*this->h_messageThread = *///CreateThread(messageLoop, &params);
    /*if (!this->h_messageThread)
        throw runtime_error("Error creating message thread.");*/
}

void CoinNodeSocket::close()
{
    if (this->h_messageThread) pthread_cancel(this->h_messageThread);
    ::close(h_socket);
    h_socket = -1;
}

void CoinNodeSocket::doHandshake(
    int32_t version,
    uint64_t services,
    int64_t timestamp,
    const NetworkAddress& recipientAddress,
    const NetworkAddress& senderAddress,
    uint64_t nonce,
    const char* subVersion,
    int32_t startHeight
)
{
    VersionMessage versionMessage(version, services, timestamp, recipientAddress, senderAddress, nonce, subVersion, startHeight);
    CoinNodeMessage messagePacket(this->m_magic, &versionMessage);
    this->sendMessage(messagePacket);
}

void CoinNodeSocket::waitOnHandshakeComplete()
{
    pthread_mutex_lock(&this->m_handshakeLock);
    pthread_cond_wait(&this->m_handshakeComplete, &this->m_handshakeLock);
    pthread_mutex_unlock(&this->m_handshakeLock);
}

void CoinNodeSocket::sendMessage(const CoinNodeMessage& message)
{
    if (this->h_socket == -1) throw runtime_error("Socket is not open.");

    vector<unsigned char> rawData = message.getSerialized();

#ifdef __DEBUG_OUT__
    fprintf(stdout, "Sending message: %s\n", message.toString().c_str());
    fprintf(stdout, "Raw data:\n%s\n", uchar_vector(rawData).getHex().c_str());
#endif

    pthread_mutex_lock(&m_sendLock);
    send(this->h_socket, (unsigned char*)&rawData[0], rawData.size(), 0);
    pthread_mutex_unlock(&m_sendLock);
}