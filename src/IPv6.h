////////////////////////////////////////////////////////////////////////////////
//
// IPv6.h
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

#ifndef IPV6_H_INCLUDED
#define IPV6_H_INCLUDED

#include <cstring>
#include <string>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <stdexcept>

class IPv6AddressException : public std::runtime_error
{
public:
    IPv6AddressException(const char* description) : std::runtime_error(description) { }
};

class IPv6Address
{
private:
    unsigned char bytes[16];

public:
    IPv6Address() { memset(&bytes[0], 0, sizeof(bytes)); }
    IPv6Address(const std::string& address) { set(address); }
    IPv6Address(const IPv6Address& source) { memcpy(bytes, source.bytes, sizeof(bytes)); }
    IPv6Address(const unsigned char bytes[]) { set(bytes); }

    void set(const unsigned char _bytes[]) { memcpy(bytes, _bytes, std::min(sizeof(bytes), sizeof(_bytes))); }
    void set(const std::string& address);

    IPv6Address& operator=(const unsigned char bytes[]) { set(bytes); return *this; }
    IPv6Address& operator=(const std::string& address) { set(address); return *this; }

    bool isIPv4() const;

    std::string toString(bool bShorten = false) const;
    std::string toIPv4String() const;
    std::string toStringAuto() const;

    const unsigned char* getBytes() const { return bytes; }
};

void IPv6Address::set(const std::string& address)
{
    std::stringstream ss(address);
    std::string group;

    int i = 0;

    // IPv4
    if (address.size() <= 15)
    {
        int byte;
        unsigned char bytes[4];
        
        while (std::getline(ss, group, '.'))
        {
            if (i > 3)
                throw IPv6AddressException("Invalid address");

            try {
                byte = strtoul(group.c_str(), NULL, 10);
            }
            catch (const std::exception& e) {
                throw IPv6AddressException("Invalid address");
            }

            if ((byte < 0) || (byte > 255))
                throw IPv6AddressException("Invalid address");

            bytes[i++] = (unsigned char)byte;
        }

        if (i < 4) throw IPv6AddressException("Invalid address");

        memset(this->bytes, 0, 10);
        memset(&this->bytes[10], 0xff, 2);
        memcpy(&this->bytes[12], bytes, 4);
        return;
    }

    // IPv6
    while (std::getline(ss, group, ':'))
    {
        if (i > 15)
            throw IPv6AddressException("Invalid address");

        int bytepair;
        try {
            bytepair = strtoul(group.c_str(), NULL, 16);
        }
        catch (const std::exception& e) {
            throw IPv6AddressException("Invalid address");
        }

        if ((bytepair < 0) || (bytepair > 0xffff))
            throw IPv6AddressException("Invalid address");

        this->bytes[i++] = (unsigned char)(bytepair / 0x100);
        this->bytes[i++] = (unsigned char)(bytepair % 0x100);
    }
}

bool IPv6Address::isIPv4() const
{
    const unsigned char ipv4LeadBytes[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff };
    return (memcmp(bytes, ipv4LeadBytes, sizeof(ipv4LeadBytes)) == 0);
}

std::string IPv6Address::toString(bool bShorten) const
{
    std::stringstream ss;
    ss  << std::hex << std::setfill('0')
        << std::setw(2) << (int)bytes[0] << std::setw(2) << (int)bytes[1] << ":"
        << std::setw(2) << (int)bytes[2] << std::setw(2) << (int)bytes[3] << ":"
        << std::setw(2) << (int)bytes[4] << std::setw(2) << (int)bytes[5] << ":"
        << std::setw(2) << (int)bytes[6] << std::setw(2) << (int)bytes[7] << ":"
        << std::setw(2) << (int)bytes[8] << std::setw(2) << (int)bytes[9] << ":"
        << std::setw(2) << (int)bytes[10] << std::setw(2) << (int)bytes[11] << ":"
        << std::setw(2) << (int)bytes[12] << std::setw(2) << (int)bytes[13] << ":"
        << std::setw(2) << (int)bytes[14] << std::setw(2) << (int)bytes[15];
    return ss.str();
}

std::string IPv6Address::toIPv4String() const
{
    std::stringstream ss;
    ss << (int)bytes[12] << "." << (int)bytes[13] << "." << (int)bytes[14] << "." << (int)bytes[15];
    return ss.str();
}

std::string IPv6Address::toStringAuto() const
{
    if (isIPv4()) return toIPv4String();
    return toString();
}

#endif // IPV6_H_INCLUDED
