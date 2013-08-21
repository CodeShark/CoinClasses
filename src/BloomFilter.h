////////////////////////////////////////////////////////////////////////////////
//
// BloomFilter.h
//
// Copyright (c) 2013 Eric Lombrozo
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

#ifndef BLOOM_FILTER_H__
#define BLOOM_FILTER_H__

#include "CoinNodeData.h"

namespace Coin {

class BloomFilter
{
private:
    uchar_vector filter;
    uint32_t nHashFuncs;
    uint32_t nTweak;
    uint8_t nFlags;

    bool bFull, bEmpty;

    uint32_t hash(uint n, const uchar_vector& data) const;

public:
    void insert(const uchar_vector& data);

    bool match(const uchar_vector& data) const;
    bool matchAndUpdate(const Transaction& tx, const uchar_vector& data) const;
};

} // Coin

#endif // BLOOM_FILTER_H__
