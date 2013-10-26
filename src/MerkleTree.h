////////////////////////////////////////////////////////////////////////////////
//
// MerkleTree.h
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

#ifndef COIN_MERKLETREE_H__
#define COIN_MERKLETREE_H__

#include "uchar_vector.h"
#include "hash.h"

#include <list>
#include <queue>
#include <sstream>

namespace Coin
{
	
class MerkleTree
{
public:
    MerkleTree() { }
    MerkleTree(const std::vector<uchar_vector>& hashes) { hashes_ = hashes; }

    const std::vector<uchar_vector>& getHashes() const { return hashes_; }
    void clear() { hashes_.clear(); }
    void addHash(const uchar_vector& hash) { hashes_.push_back(hash); }
    void addHashLittleEndian(const uchar_vector& hash) { hashes_.push_back(uchar_vector(hash).getReverse()); }

    uchar_vector getRoot() const;
    uchar_vector getRootLittleEndian() const { return getRoot().getReverse(); }

private:
    std::vector<uchar_vector> hashes_;
};

class PartialMerkleTree
{
public:
    typedef std::pair<uchar_vector, bool> MerkleLeaf;

    PartialMerkleTree() { }
    PartialMerkleTree(unsigned int nTxs, const std::vector<uchar_vector>& hashes, const uchar_vector& flags) { setCompressed(nTxs, hashes, flags); }
    PartialMerkleTree(const std::vector<MerkleLeaf>& leaves) { setUncompressed(leaves); }

    void setCompressed(unsigned int nTxs, const std::vector<uchar_vector>& hashes, const uchar_vector& flags);
    void setUncompressed(const std::vector<MerkleLeaf>& leaves);

    unsigned int getNTxs() const { return nTxs_; }
    unsigned int getDepth() const { return depth_; }
    const std::list<uchar_vector>& getMerkleHashes() const { return merkleHashes_; }
    std::vector<uchar_vector> getMerkleHashesVector() const
    {
        std::vector<uchar_vector> rval;
        for (auto& hash: merkleHashes_) { rval.push_back(hash); }
        return rval;
    }

    const std::list<uchar_vector>& getTxHashes() const { return txHashes_; }
    std::vector<uchar_vector> getTxHashesVector() const
    {
        std::vector<uchar_vector> rval;
        for (auto& hash: txHashes_) { rval.push_back(hash); }
        return rval;
    }

    uchar_vector getFlags() const;

    const uchar_vector& getRoot() const { return root_; }
    uchar_vector getRootLittleEndian() const { return uchar_vector(root_).getReverse(); }

    std::string toIndentedString() const;

private:
    unsigned int nTxs_;
    unsigned int depth_;
    std::list<uchar_vector> merkleHashes_;
    std::list<uchar_vector> txHashes_;
    std::list<bool> bits_;
    uchar_vector root_;

    void setCompressed(std::queue<uchar_vector>& hashQueue, std::queue<bool>& bitQueue, unsigned int depth);
    void setUncompressed(const std::vector<MerkleLeaf>& leaves, std::size_t begin, std::size_t end, unsigned int depth);
};

} // namespace Coin

#endif // COIN_MERKLETREE_H__
