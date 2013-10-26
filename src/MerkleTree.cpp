////////////////////////////////////////////////////////////////////////////////
//
// MerkleTree.cpp
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

#include "MerkleTree.h"

#include <stdexcept>

using namespace Coin;

///////////////////////////////////////////////////////////////////////////////
//
// class MerkleTree implementation
//
uchar_vector MerkleTree::getRoot() const
{
    uchar_vector pairedHashes;
    if (hashes_.size() == 0)
        return pairedHashes; // empty vector

    if (hashes_.size() == 1)
        return hashes_[0];

    MerkleTree tree;
    for (unsigned int i = 0; i < hashes_.size(); i += 2) {
        pairedHashes = hashes_[i];
        if (i + 1 < hashes_.size()) {
            // two different nodes
            pairedHashes += hashes_[i + 1];
        }
        else {
            // the same node with itself
            pairedHashes += hashes_[i];
        }
        //pairedHashes.reverse();
        tree.addHash(sha256_2(pairedHashes));
    }

    return tree.getRoot(); // recurse
}

///////////////////////////////////////////////////////////////////////////////
//
// class PartialMerkleTree implementation
//
std::string PartialMerkleTree::toIndentedString() const
{
    std::stringstream ss;
    ss << "root: " << uchar_vector(root_).getReverse().getHex() << std::endl;
    ss << "nTxs: " << nTxs_ << std::endl;
    ss << "merkleHashes: " << std::endl;
    unsigned int i = 0;
    for (auto& hash: merkleHashes_) {
        ss << "  " << i++ << ": " << uchar_vector(hash).getReverse().getHex() << std::endl; 
    }

    ss << "txHashes: " << std::endl;
    i = 0;
    for (auto& hash: txHashes_) {
        ss << "  " << i++ << ": " << uchar_vector(hash).getReverse().getHex() << std::endl;
    }

    ss << "flags: " << getFlags().getHex() << std::endl;
    return ss.str();
}

void PartialMerkleTree::setCompressed(unsigned int nTxs, const std::vector<uchar_vector>& hashes, const uchar_vector& flags)
{
    if (nTxs == 0) {
        throw std::runtime_error("Transaction count is zero.");
    }

    // Compute depth = ceiling(log_2(leaves.size()))
    nTxs_ = nTxs;
    unsigned int depth = 1;
    unsigned int n = nTxs_ - 1;
    while (n > 0) { depth++; n >>= 1; }
    depth--;

    std::queue<uchar_vector> hashQueue;
    merkleHashes_.clear();
    for (auto& hash: hashes) { merkleHashes_.push_back(hash); hashQueue.push(hash); }
    txHashes_.clear();
    bits_.clear();

    std::queue<bool> bitQueue; 
    for (auto& flag: flags) {
        for (unsigned int i = 0; i < 8; i++) {
            bool bit = ((flag >> i) & (unsigned char)0x01);
            bits_.push_back(bit);
            bitQueue.push(bit);
        }
    }

    setCompressed(hashQueue, bitQueue, depth);
}

void PartialMerkleTree::setCompressed(std::queue<uchar_vector>& hashQueue, std::queue<bool>& bitQueue, unsigned int depth)
{
    depth_ = depth;

    bool bit = bitQueue.front();
    bitQueue.pop();

    // We've reached a leaf of the partial merkle tree
    if (depth == 0 || !bit) {
        root_ = hashQueue.front();
        if (bit) txHashes_.push_back(hashQueue.front());
        hashQueue.pop();
        return;
    }

    depth--;

    // we're not at a leaf and bit is set so recurse
    PartialMerkleTree leftSubtree;
    leftSubtree.setCompressed(hashQueue, bitQueue, depth);

    txHashes_.swap(leftSubtree.txHashes_);

    if (!hashQueue.empty()) {
        // A right subtree also exists, so find it
        PartialMerkleTree rightSubtree;
        rightSubtree.setCompressed(hashQueue, bitQueue, depth);

        root_ = sha256_2(leftSubtree.root_ + rightSubtree.root_);
        txHashes_.splice(txHashes_.end(), rightSubtree.txHashes_);
    }
    else {
        // There's no right subtree - copy over this node's hash
        root_ = sha256_2(leftSubtree.root_ + leftSubtree.root_);
    }
}

void PartialMerkleTree::setUncompressed(const std::vector<MerkleLeaf>& leaves)
{
    if (leaves.empty()) {
        throw std::runtime_error("Leaf vector is empty.");
    }

    nTxs_ = leaves.size();
    merkleHashes_.clear();
    txHashes_.clear();
    bits_.clear();

    // Compute depth = ceiling(log_2(leaves.size()))
    unsigned int depth = 1;
    unsigned int n = nTxs_ - 1;
    while (n > 0) { depth++; n >>= 1; }
    depth--;

    setUncompressed(leaves, 0, leaves.size(), depth);
}

void PartialMerkleTree::setUncompressed(const std::vector<MerkleLeaf>& leaves, std::size_t begin, std::size_t end, unsigned int depth)
{
    depth_ = depth;
/*
    std::cout << std::endl << "----Creating PartialMerkleTree----" << std::endl;
    std::cout << "depth: " << depth << std::endl;
    std::cout << "leaves: " << std::endl;
    for (unsigned int i = begin; i < end; i++) { std::cout << leaves[i].first.getHex() << ", " << (leaves[i].second ? "true" : "false") << std::endl; }
*/
    // We've hit a leaf. Store the hash and push a true bit if matched, a false bit if unmatched.
    if (depth == 0) {
        root_ = leaves[begin].first;
        merkleHashes_.push_back(leaves[begin].first);
        if (leaves[begin].second) txHashes_.push_back(leaves[begin].first);
        bits_.push_back(leaves[begin].second);
        return;
    }

    depth--; // Descend a level

    // For a full tree, each subtree should have 2^depth leaves. The total number of leaves is end - begin.
    // We want to partition the leaves into a left set that contains 2^depth elemments
    // and a right set with the remainder. If we have 2^depth or fewer total leaves, we need to duplicate
    // the subtree merkle hash to compute the merkle hash but we only include the hashes, txids, and bits one time.
    std::size_t partitionPos = std::min((std::size_t)1 << depth, end - begin);
    PartialMerkleTree leftSubtree;
    leftSubtree.setUncompressed(leaves, begin, begin + partitionPos, depth);

    merkleHashes_.swap(leftSubtree.merkleHashes_);
    txHashes_.swap(leftSubtree.txHashes_);
    bits_.swap(leftSubtree.bits_);

    if (begin + partitionPos < end) {
        PartialMerkleTree rightSubtree;
        rightSubtree.setUncompressed(leaves, begin + partitionPos, end, depth);

        root_ = sha256_2(leftSubtree.root_ + rightSubtree.root_);

        merkleHashes_.splice(merkleHashes_.end(), rightSubtree.merkleHashes_);
        txHashes_.splice(txHashes_.end(), rightSubtree.txHashes_);
        bits_.splice(bits_.end(), rightSubtree.bits_);
    }
    else {
        root_ = sha256_2(leftSubtree.root_ + leftSubtree.root_);
    }

    if (txHashes_.empty()) {
        // No matched leaves in subtree, so prepend the root to hashes and a false to bits
        merkleHashes_.clear();
        merkleHashes_.push_front(root_);
        bits_.clear();
        bits_.push_front(false);     
    }
    else {
        bits_.push_front(true);
    }
}

uchar_vector PartialMerkleTree::getFlags() const
{
    uchar_vector flags;

    unsigned int byteCounter = 0;
    unsigned char byte = 0;
    for (auto bit: bits_) {
        //std::cout << "bit: " << (bit ? "true" : "false") << std::endl;
        if (byteCounter == 8) {
            flags.push_back(byte);
            byteCounter = 0;
            byte = 0;            
        }
        if (bit) byte |= ((unsigned char)1 << byteCounter);
        byteCounter++;
    }
    flags.push_back(byte);
    return flags;
}
