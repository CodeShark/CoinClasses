#include <CoinNodeData.h>

#include <iostream>

using namespace Coin;
using namespace std;

int main()
{
    std::vector<PartialMerkleTree::MerkleLeaf> leaves;
    leaves.push_back(make_pair(uchar_vector("cf86811c2853a14c520d7bc7cd2f41e16ba1d02a19ddef197df8fe4c575a599e").getReverse(), false));
    leaves.push_back(make_pair(uchar_vector("da9219371684385a997194b54ee7cbe908eb829043e1cb245b09157a2adb5de3").getReverse(), false));
    leaves.push_back(make_pair(uchar_vector("87c9b40548e71b0c50fc535aead2674a3f575f18af451b3f27770e04bf03e3d1").getReverse(), false));
    leaves.push_back(make_pair(uchar_vector("757efcca85025b9b67780e6d66f4284badf01c9d3eb1a6f4648d57d383868625").getReverse(), false));
    leaves.push_back(make_pair(uchar_vector("123ec576f0cc12c5e3876c82b4f860ac7f6170096a089982b99d24e575dc521b").getReverse(), true));
    leaves.push_back(make_pair(uchar_vector("d52a468b14a3b2dfa11eb26081aa2e0b7158986118f3021c7969f1c675e385a9").getReverse(), false));
    leaves.push_back(make_pair(uchar_vector("98abb76a0289477519b98ef216dbfb5fe807a90bb9a7f53a140e2d0213e38c80").getReverse(), false));
    leaves.push_back(make_pair(uchar_vector("0b82afba1b61e301ade9f67bd588ced909967156084bd6b4c088cc5b266c099b").getReverse(), true));

    PartialMerkleTree tree;
    tree.setUncompressed(leaves);

    cout << "merkleRoot: " << tree.getRootLittleEndian().getHex() << endl;
    cout << "hashes:" << endl;
    unsigned int i = 0;
    for (auto& hash: tree.getMerkleHashes()) { cout << "  " << i++ << ": " << uchar_vector(hash).getReverse().getHex() << endl; }

    cout << "txids:" << endl;
    i = 0;
    for (auto& hash: tree.getTxHashes()) { cout << "  " << i++ << ": " << uchar_vector(hash).getReverse().getHex() << endl; }

    cout << "flags: " << tree.getFlags().getHex() << endl;
 
    return 0;
}
