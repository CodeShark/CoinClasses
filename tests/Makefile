CXX = g++
CXXFLAGS = -std=c++0x -Wall -g

build/hdwallets: hdwallets.cpp ../src/hdwallet.h ../src/BigInt.h ../src/hash.h ../src/uchar_vector.h ../src/secp256k1.h ../src/Base58Check.h
	$(CXX) $(CXXFLAGS) -o $@ $< -lcrypto

clean:
	-rm -rf build/*
