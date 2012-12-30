SRC_PATH=../../src

LIBS = \
	-l ssl \
	-l crypto

all: keygen

$(SRC_PATH)/obj/CoinKey.o: $(SRC_PATH)/CoinKey.cpp
	$(CXX) -c -o $(SRC_PATH)/obj/CoinKey.o \
	$(SRC_PATH)/CoinKey.cpp \
	-I$(SRC_PATH)

keygen: $(SRC_PATH)/obj/CoinKey.o
	$(CXX) -o keygen \
	keygen.cpp $(SRC_PATH)/obj/CoinKey.o \
	-I$(SRC_PATH) \
	$(LIBS)

clean:
	-rm -f keygen

clean-all:
	-rm -f keygen
	-rm -f $(SRC_PATH)/obj/*.o
