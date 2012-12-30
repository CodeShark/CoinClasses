SHELL=/bin/bash

SRC_PATH=../../src

LIBS = \
	-l pthread \
	-l ssl \
	-l crypto \
	-l boost_regex

OBJS = \
	obj/CoinNodeData.o \
	obj/CoinNodeSocket.o

all: listener

$(SRC_PATH)/obj/%.o: $(SRC_PATH)/%.cpp
	$(CXX) -c -o $@ $< \
	-I$(SRC_PATH)

listener: $(OBJS:obj/%=$(SRC_PATH)/obj/%)
	$(CXX) -o $@ listener.cpp $^ \
	-I$(SRC_PATH) \
	$(LIBS)

clean:
	-rm -f listener

clean-all:
	-rm -f listener
	-rm -f $(SRC_PATH)/obj/*.o
