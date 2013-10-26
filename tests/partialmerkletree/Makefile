CXX = g++
CXXFLAGS = -std=c++0x -Wall -g

SRCDIR = ../../src
INCPATH = -I$(SRCDIR)

LIBS = \
    -lcrypto \
    -lboost_regex

OBJ = \
    $(SRCDIR)/obj/CoinNodeData.o \
    $(SRCDIR)/obj/IPv6.o

build/partialmerkletree: main.cpp $(OBJ)
	$(CXX) $(CXXFLAGS)  -o $@ $< $(OBJ) $(INCPATH) $(LIBS)

$(SRCDIR)/obj/%.o: $(SRCDIR)/%.cpp $(SRCDIR)/%.h
	$(CXX) $(CXXFLAGS) -o $@ -c $< $(INCPATH)


clean:
	-rm -rf build/*

clean-all:
	-rm -rf build/* $(OBJ)
