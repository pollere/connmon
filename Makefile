# should only need to change LIBTINS to the libtins install prefix
# (typically /usr/local unless overridden when tins built)
LIBTINS = $(HOME)/src/libtins
CPPFLAGS += -I$(LIBTINS)/include
LDFLAGS += -L$(LIBTINS)/lib -ltins -lpcap
CXXFLAGS += -std=c++14 -g -O3 -Wall

connmon:  connmon.cpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -o connmon connmon.cpp $(LDFLAGS)

clean:
	rm connmon
