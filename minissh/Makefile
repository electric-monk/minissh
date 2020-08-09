AR = ar
LD =gcc 
CFLAGS = -O3 -std=c++17 -ILibrary
LFLAGS = -LLibrary -L. -lstdc++

UTIL_OBJS = TestNetwork.o TestRandom.o TestUtils.o
SERVER_OBJS = server.o
CLIENT_OBJS = main.o

SERVER_SRC = $(patsubst %.o,%.cpp,$(SERVER_OBJS))
CLIENT_SRC = $(patsubst %.o,%.cpp,$(CLIENT_OBJS))
UTIL_SRC = $(patsubst %.o,%.cpp,$(UTIL_OBJS))

all: libutils.a minissh miniserver

%.o: %.cpp
	$(CXX) $(CFLAGS) -c $< -o $@

libutils.a: $(UTIL_OBJS)
	$(AR) rcs $@ $^

minissh: $(CLIENT_OBJS)
	$(LD) $(LFLAGS) -o $@ $^ -lminissh -lutils

miniserver: $(SERVER_OBJS)
	$(LD) $(LFLAGS) -o $@ $^ -lminissh -lutils

clean:
	rm minissh miniserver *.o

depend: .depend
.depend: $(SERVER_SRC) $(CLIENT_SRC) $(UTIL_SRC)
	rm -rf ./.depend
	$(CC) $(CFLAGS) -MM $^ > ./.depend
include .depend

