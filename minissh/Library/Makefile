AR = ar
CFLAGS = -O3 -std=c++17

OBJS = AES.o Connection.o Hash.o Primes.o SSH_RSA.o SshNumbers.o sha1.o Base64.o DerFile.o KeyFile.o RSA.o Server.o Transport.o BlumBlumShub.o DiffieHellman.o Maths.o SSH_AES.o Session.o Types.o Client.o Encryption.o Operations.o SSH_HMAC.o SshAuth.o hmac.o

SRC = $(patsubst %.o,%.cpp,$(OBJS))

%.o: %.cpp
	$(CXX) $(CFLAGS) -c $< -o $@
libminissh.a: $(OBJS)
	$(AR) rcs $@ $^
clean:
	rm *.o *.a

depend: .depend
.depend: $(SRC)
	rm -rf ./.depend
	$(CC) $(CFLAGS) -MM $^ > ./.depend
include .depend

