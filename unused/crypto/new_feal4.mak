B=          ~/cryptobin
O=          ~/cryptoobj/experimental_crypto
S=          .

CC=         g++
LINK=       g++
CFLAGS=     -O1

dobjs=      $(B)/new_feal4.o 

all: $(B)/new_feal4.exe
$(B)/new_feal4.exe: $(dobjs)
	@echo "new_feal4.exe"
	$(LINK) -o $(B)/new_feal4.exe $(dobjs) 

$(B)/new_feal4.o: new_feal4.cc
	@echo "compiling new_feal4.cc"
	$(CC) $(CFLAGS) -c -o $(B)/new_feal4.o $(S)/new_feal4.cc
