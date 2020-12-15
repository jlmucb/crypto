B=          ~/cryptobin
O=          ~/cryptoobj/experimental_crypto
S=          .

CC=         g++
LINK=       g++
CFLAGS=     "-D JLMUNIX"

dobjs=      $(B)/Feal4.o 

all: $(B)/Feal4.exe
$(B)/Feal4.exe: $(dobjs)
	@echo "feal4.exe"
	$(LINK) -o $(B)/Feal4.exe $(dobjs) 

$(B)/Feal4.o: Feal4.cpp
	@echo "compiling feal4.cpp"
	$(CC) $(CFLAGS) -c -o $(B)/Feal4.o $(S)/Feal4.cpp
