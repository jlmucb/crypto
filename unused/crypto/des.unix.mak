HOME=	/Users/jlm
BIN=	$(HOME)/jlmcrypt
CFLAGS=	"-D JLMUNIX"

CC=	g++

all: des4.exe des5.exe des6.exe des8.exe

des4.exe: des4.cpp
	@echo "des4"
	$(CC) $(CFLAGS) $(LINKFLAGS) -o $(BIN)/des4.exe des4.cpp

des5.exe: des5.cpp
	@echo "des5"
	$(CC) $(CFLAGS) $(LINKFLAGS) -o $(BIN)/des5.exe des5.cpp

des6.exe: des6.cpp BigCount.cpp
	@echo "des6"
	$(CC) $(CFLAGS) $(LINKFLAGS) -o $(BIN)/des6.exe des6.cpp BigCount.cpp

des8.exe: des8.cpp BigCount.cpp
	@echo "des8"
	$(CC) $(CFLAGS) $(LINKFLAGS) -o $(BIN)/des8.exe des8.cpp BigCount.cpp

