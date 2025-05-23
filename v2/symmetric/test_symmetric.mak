#    Copyright 2014 John Manferdelli, All Rights Reserved.
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#        http://www.apache.org/licenses/LICENSE-2.0
#    or in the the file LICENSE-2.0.txt in the top level sourcedirectory
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License
#    File: test_symmetric.mak


ifndef SRC_DIR
SRC_DIR=$(HOME)/src/github.com/jlmucb/crypto/v2
endif
ifndef OBJ_DIR
OBJ_DIR=$(HOME)/cryptoobj/v2
endif
ifndef EXE_DIR
EXE_DIR=$(HOME)/cryptobin
endif
#ifndef GOOGLE_INCLUDE
#GOOGLE_INCLUDE=/usr/local/include/g
#endif
ifndef LOCAL_LIB
LOCAL_LIB=/usr/local/lib
endif
ifndef TARGET_MACHINE_TYPE
TARGET_MACHINE_TYPE= x64
endif

NEWPROTOBUF=1

ifndef NEWPROTOBUF
CFLAGS=$(INCLUDE) -O3 -g -Wall -std=c++11 -Wno-unused-variable -D X64
CFLAGS1=$(INCLUDE) -O1 -g -Wall -std=c++11 -Wno-unused-variable -D X64
LDFLAGS= -lprotobuf -lgtest -lgflags -lpthread
else
CFLAGS=$(INCLUDE) -O3 -g -Wall -std=c++17 -Wno-unused-variable -D X64
CFLAGS1=$(INCLUDE) -O1 -g -Wall -std=c++17 -Wno-unused-variable -D X64
export LD_LIBRARY_PATH=/usr/local/lib
LDFLAGS= -L/usr/local/lib `pkg-config --cflags --libs protobuf` -lgtest -lgflags -lpthread
endif

S= $(SRC_DIR)/symmetric
O= $(OBJ_DIR)/symmetric
S_SUPPORT=$(SRC_DIR)/crypto_support
INCLUDE= -I$(SRC_DIR)/include -I$(S) -I$(S_SUPPORT) -I/usr/local/include
CC=g++
LINK=g++
PROTO=protoc
AR=ar

dobj=   $(O)/test_symmetric.o $(O)/support.pb.o $(O)/crypto_support.o $(O)/crypto_names.o \
	$(O)/symmetric_cipher.o $(O)/aes.o $(O)/tea.o $(O)/rc4.o $(O)/twofish.o \
	$(O)/simonspeck.o $(O)/aesni.o

all:    test_symmetric.exe
clean:
	@echo "removing object files"
	rm $(O)/*.o
	@echo "removing executable file"
	rm $(EXE_DIR)/test_symmetric.exe

test_symmetric.exe: $(dobj) 
	@echo "linking executable files"
	$(LINK) -o $(EXE_DIR)/test_symmetric.exe $(dobj) $(LDFLAGS)

$(S_SUPPORT)/support.pb.cc $(S_SUPPORT)/support.pb.h: $(S_SUPPORT)/support.proto
	$(PROTO) -I=$(S) --cpp_out=$(S_SUPPORT) $(S_SUPPORT)/support.proto

$(O)/test_symmetric.o: $(S)/test_symmetric.cc
	@echo "compiling test_symmetric.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/test_symmetric.o $(S)/test_symmetric.cc

$(O)/support.pb.o: $(S_SUPPORT)/support.pb.cc $(S_SUPPORT)/support.pb.h
	@echo "compiling support.pb.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/support.pb.o $(S_SUPPORT)/support.pb.cc

$(O)/crypto_support.o: $(S_SUPPORT)/crypto_support.cc $(S_SUPPORT)/support.pb.h
	@echo "compiling crypto_support.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/crypto_support.o $(S_SUPPORT)/crypto_support.cc

$(O)/crypto_names.o: $(S_SUPPORT)/crypto_names.cc
	@echo "compiling crypto_names.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/crypto_names.o $(S_SUPPORT)/crypto_names.cc

$(O)/symmetric_cipher.o: $(S)/symmetric_cipher.cc
	@echo "compiling symmetric_cipher.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/symmetric_cipher.o $(S)/symmetric_cipher.cc

$(O)/aes.o: $(S)/aes.cc
	@echo "compiling aes.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/aes.o $(S)/aes.cc

$(O)/tea.o: $(S)/tea.cc
	@echo "compiling tea.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/tea.o $(S)/tea.cc

$(O)/rc4.o: $(S)/rc4.cc
	@echo "compiling rc4.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/rc4.o $(S)/rc4.cc

$(O)/twofish.o: $(S)/twofish.cc
	@echo "compiling twofish.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/twofish.o $(S)/twofish.cc

$(O)/simonspeck.o: $(S)/simonspeck.cc
	@echo "compiling simonspeck.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/simonspeck.o $(S)/simonspeck.cc

$(O)/aesni.o: $(S)/aesni.cc
	@echo "compiling aesni.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/aesni.o $(S)/aesni.cc
