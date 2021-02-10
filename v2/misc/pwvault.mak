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
#    File: pwutil.mak


ifndef SRC_DIR
SRC_DIR=$(HOME)/crypto/v2
endif
ifndef OBJ_DIR
OBJ_DIR=$(HOME)/cryptoobj/v2
endif
ifndef EXE_DIR
EXE_DIR=$(HOME)/cryptobin
endif
ifndef GOOGLE_INCLUDE
GOOGLE_INCLUDE=/usr/local/include/google
endif
ifndef LOCAL_LIB
LOCAL_LIB=/usr/local/lib
endif
ifndef TARGET_MACHINE_TYPE
TARGET_MACHINE_TYPE= x64
endif

#ifndef SRC_DIR
SRC_DIR=$(HOME)/src/github.com/jlmucb/crypto/v2
#endif
#ifndef OBJ_DIR
OBJ_DIR=$(HOME)/cryptoobj/v2
#endif

S= $(SRC_DIR)/misc
O= $(OBJ_DIR)/misc
INCLUDE= -I$(SRC_DIR)/include -I$(S) -I$(S_SUPPORT) -I/usr/local/include
S_SUPPORT=$(SRC_DIR)/crypto_support
S_HASH=$(SRC_DIR)/hash

CC=g++
LINK=g++
CFLAGS=$(INCLUDE) -O3 -g -Wall -std=c++11 -Wno-unused-variable
CFLAGS1=$(INCLUDE) -O1 -g -Wall -std=c++11 -Wno-unused-variable
PROTO=protoc
AR=ar
LDFLAGS= -lprotobuf -lgtest -lgflags -lpthread

dobj=	$(O)/pwvault.o $(O)/support.pb.o $(O)/crypto_support.o $(O)/sha256.o \
	$(O)/hash.o $(O)/hmac_sha256.o $(O)/pbkdf2.o

all:	pwvault.exe
clean:
	@echo "removing object files"
	rm $(O)/*.o
	@echo "removing executable file"
	rm $(EXE_DIR)/pwvault.exe

pwvault.exe: $(dobj) 
	@echo "linking executable files"
	$(LINK) -o $(EXE_DIR)/pwvault.exe $(dobj) $(LDFLAGS)

$(O)/pwvault.o: $(S)/pwvault.cc
	@echo "compiling pwvault.cc"
	$(CC) $(CFLAGS) -c -o $(O)/pwvault.o $(S)/pwvault.cc

$(O)/support.pb.o: $(S_SUPPORT)/support.pb.cc $(S_SUPPORT)/support.pb.h
	@echo "compiling support.pb.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/support.pb.o $(S_SUPPORT)/support.pb.cc

$(O)/crypto_support.o: $(S_SUPPORT)/crypto_support.cc $(S_SUPPORT)/support.pb.h
	@echo "compiling crypto_support.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/crypto_support.o $(S_SUPPORT)/crypto_support.cc

$(O)/hash.o: $(S_HASH)/hash.cc
	@echo "compiling hash.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/hash.o $(S_HASH)/hash.cc

$(O)/sha256.o: $(S_HASH)/sha256.cc
	@echo "compiling sha256.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/sha256.o $(S_HASH)/sha256.cc

$(O)/hmac_sha256.o: $(S_HASH)/hmac_sha256.cc
	@echo "compiling hmac_sha256.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/hmac_sha256.o $(S_HASH)/hmac_sha256.cc

$(O)/pbkdf2.o: $(S_HASH)/pbkdf2.cc
	@echo "compiling pbkdf2.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/pbkdf2.o $(S_HASH)/pbkdf2.cc
