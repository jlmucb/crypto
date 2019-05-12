#
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
#    Project: New Cloudproxy Crypto
#    File: cryptutil.mak

SRC_DIR=$(HOME)/crypto
ifndef SRC_DIR
SRC_DIR=$(HOME)/crypto
endif
ifndef OBJ_DIR
OBJ_DIR=$(HOME)/cryptoobj
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

S= $(SRC_DIR)/cryptutil
O= $(OBJ_DIR)/cryptutil
LO= $(OBJ_DIR)/cryptolib
INCLUDE= -I$(SRC_DIR)/include -I$(S) -I/usr/local/include -I$(GOOGLE_INCLUDE) -I$(SRC_DIR)/keys

CFLAGS=$(INCLUDE) -O3 -g -Wall -std=c++11
CFLAGS1=$(INCLUDE) -O3 -g -Wall -std=c++11

lobj=   $(LO)/bignum.o $(LO)/basic_arith.o $(LO)/number_theory.o $(LO)/arith64.o \
        $(LO)/intel64_arith.o $(LO)/globals.o $(LO)/util.o $(LO)/conversions.o \
        $(LO)/smallprimes.o $(LO)/ecc.o $(LO)/rsa.o $(LO)/keys.o $(LO)/keys.pb.o \
        $(LO)/symmetric_cipher.o $(LO)/aes.o $(LO)/sha1.o $(LO)/sha256.o \
        $(LO)/aesni.o $(LO)/hash.o $(LO)/hmac_sha256.o $(LO)/sha3.o $(LO)/twofish.o \
        $(LO)/encryption_algorithm.o $(LO)/aescbchmac256sympad.o \
        $(LO)/aesgcm.o $(LO)/aesctrhmac256sympad.o $(LO)/pkcs.o $(LO)/pbkdf2.o \
        $(LO)/ghash.o $(LO)/simonspeck.o $(LO)/rc4.o $(LO)/tea.o

include ../OSName
ifdef YOSEMITE
	CC=clang++
	LINK=clang++
	LDFLAGS= -L$(LOCAL_LIB) -lgtest -lgflags -lprotobuf -lpthread
else
	CC=g++
	LINK=g++
	export LD_LIBRARY_PATH=/usr/local/lib
	LDFLAGS= -lprotobuf -lgtest -lgflags -lpthread
endif


dobj=	$(O)/cryptutil.o 

all:	cryptutil.exe
clean:
	@echo "removing object files"
	rm $(O)/*.o
	@echo "removing executable file"
	rm $(EXE_DIR)/cryptutil.exe

cryptutil.exe: $(dobj) 
	@echo "linking executable files"
	$(LINK) -o $(EXE_DIR)/cryptutil.exe $(lobj) $(dobj) $(LDFLAGS)

$(O)/cryptutil.o: $(S)/cryptutil.cc
	@echo "compiling cryptutil.cc"
	$(CC) $(CFLAGS) -c -o $(O)/cryptutil.o $(S)/cryptutil.cc


