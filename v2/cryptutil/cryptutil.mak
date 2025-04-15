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
#    File: cryptutil.mak

SRC_DIR=$(HOME)/src/github.com/jlmucb/crypto/v2
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
NEWPROTOBUF=1

S= $(SRC_DIR)/cryptutil
S_SUPPORT=$(SRC_DIR)/crypto_support
S_BIGNUM=$(SRC_DIR)/big_num
S_HASH=$(SRC_DIR)/hash
S_SYMMETRIC=$(SRC_DIR)/symmetric
S_LATTICES=$(SRC_DIR)/lattices
S_RSA=$(SRC_DIR)/rsa
S_ECC=$(SRC_DIR)/ecc
S_ENCRYPTION_SCHEME=$(SRC_DIR)/encryption_scheme
S_MISC=$(SRC_DIR)/misc
O= $(OBJ_DIR)/cryptutil
INCLUDE= -I$(SRC_DIR)/include -I$(S) -I$(S_SUPPORT) -I/usr/local/include

ifndef NEWPROTOBUF
CFLAGS=$(INCLUDE) -O3 -g -Wall -std=c++11
CFLAGS1=$(INCLUDE) -O3 -g -Wall -std=c++11
LDFLAGS= -lprotobuf -lgtest -lgflags -lpthread
else
CFLAGS=$(INCLUDE) -O3 -g -Wall -std=c++17
CFLAGS1=$(INCLUDE) -O3 -g -Wall -std=c++17
export LD_LIBRARY_PATH=/usr/local/lib
LDFLAGS= -L/usr/local/lib `pkg-config --cflags --libs protobuf` -lgtest -lgflags -lpthread
endif

CC=g++
LINK=g++

CRYPTOLIB= $(OBJ_DIR)/jlmcryptolib.a


dobj=	$(O)/cryptutil.o 

all:	cryptutil.exe
clean:
	@echo "removing object files"
	rm $(O)/*.o
	@echo "removing executable file"
	rm $(EXE_DIR)/cryptutil.exe

$(O)/cryptutil.o: $(S)/cryptutil.cc
	@echo "compiling cryptutil.cc"
	$(CC) $(CFLAGS) -c -o $(O)/cryptutil.o $(S)/cryptutil.cc

cryptutil.exe: $(dobj) 
	@echo "linking executable files"
	$(LINK) -o $(EXE_DIR)/cryptutil.exe $(dobj) $(CRYPTOLIB) $(LDFLAGS)

$(O)/cryptutil.o: $(S)/cryptutil.cc
	@echo "compiling cryptutil.cc"
	$(CC) $(CFLAGS) -c -o $(O)/cryptutil.o $(S)/cryptutil.cc


