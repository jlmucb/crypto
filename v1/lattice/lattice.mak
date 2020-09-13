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
#    File: symmetric.mak

SRC_DIR=$(HOME)/src/github.com/jlmucb/crypto
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

S= $(SRC_DIR)/lattice
O= $(OBJ_DIR)/lattice
INCLUDE= -I$(SRC_DIR)/include -I$(S) -I$(SRC_DIR)/keys -I/usr/local/include -I$(GOOGLE_INCLUDE)

CFLAGS=$(INCLUDE) -O3 -g -Wall -std=c++11
CFLAGS1=$(INCLUDE) -O1 -g -Wall -std=c++11

include ../OSName
ifdef YOSEMITE
	CC=clang++
	LINK=clang++
	PROTO=protoc
	AR=ar
	LDFLAGS= $(LOCAL_LIB)/libprotobuf.a -L$(LOCAL_LIB) -lgtest -lgflags -lprotobuf -lpthread
else
	CC=g++
	LINK=g++
	PROTO=protoc
	AR=ar
	export LD_LIBRARY_PATH=/usr/local/lib
	LDFLAGS= -lprotobuf -lgtest -lgflags -lpthread
endif

dobj=	$(O)/lattice_test.o $(O)/lattice_support.o $(O)/lwe_lattice.o

all:	lattice_test.exe
clean:
	@echo "removing object files"
	rm $(O)/*.o
	@echo "removing executable file"
	rm $(EXE_DIR)/lattice_test.exe

lattice_test.exe: $(dobj) 
	@echo "linking executable files"
	$(LINK) -o $(EXE_DIR)/lattice_test.exe $(dobj) $(LDFLAGS)

$(O)/lattice_test.o: $(S)/lattice_test.cc
	@echo "compiling lattice_test.cc"
	$(CC) $(CFLAGS) -c -o $(O)/lattice_test.o $(S)/lattice_test.cc

$(O)/lattice_support.o: $(S)/lattice_support.cc
	@echo "compiling lattice_support.cc"
	$(CC) $(CFLAGS) -c -o $(O)/lattice_support.o $(S)/lattice_support.cc

$(O)/lwe_lattice.o: $(S)/lwe_lattice.cc
	@echo "compiling lwe_lattice.cc"
	$(CC) $(CFLAGS) -c -o $(O)/lwe_lattice.o $(S)/lwe_lattice.cc

