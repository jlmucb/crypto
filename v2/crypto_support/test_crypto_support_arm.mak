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
#    File: crypto_support.mak


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
TARGET_MACHINE_TYPE= ARM64
endif

S= $(SRC_DIR)/crypto_support
O= $(OBJ_DIR)/crypto_support
INCLUDE= -I$(SRC_DIR)/include -I$(S) -I/usr/local/include

CFLAGS=$(INCLUDE) -O3 -g -Wall -std=c++11 -Wno-unused-variable -D ARM64
CFLAGS1=$(INCLUDE) -O1 -g -Wall -std=c++11 -Wno-unused-variable -D ARM64
CC=g++
LINK=g++
PROTO=protoc
AR=ar
#export LD_LIBRARY_PATH=/usr/local/lib
LDFLAGS= -lprotobuf -lgtest -lgflags -lpthread

dobj=	$(O)/test_crypto_support.o $(O)/support.pb.o $(O)/crypto_support.o $(O)/crypto_names.o


all:	test_crypto_support.exe
clean:
	@echo "removing object files"
	rm $(O)/*.o
	@echo "removing executable file"
	rm $(EXE_DIR)/test_crypto_support.exe

test_crypto_support.exe: $(dobj) 
	@echo "linking executable files"
	$(LINK) -o $(EXE_DIR)/test_crypto_support.exe $(dobj) $(LDFLAGS)

$(S)/support.pb.cc $(S)/support.pb.h: $(S)/support.proto
	$(PROTO) -I=$(S) --cpp_out=$(S) $(S)/support.proto

$(O)/test_crypto_support.o: $(S)/test_crypto_support.cc $(S)/support.pb.h
	@echo "compiling test_crypto_support.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/test_crypto_support.o $(S)/test_crypto_support.cc

$(O)/support.pb.o: $(S)/support.pb.cc $(S)/support.pb.h
	@echo "compiling support.pb.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/support.pb.o $(S)/support.pb.cc

$(O)/crypto_support.o: $(S)/crypto_support.cc $(S)/support.pb.h
	@echo "compiling crypto_support.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/crypto_support.o $(S)/crypto_support.cc

$(O)/crypto_names.o: $(S)/crypto_names.cc
	@echo "compiling crypto_names.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/crypto_names.o $(S)/crypto_names.cc
