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
SRC_DIR=$(HOME)/src/github.com/jlmucb/crypto/v2
endif
ifndef OBJ_DIR
OBJ_DIR=$(HOME)/cryptoobj/v2
endif
ifndef EXE_DIR
EXE_DIR=$(HOME)/cryptobin
endif
ifndef TARGET_MACHINE_TYPE
TARGET_MACHINE_TYPE=arm64
endif

S= $(SRC_DIR)/misc
O= $(OBJ_DIR)/misc

S_SUPPORT=$(SRC_DIR)/crypto_support
S_HASH=$(SRC_DIR)/hash
S_SYMMETRIC=$(SRC_DIR)/symmetric
S_BIGNUM=$(SRC_DIR)/big_num

ifndef TARGET_MACHINE_TYPE
TARGET_MACHINE_TYPE=arm64
endif

INCLUDE= -I $(SRC_DIR)/include -I $(S_SUPPORT) -I $(S) -I/opt/homebrew/include
CC=clang++
LDFLAGS=-v -L/opt/homebrew/lib `pkg-config --cflags --libs protobuf` -lgtest -lgflags -lpthread
LINK=clang++
CFLAGS=$(INCLUDE) -O3 -g -Wall -std=c++17 -Wno-unused-variable -D ARM64
CFLAGS1=$(INCLUDE) -O1 -g -Wall -std=c++17 -Wno-unused-variable -D ARM64
PROTO=protoc
AR=ar


CRYPTOLIB= $(OBJ_DIR)/jlmcryptolib.a


dobj=	$(O)/pwutil.o $(O)/pwutil.pb.o $(O)/tokenizer.o

all:	pwutil.exe
clean:
	@echo "removing object files"
	rm $(O)/*.o
	@echo "removing executable file"
	rm $(EXE_DIR)/pwutil.exe

pwutil.exe: $(dobj) 
	@echo "linking executable files"
	$(LINK) -o $(EXE_DIR)/pwutil.exe $(dobj) $(CRYPTOLIB) $(LDFLAGS)

$(S)/pwutil.pb.cc $(S)/pwutil.pb.h: $(S)/pwutil.proto
	$(PROTO) -I=$(S) --cpp_out=$(S) $(S)/pwutil.proto

$(O)/pwutil.o: $(S)/pwutil.cc $(S)/pwutil.pb.h
	@echo "compiling pwutil.cc"
	$(CC) $(CFLAGS) -c -o $(O)/pwutil.o $(S)/pwutil.cc

$(O)/pwutil.pb.o: $(S)/pwutil.pb.cc
	@echo "compiling pwutil.pb.cc"
	$(CC) $(CFLAGS) -c -o $(O)/pwutil.pb.o $(S)/pwutil.pb.cc

$(O)/tokenizer.o: $(S)/tokenizer.cc $(S)/tokenizer.h
	@echo "compiling tokenizer.cc"
	$(CC) $(CFLAGS) -c -o $(O)/tokenizer.o $(S)/tokenizer.cc

