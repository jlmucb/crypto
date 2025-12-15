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
#    File: splitsecret.mak

SRC_DIR=$(HOME)/src/github.com/jlmucb/crypto/v2
#ifndef OBJ_DIR
OBJ_DIR=$(HOME)/cryptoobj/v2
#endif
#ifndef EXE_DIR
EXE_DIR=$(HOME)/cryptobin
#endif

S= $(SRC_DIR)/misc
O= $(OBJ_DIR)/misc
S_SUPPORT=$(SRC_DIR)/crypto_support
S_HASH=$(SRC_DIR)/hash
S_SYMMETRIC=$(SRC_DIR)/symmetric
S_BIGNUM=$(SRC_DIR)/big_num

ifndef TARGET_MACHINE_TYPE
TARGET_MACHINE_TYPE=arm64
endif

INCLUDE= -I $(SRC_DIR)/include -I $(S_SUPPORT) -I $(S) -I $(S)/keys -I/opt/homebrew/include
CC=clang++
LDFLAGS=-v -L/opt/homebrew/lib `pkg-config --cflags --libs protobuf` -lgtest -lgflags -lpthread
LINK=clang++
CFLAGS=$(INCLUDE) -O3 -g -Wall -std=c++17 -Wno-unused-variable -D ARM64
CFLAGS1=$(INCLUDE) -O1 -g -Wall -std=c++17 -Wno-unused-variable -D ARM64
PROTO=protoc
AR=ar

dobj_gf2_common_test=$(O)/gf2_common.o $(O)/gf2_common_test.o $(O)/splitsecret.pb.o
dobj_splitsecret=$(O)/gf2_common.o $(O)/splitsecret.pb.o $(O)/splitsecret.o

all:	$(EXE_DIR)/splitsecret.exe
clean:
	@echo "removing object files"
	rm $(O)/*.o
	@echo "removing executable file"
	rm $(EXE_DIR)/gf2_common_test.exe

$(EXE_DIR)/gf2_common_test.exe: $(dobj_gf2_common_test) 
	@echo "linking executable files"
	$(LINK) -o $(EXE_DIR)/gf2_common_test.exe $(dobj_gf2_common_test) $(LDFLAGS)

$(EXE_DIR)/splitsecret.exe: $(dobj_splitsecret) 
	@echo "linking executable files"
	$(LINK) -o $(EXE_DIR)/splitsecret.exe $(dobj_splitsecret) $(LDFLAGS)

$(O)/gf2_common.o: $(S)/gf2_common.cc $(S)/splitsecret.pb.h
	@echo "compiling gf2_common.cc"
	$(CC) $(CFLAGS) -c -o $(O)/gf2_common.o $(S)/gf2_common.cc

$(O)/gf2_common_test.o: $(S)/gf2_common_test.cc  $(S)/splitsecret.pb.h
	@echo "compiling gf2_common_test.cc"
	$(CC) $(CFLAGS) -c -o $(O)/gf2_common_test.o $(S)/gf2_common_test.cc

$(S)/splitsecret.pb.cc $(S)/splitsecret.pb.h : $(S)/splitsecret.proto
	echo "$(PROTO) -I=$(S) --cpp_out=$(S) $(S)/splitsecret.proto"
	$(PROTO) -I=$(S) --cpp_out=$(S) $(S)/splitsecret.proto

$(O)/splitsecret.pb.o: $(S)/splitsecret.pb.cc
	@echo "compiling splitsecret.pb.cc"
	$(CC) $(CFLAGS) -c -o $(O)/splitsecret.pb.o $(S)/splitsecret.pb.cc

$(O)/splitsecret.o: $(S)/splitsecret.cc  $(S)/splitsecret.pb.h
	@echo "compiling splitsecret.cc"
	$(CC) $(CFLAGS) -c -o $(O)/splitsecret.o $(S)/splitsecret.cc

