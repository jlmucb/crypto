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

S= $(SRC_DIR)/big_num
O= $(OBJ_DIR)/big_num
S_SUPPORT=$(SRC_DIR)/crypto_support
INCLUDE= -I$(SRC_DIR)/include -I$(S) -I$(S_SUPPORT) -I/usr/local/include

CFLAGS=$(INCLUDE) -O3 -g -Wall -std=c++11
CFLAGS1=$(INCLUDE) -O1 -g -Wall -std=c++11
CC=g++
LINK=g++
PROTO=protoc
AR=ar
LDFLAGS= -lprotobuf -lgtest -lgflags -lpthread

dobj=   $(O)/test_big_num.o $(O)/support.pb.o $(O)/crypto_support.o $(O)/crypto_names.o \
	$(O)/globals.o $(O)/intel_digit_arith.o $(O)/big_num.o $(O)/basic_arith.o $(O)/number_theory.o

all:    test_big_num.exe
clean:
	@echo "removing object files"
	rm $(O)/*.o
	@echo "removing executable file"
	rm $(EXE_DIR)/test_big_num.exe

test_big_num.exe: $(dobj) 
	@echo "linking executable files"
	$(LINK) -o $(EXE_DIR)/test_big_num.exe $(dobj) $(LDFLAGS)

$(S_SUPPORT)/support.pb.cc $(S_SUPPORT)/support.pb.h: $(S_SUPPORT)/support.proto
	$(PROTO) -I=$(S) --cpp_out=$(S_SUPPORT) $(S_SUPPORT)/support.proto

$(O)/test_big_num.o: $(S)/test_big_num.cc
	@echo "compiling test_big_num.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/test_big_num.o $(S)/test_big_num.cc

$(O)/support.pb.o: $(S_SUPPORT)/support.pb.cc $(S_SUPPORT)/support.pb.h
	@echo "compiling support.pb.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/support.pb.o $(S_SUPPORT)/support.pb.cc

$(O)/crypto_support.o: $(S_SUPPORT)/crypto_support.cc $(S_SUPPORT)/support.pb.h
	@echo "compiling crypto_support.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/crypto_support.o $(S_SUPPORT)/crypto_support.cc

$(O)/crypto_names.o: $(S_SUPPORT)/crypto_names.cc
	@echo "compiling crypto_names.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/crypto_names.o $(S_SUPPORT)/crypto_names.cc

$(O)/globals.o: $(S)/globals.cc
	@echo "compiling globals.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/globals.o $(S)/globals.cc

$(O)/intel_digit_arith.o: $(S)/intel_digit_arith.cc
	@echo "compiling intel_digit_arith.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/intel_digit_arith.o $(S)/intel_digit_arith.cc

$(O)/basic_arith.o: $(S)/basic_arith.cc
	@echo "compiling basic_arith.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/basic_arith.o $(S)/basic_arith.cc

$(O)/number_theory.o: $(S)/number_theory.cc
	@echo "compiling number_theory.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/number_theory.o $(S)/number_theory.cc

$(O)/big_num.o: $(S)/big_num.cc
	@echo "compiling big_num.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/big_num.o $(S)/big_num.cc
