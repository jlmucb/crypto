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
#    File: keys.mak


SRC_DIR=$(HOME)/src/github.com/jlmucb/crypto
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

S= $(SRC_DIR)/keys
O= $(OBJ_DIR)/keys
INCLUDE= -I$(SRC_DIR)/include -I$(S) -I/usr/local/include -I$(GOOGLE_INCLUDE)

include ../OSName
ifdef YOSEMITE
	CFLAGS=$(INCLUDE) -O3 -g -Wall -std=c++11 -stdlib=libc++
	CFLAGS1=$(INCLUDE) -O1 -g -Wall -std=c++11 -stdlib=libc++
	CC=clang++
	LINK=clang++
	PROTO=protoc
	AR=ar
	LDFLAGS= $(LOCAL_LIB)/libprotobuf.a -L$(LOCAL_LIB) -lgtest -lgflags -lprotobuf -lpthread
else
	CFLAGS=$(INCLUDE) -O3 -g -Wall -std=c++11
	CFLAGS1=$(INCLUDE) -O1 -g -Wall -std=c++11
	CC=g++
	LINK=g++
	PROTO=protoc
	AR=ar
	export LD_LIBRARY_PATH=/usr/local/lib
	LDFLAGS= -lprotobuf -lgtest -lgflags -lpthread
endif

dobj=	$(O)/keytest.o $(O)/keys.o $(O)/keys.pb.o $(O)/util.o $(O)/conversions.o \
        $(O)/rsa.o $(O)/ecc.o $(O)/bignum.o $(O)/basic_arith.o $(O)/arith64.o \
	$(O)/number_theory.o $(O)/intel64_arith.o $(O)/globals.o  $(O)/smallprimes.o

all:	keytest.exe
clean:
	@echo "removing object files"
	rm $(O)/*.o
	@echo "removing executable file"
	rm $(EXE_DIR)/keytest.exe

keytest.exe: $(dobj) 
	@echo "linking executable files"
	$(LINK) -o $(EXE_DIR)/keytest.exe $(dobj) $(LDFLAGS)

$(S)/keys.pb.cc $(S)/keys.pb.h: $(S)/keys.proto
	$(PROTO) -I=$(S) --cpp_out=$(S) $(S)/keys.proto

$(O)/keytest.o: $(S)/keytest.cc $(S)/keys.pb.h
	@echo "compiling keytest.cc"
	$(CC) $(CFLAGS) -c -o $(O)/keytest.o $(S)/keytest.cc

$(O)/keys.o: $(S)/keys.cc $(S)/keys.pb.h
	@echo "compiling keys.cc"
	$(CC) $(CFLAGS) -c -o $(O)/keys.o $(S)/keys.cc

$(O)/keys.pb.o: $(S)/keys.pb.cc
	@echo "compiling keys.pb.cc"
	$(CC) $(CFLAGS) -c -o $(O)/keys.pb.o $(S)/keys.pb.cc

$(O)/util.o: $(SRC_DIR)/common/util.cc
	@echo "compiling util.cc"
	$(CC) $(CFLAGS) -c -o $(O)/util.o $(SRC_DIR)/common/util.cc

$(O)/conversions.o: $(SRC_DIR)/common/conversions.cc
	@echo "compiling conversions.cc"
	$(CC) $(CFLAGS) -c -o $(O)/conversions.o $(SRC_DIR)/common/conversions.cc

$(O)/rsa.o: $(SRC_DIR)/rsa/rsa.cc
	@echo "compiling rsa.cc"
	$(CC) $(CFLAGS) -c -o $(O)/rsa.o $(SRC_DIR)/rsa/rsa.cc

$(O)/ecc.o: $(SRC_DIR)/ecc/ecc.cc
	@echo "compiling ecc.cc"
	$(CC) $(CFLAGS) -c -o $(O)/ecc.o $(SRC_DIR)/ecc/ecc.cc

$(O)/globals.o: $(SRC_DIR)/bignum/globals.cc
	@echo "compiling globals.cc"
	$(CC) $(CFLAGS) -c -o $(O)/globals.o $(SRC_DIR)/bignum/globals.cc

$(O)/bignum.o: $(SRC_DIR)/bignum/bignum.cc
	@echo "compiling bignum.cc"
	$(CC) $(CFLAGS) -c -o $(O)/bignum.o $(SRC_DIR)/bignum/bignum.cc

$(O)/basic_arith.o: $(SRC_DIR)/bignum/basic_arith.cc
	@echo "compiling basic_arith.cc"
	$(CC) $(CFLAGS) -c -o $(O)/basic_arith.o $(SRC_DIR)/bignum/basic_arith.cc

$(O)/smallprimes.o: $(SRC_DIR)/bignum/smallprimes.cc
	@echo "compiling smallprimes.cc"
	$(CC) $(CFLAGS) -c -o $(O)/smallprimes.o $(SRC_DIR)/bignum/smallprimes.cc

$(O)/number_theory.o: $(SRC_DIR)/bignum/number_theory.cc
	@echo "compiling number_theory.cc"
	$(CC) $(CFLAGS) -c -o $(O)/number_theory.o $(SRC_DIR)/bignum/number_theory.cc

$(O)/arith64.o: $(SRC_DIR)/bignum/arith64.cc
	@echo "compiling arith64.cc"
	$(CC) $(CFLAGS1) -c -o $(O)/arith64.o $(SRC_DIR)/bignum/arith64.cc

$(O)/intel64_arith.o: $(SRC_DIR)/bignum/intel64_arith.cc
	@echo "compiling intel64_arith.cc"
	$(CC) $(CFLAGS1) -c -o $(O)/intel64_arith.o $(SRC_DIR)/bignum/intel64_arith.cc

