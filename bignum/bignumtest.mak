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
#    File: bignumtest.mak


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

S= $(SRC_DIR)/bignum
O= $(OBJ_DIR)/bignum
INCLUDE= -I$(SRC_DIR)/include -I$(S) -I/usr/local/include -I$(GOOGLE_INCLUDE) -I$(SRC_DIR)/keys

CFLAGS=$(INCLUDE) -O3 -g -Wall -std=c++11
CFLAGS1=$(INCLUDE) -O3 -g -Wall -std=c++11

include ../OSName
ifdef YOSEMITE
	CC=clang++
	LINK=clang++
	AR=ar
	LDFLAGS= $(LOCAL_LIB)/libprotobuf.a -L$(LOCAL_LIB) -lgtest -lgflags -lprotobuf -lpthread
else
	CC=g++
	LINK=g++
	AR=ar
	export LD_LIBRARY_PATH=/usr/local/lib
	LDFLAGS= -lprotobuf -lgtest -lgflags -lpthread
endif

dobj=	$(O)/bignumtest.o $(O)/bignum.o $(O)/basic_arith.o $(O)/number_theory.o \
	$(O)/arith64.o $(O)/intel64_arith.o $(O)/globals.o $(O)/util.o $(O)/conversions.o \
	$(O)/smallprimes.o $(O)/ecc.o $(O)/rsa.o $(O)/keys.o $(O)/keys.pb.o 

all:	bignumtest.exe
clean:
	@echo "removing object files"
	rm $(O)/*.o
	@echo "removing executable file"
	rm $(EXE_DIR)/bignumtest.exe

bignumtest.exe: $(dobj) 
	@echo "linking executable files"
	$(LINK) -o $(EXE_DIR)/bignumtest.exe $(dobj) $(LDFLAGS)


$(O)/bignumtest.o: $(S)/bignumtest.cc
	@echo "compiling bignumtest.cc"
	$(CC) $(CFLAGS) -c -o $(O)/bignumtest.o $(S)/bignumtest.cc

$(O)/globals.o: $(S)/globals.cc
	@echo "compiling globals.cc"
	$(CC) $(CFLAGS) -c -o $(O)/globals.o $(S)/globals.cc

$(O)/bignum.o: $(S)/bignum.cc
	@echo "compiling bignum.cc"
	$(CC) $(CFLAGS) -c -o $(O)/bignum.o $(S)/bignum.cc

$(O)/basic_arith.o: $(S)/basic_arith.cc
	@echo "compiling basic_arith.cc"
	$(CC) $(CFLAGS) -c -o $(O)/basic_arith.o $(S)/basic_arith.cc

$(O)/smallprimes.o: $(S)/smallprimes.cc
	@echo "compiling smallprimes.cc"
	$(CC) $(CFLAGS) -c -o $(O)/smallprimes.o $(S)/smallprimes.cc

$(O)/number_theory.o: $(S)/number_theory.cc
	@echo "compiling number_theory.cc"
	$(CC) $(CFLAGS) -c -o $(O)/number_theory.o $(S)/number_theory.cc

$(O)/arith64.o: $(S)/arith64.cc
	@echo "compiling arith64.cc"
	$(CC) $(CFLAGS1) -S -o $(O)/arith64.s $(S)/arith64.cc
	$(CC) $(CFLAGS1) -c -o $(O)/arith64.o $(S)/arith64.cc

$(O)/intel64_arith.o: $(S)/intel64_arith.cc
	@echo "compiling intel64_arith.cc"
	$(CC) $(CFLAGS1) -S -o $(O)/intel64_arith.s $(S)/intel64_arith.cc
	$(CC) $(CFLAGS1) -c -o $(O)/intel64_arith.o $(S)/intel64_arith.cc

$(O)/util.o: $(SRC_DIR)/common/util.cc
	@echo "compiling util.cc"
	$(CC) $(CFLAGS) -c -o $(O)/util.o $(SRC_DIR)/common/util.cc

$(O)/conversions.o: $(SRC_DIR)/common/conversions.cc
	@echo "compiling conversions.cc"
	$(CC) $(CFLAGS) -c -o $(O)/conversions.o $(SRC_DIR)/common/conversions.cc

$(O)/keys.o: $(SRC_DIR)/keys/keys.cc $(SRC_DIR)/keys/keys.pb.h
	@echo "compiling keys.cc"
	$(CC) $(CFLAGS) -I$(SRC_DIR)/keys -c -o $(O)/keys.o $(SRC_DIR)/keys/keys.cc

$(O)/keys.pb.o: $(SRC_DIR)/keys/keys.pb.cc
	@echo "compiling keys.pb.cc"
	$(CC) $(CFLAGS) -I$(SRC_DIR)/keys -c -o $(O)/keys.pb.o $(SRC_DIR)/keys/keys.pb.cc

$(O)/ecc.o: $(SRC_DIR)/ecc/ecc.cc
	@echo "compiling ecc.cc"
	$(CC) $(CFLAGS) -I$(SRC_DIR)/keys -c -o $(O)/ecc.o $(SRC_DIR)/ecc/ecc.cc

$(O)/rsa.o: $(SRC_DIR)/rsa/rsa.cc
	@echo "compiling rsa.cc"
	$(CC) $(CFLAGS) -I$(SRC_DIR)/keys -c -o $(O)/rsa.o $(SRC_DIR)/rsa/rsa.cc

