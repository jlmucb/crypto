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
#    File: indeterminate.mak

#ifndef SRC_DIR
SRC_DIR=$(HOME)/crypto
#endif
#ifndef OBJ_DIR
OBJ_DIR=$(HOME)/cryptoobj
#endif
#ifndef EXE_DIR
EXE_DIR=$(HOME)/cryptobin
#endif
#ifndef GOOGLE_INCLUDE
GOOGLE_INCLUDE=/usr/local/include/google
#endif
#ifndef LOCAL_LIB
LOCAL_LIB=/usr/local/lib
#endif
#ifndef TARGET_MACHINE_TYPE
TARGET_MACHINE_TYPE= x64
#endif

S= $(SRC_DIR)/indeterminate
O= $(OBJ_DIR)/indeterminate
INCLUDE= -I$(SRC_DIR)/include -I$(S) -I$(SRC_DIR)/keys -I/usr/local/include -I$(GOOGLE_INCLUDE)

CFLAGS=$(INCLUDE) -O3 -g -Wall -std=c++11
CFLAGS1=$(INCLUDE) -O1 -g -Wall -std=c++11

include ../OSName
ifdef YOSEMITE
	LDFLAGS= $(LOCAL_LIB)/libprotobuf.a -L$(LOCAL_LIB) -lgtest -lgflags -lprotobuf -lpthread
else
	LDFLAGS= $(LOCAL_LIB)/libgtest.a  $(LOCAL_LIB)/libprotobuf.a $(LOCAL_LIB)/libgflags.a -lpthread
endif
ifdef YOSEMITE
	CC=clang++
	LINK=clang++
	AR=ar
else
	CC=g++
	LINK=g++
	AR=ar
endif

dobj=	$(O)/polynomial.o $(O)/rational.o $(O)/indeterminatetest.o $(O)/util.o \
	$(O)/bignum.o $(O)/globals.o $(O)/basic_arith.o $(O)/number_theory.o \
	$(O)/intel64_arith.o $(O)/smallprimes.o $(O)/conversions.o

all:	indeterminatetest.exe
clean:
	@echo "removing object files"
	rm $(O)/*.o
	@echo "removing executable file"
	rm $(EXE_DIR)/indeterminatetest.exe

indeterminatetest.exe: $(dobj) 
	@echo "linking executable files"
	$(LINK) -o $(EXE_DIR)/indeterminatetest.exe $(dobj) $(LDFLAGS)

$(O)/indeterminatetest.o: $(S)/indeterminatetest.cc
	@echo "compiling indeterminatetest.cc"
	$(CC) $(CFLAGS) -c -o $(O)/indeterminatetest.o $(S)/indeterminatetest.cc

$(O)/util.o: $(SRC_DIR)/common/util.cc
	@echo "compiling util.cc"
	$(CC) $(CFLAGS) -c -o $(O)/util.o $(SRC_DIR)/common/util.cc

$(O)/conversions.o: $(SRC_DIR)/common/conversions.cc
	@echo "compiling conversions.cc"
	$(CC) $(CFLAGS) -c -o $(O)/conversions.o $(SRC_DIR)/common/conversions.cc

$(O)/polynomial.o: $(S)/polynomial.cc
	@echo "compiling polynomial.cc"
	$(CC) $(CFLAGS) -c -o $(O)/polynomial.o $(S)/polynomial.cc

$(O)/rational.o: $(S)/rational.cc
	@echo "compiling rational.cc"
	$(CC) $(CFLAGS) -c -o $(O)/rational.o $(S)/rational.cc

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

$(O)/intel64_arith.o: $(SRC_DIR)/bignum/intel64_arith.cc
	@echo "compiling intel64_arith.cc"
	$(CC) $(CFLAGS1) -c -o $(O)/intel64_arith.o $(SRC_DIR)/bignum/intel64_arith.cc

