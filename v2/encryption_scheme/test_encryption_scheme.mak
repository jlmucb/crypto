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
#    File: test_encryption_scheme.mak


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
NEWPROTOBUF=1

S= $(SRC_DIR)/encryption_scheme
O= $(OBJ_DIR)/encryption_scheme
S_SUPPORT=$(SRC_DIR)/crypto_support
S_HASH=$(SRC_DIR)/hash
S_SYMMETRIC=$(SRC_DIR)/symmetric
S_BIGNUM=$(SRC_DIR)/big_num

INCLUDE= -I$(SRC_DIR)/include -I$(S) -I$(S_SUPPORT) -I/usr/local/include

ifndef NEWPROTOBUF
CFLAGS=$(INCLUDE) -O3 -g -Wall -std=c++11 -Wno-unused-variable
CFLAGS1=$(INCLUDE) -O1 -g -Wall -std=c++11 -Wno-unused-variable
else
CFLAGS=$(INCLUDE) -O3 -g -Wall -std=c++17 -Wno-unused-variable
CFLAGS1=$(INCLUDE) -O1 -g -Wall -std=c++17 -Wno-unused-variable
endif

CC=g++
LINK=g++
PROTO=protoc
AR=ar

ifndef NEWPROTOBUF
LDFLAGS= -lprotobuf -lgtest -lgflags -lpthread
else
export LD_LIBRARY_PATH=/usr/local/lib
LDFLAGS= -L/usr/local/lib `pkg-config --cflags --libs protobuf` -lgtest -lgflags -lpthread
endif

dobj=   $(O)/test_encryption_scheme.o $(O)/support.pb.o $(O)/crypto_support.o $(O)/crypto_names.o \
	$(O)/symmetric_cipher.o $(O)/aes.o $(O)/twofish.o $(O)/hash.o $(O)/sha256.o \
	$(O)/hmac_sha256.o $(O)/aesni.o $(O)/encryption_scheme.o $(O)/globals.o $(O)/intel_digit_arith.o \
	$(O)/big_num.o $(O)/basic_arith.o $(O)/number_theory.o

all:    test_encryption_scheme.exe
clean:
	@echo "removing object files"
	rm $(O)/*.o
	@echo "removing executable file"
	rm $(EXE_DIR)/test_encryption_scheme.exe

test_encryption_scheme.exe: $(dobj) 
	@echo "linking executable files"
	$(LINK) -o $(EXE_DIR)/test_encryption_scheme.exe $(dobj) $(LDFLAGS)

$(S_SUPPORT)/support.pb.cc $(S_SUPPORT)/support.pb.h: $(S_SUPPORT)/support.proto
	$(PROTO) -I=$(S) --cpp_out=$(S_SUPPORT) $(S_SUPPORT)/support.proto

$(O)/test_encryption_scheme.o: $(S)/test_encryption_scheme.cc
	@echo "compiling test_encryption_scheme.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/test_encryption_scheme.o $(S)/test_encryption_scheme.cc

$(O)/encryption_scheme.o: $(S)/encryption_scheme.cc
	@echo "compiling encryption_scheme.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/encryption_scheme.o $(S)/encryption_scheme.cc

$(O)/support.pb.o: $(S_SUPPORT)/support.pb.cc $(S_SUPPORT)/support.pb.h
	@echo "compiling support.pb.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/support.pb.o $(S_SUPPORT)/support.pb.cc

$(O)/crypto_support.o: $(S_SUPPORT)/crypto_support.cc $(S_SUPPORT)/support.pb.h
	@echo "compiling crypto_support.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/crypto_support.o $(S_SUPPORT)/crypto_support.cc

$(O)/crypto_names.o: $(S_SUPPORT)/crypto_names.cc
	@echo "compiling crypto_names.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/crypto_names.o $(S_SUPPORT)/crypto_names.cc

$(O)/symmetric_cipher.o: $(S_SYMMETRIC)/symmetric_cipher.cc
	@echo "compiling symmetric_cipher.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/symmetric_cipher.o $(S_SYMMETRIC)/symmetric_cipher.cc

$(O)/aes.o: $(S_SYMMETRIC)/aes.cc
	@echo "compiling aes.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/aes.o $(S_SYMMETRIC)/aes.cc

$(O)/twofish.o: $(S_SYMMETRIC)/twofish.cc
	@echo "compiling twofish.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/twofish.o $(S_SYMMETRIC)/twofish.cc

$(O)/aesni.o: $(S_SYMMETRIC)/aesni.cc
	@echo "compiling aesni.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/aesni.o $(S_SYMMETRIC)/aesni.cc

$(O)/hash.o: $(S_HASH)/hash.cc
	@echo "compiling hash.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/hash.o $(S_HASH)/hash.cc

$(O)/sha256.o: $(S_HASH)/sha256.cc
	@echo "compiling sha256.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/sha256.o $(S_HASH)/sha256.cc

$(O)/hmac_sha256.o: $(S_HASH)/hmac_sha256.cc
	@echo "compiling hmac_sha256.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/hmac_sha256.o $(S_HASH)/hmac_sha256.cc

$(O)/globals.o: $(S_BIGNUM)/globals.cc
	@echo "compiling globals.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/globals.o $(S_BIGNUM)/globals.cc

$(O)/intel_digit_arith.o: $(S_BIGNUM)/intel_digit_arith.cc
	@echo "compiling intel_digit_arith.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/intel_digit_arith.o $(S_BIGNUM)/intel_digit_arith.cc

$(O)/basic_arith.o: $(S_BIGNUM)/basic_arith.cc
	@echo "compiling basic_arith.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/basic_arith.o $(S_BIGNUM)/basic_arith.cc

$(O)/number_theory.o: $(S_BIGNUM)/number_theory.cc
	@echo "compiling number_theory.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/number_theory.o $(S_BIGNUM)/number_theory.cc

$(O)/big_num.o: $(S_BIGNUM)/big_num.cc
	@echo "compiling big_num.cc"
	$(CC) $(CFLAGS) -c $(I) -o $(O)/big_num.o $(S_BIGNUM)/big_num.cc
