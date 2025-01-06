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
#    File: cryptolib.mak


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

O= $(OBJ_DIR)/cryptolib
INCLUDE= -I$(SRC_DIR)/include -I/usr/local/include -I$(SRC_DIR)/crypto_support -I$(GOOGLE_INCLUDE) 

ifndef NEWPROTOBUF
CFLAGS=$(INCLUDE) -O3 -g -Wall -std=c++11
CFLAGS1=$(INCLUDE) -O1 -g -Wall -std=c++11
else
CFLAGS=$(INCLUDE) -O3 -g -Wall -std=c++17
CFLAGS1=$(INCLUDE) -O1 -g -Wall -std=c++17
endif

CC=g++
LINK=g++

ifndef NEWPROTOBUF
LDFLAGS=  #$(LOCAL_LIB)/libprotobuf.a -L$(LOCAL_LIB) -lgtest -lgflags -lprotobuf -lpthread
else
endif

dobj=	$(O)/big_num.o $(O)/basic_arith.o $(O)/number_theory.o \
	$(O)/intel_digit_arith.o $(O)/globals.o $(O)/rc4.o \
	$(O)/ecc.o $(O)/rsa.o $(O)/crypto_support.o $(O)/tea.o \
	$(O)/symmetric_cipher.o $(O)/aes.o $(O)/simonspeck.o $(O)/sha1.o \
	$(O)/aesni.o $(O)/hash.o $(O)/hmac_sha256.o $(O)/sha3.o $(O)/twofish.o \
	$(O)/encryption_scheme.o $(O)/sha256.o 

all:	$(OBJ_DIR)/jlmcryptolib.a
clean:
	@echo "removing object files"
	rm $(O)/*.o
	@echo "removing library file"
	rm $(OBJ_DIR)/jlmcryptolib.a

AR=ar
PROTO=protoc

$(OBJ_DIR)/jlmcryptolib.a: $(dobj) 
	@echo "linking library"
	$(AR) -r $(OBJ_DIR)/jlmcryptolib.a $(dobj) $(LDFLAGS)

$(SRC_DIR)/crypto_support/support.pb.cc $(SRC_DIR)/crypto_support/support.pb.h: $(SRC_DIR)/crypto_support/support.proto
	$(PROTO) --cpp_out=$(SRC_DIR)/crypto_support $(SRC_DIR)/crypto_support/support.proto

$(O)/crypto_support.o: $(SRC_DIR)/crypto_support/crypto_support.cc
	@echo "compiling crypto_support.cc"
	$(CC) $(CFLAGS) -c -o $(O)/crypto_support.o $(SRC_DIR)/crypto_support/crypto_support.cc

$(O)/globals.o: $(SRC_DIR)/big_num/globals.cc
	@echo "compiling globals.cc"
	$(CC) $(CFLAGS) -c -o $(O)/globals.o $(SRC_DIR)/big_num/globals.cc

$(O)/big_num.o: $(SRC_DIR)/big_num/big_num.cc
	@echo "compiling big_num.cc"
	$(CC) $(CFLAGS) -c -o $(O)/big_num.o $(SRC_DIR)/big_num/big_num.cc

$(O)/basic_arith.o: $(SRC_DIR)/big_num/basic_arith.cc
	@echo "compiling basic_arith.cc"
	$(CC) $(CFLAGS) -c -o $(O)/basic_arith.o $(SRC_DIR)/big_num/basic_arith.cc

$(O)/number_theory.o: $(SRC_DIR)/big_num/number_theory.cc
	@echo "compiling number_theory.cc"
	$(CC) $(CFLAGS) -c -o $(O)/number_theory.o $(SRC_DIR)/big_num/number_theory.cc

$(O)/intel_digit_arith.o: $(SRC_DIR)/big_num/intel_digit_arith.cc
	@echo "compiling intel_digit_arith.cc"
	$(CC) $(CFLAGS1) -c -o $(O)/intel_digit_arith.o $(SRC_DIR)/big_num/intel_digit_arith.cc

$(O)/ecc.o: $(SRC_DIR)/ecc/ecc.cc
	@echo "compiling ecc.cc"
	$(CC) $(CFLAGS) -c -o $(O)/ecc.o $(SRC_DIR)/ecc/ecc.cc

$(O)/rsa.o: $(SRC_DIR)/rsa/rsa.cc
	@echo "compiling rsa.cc"
	$(CC) $(CFLAGS) -c -o $(O)/rsa.o $(SRC_DIR)/rsa/rsa.cc

$(O)/hash.o: $(SRC_DIR)/hash/hash.cc
	@echo "compiling hash.cc"
	$(CC) $(CFLAGS) -c -o $(O)/hash.o $(SRC_DIR)/hash/hash.cc

$(O)/sha1.o: $(SRC_DIR)/hash/sha1.cc
	@echo "compiling sha1.cc"
	$(CC) $(CFLAGS) -c -o $(O)/sha1.o $(SRC_DIR)/hash/sha1.cc

$(O)/sha256.o: $(SRC_DIR)/hash/sha256.cc
	@echo "compiling sha256.cc"
	$(CC) $(CFLAGS) -c -o $(O)/sha256.o $(SRC_DIR)/hash/sha256.cc

$(O)/sha3.o: $(SRC_DIR)/hash/sha3.cc
	@echo "compiling sha3.cc"
	$(CC) $(CFLAGS) -c -o $(O)/sha3.o $(SRC_DIR)/hash/sha3.cc

$(O)/hmac_sha256.o: $(SRC_DIR)/hash/hmac_sha256.cc
	@echo "compiling hmac_sha256.cc"
	$(CC) $(CFLAGS) -c -o $(O)/hmac_sha256.o $(SRC_DIR)/hash/hmac_sha256.cc

$(O)/pkcs.o: $(SRC_DIR)/hash/pkcs.cc
	@echo "compiling pkcs.cc"
	$(CC) $(CFLAGS) -c -o $(O)/pkcs.o $(SRC_DIR)/hash/pkcs.cc

$(O)/pbkdf2.o: $(SRC_DIR)/hash/pbkdf2.cc
	@echo "compiling pbkdf2.cc"
	$(CC) $(CFLAGS) -c -o $(O)/pbkdf2.o $(SRC_DIR)/hash/pbkdf2.cc

$(O)/symmetric_cipher.o: $(SRC_DIR)/symmetric/symmetric_cipher.cc
	@echo "compiling symmetric_cipher.cc"
	$(CC) $(CFLAGS) -c -o $(O)/symmetric_cipher.o $(SRC_DIR)/symmetric/symmetric_cipher.cc

$(O)/aes.o: $(SRC_DIR)/symmetric/aes.cc
	@echo "compiling aes.cc"
	$(CC) $(CFLAGS) -c -o $(O)/aes.o $(SRC_DIR)/symmetric/aes.cc

$(O)/aesni.o: $(SRC_DIR)/symmetric/aesni.cc
	@echo "compiling aesni.cc"
	$(CC) $(CFLAGS) -c -o $(O)/aesni.o $(SRC_DIR)/symmetric/aesni.cc

$(O)/twofish.o: $(SRC_DIR)/symmetric/twofish.cc
	@echo "compiling twofish.cc"
	$(CC) $(CFLAGS) -c -o $(O)/twofish.o $(SRC_DIR)/symmetric/twofish.cc

$(O)/tea.o: $(SRC_DIR)/symmetric/tea.cc
	@echo "compiling tea.cc"
	$(CC) $(CFLAGS) -c -o $(O)/tea.o $(SRC_DIR)/symmetric/tea.cc

$(O)/rc4.o: $(SRC_DIR)/symmetric/rc4.cc
	@echo "compiling rc4.cc"
	$(CC) $(CFLAGS) -c -o $(O)/rc4.o $(SRC_DIR)/symmetric/rc4.cc

$(O)/simonspeck.o: $(SRC_DIR)/symmetric/simonspeck.cc
	@echo "compiling simonspeck.cc"
	$(CC) $(CFLAGS) -c -o $(O)/simonspeck.o $(SRC_DIR)/symmetric/simonspeck.cc

$(O)/encryption_scheme.o: $(SRC_DIR)/encryption_scheme/encryption_scheme.cc
	@echo "compiling encryption_scheme.cc"
	$(CC) $(CFLAGS) -c -o $(O)/encryption_scheme.o $(SRC_DIR)/encryption_scheme/encryption_scheme.cc

