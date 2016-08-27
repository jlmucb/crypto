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
#    File: big.mak


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

O= $(OBJ_DIR)/cryptolib
INCLUDE= -I$(SRC_DIR)/include -I/usr/local/include -I$(SRC_DIR)/keys -I$(GOOGLE_INCLUDE) 

CFLAGS=$(INCLUDE) -O3 -g -Wall -std=c++11
CFLAGS1=$(INCLUDE) -O1 -g -Wall -std=c++11

include OSName
ifdef YOSEMITE
	CC=clang++
	LINK=clang++
	LDFLAGS= # $(LOCAL_LIB)/libprotobuf.a -L$(LOCAL_LIB) -lgtest -lgflags -lprotobuf -lpthread
else
	CC=g++
	LINK=g++
	export LD_LIBRARY_PATH=/usr/local/lib
	LDFLAGS= # -lprotobuf -lgtest -lgflags -lpthread
endif

dobj=	$(O)/bignum.o $(O)/basic_arith.o $(O)/number_theory.o \
	$(O)/intel64_arith.o $(O)/globals.o $(O)/util.o $(O)/conversions.o \
	$(O)/smallprimes.o $(O)/ecc.o $(O)/rsa.o $(O)/keys.o $(O)/keys.pb.o \
	$(O)/symmetric_cipher.o $(O)/aes.o $(O)/sha1.o $(O)/sha256.o \
	$(O)/aesni.o $(O)/hash.o $(O)/hmac_sha256.o $(O)/sha3.o $(O)/twofish.o \
	$(O)/encryption_algorithm.o $(O)/sha256.o $(O)/aescbchmac256sympad.o \
        $(O)/aesgcm.o $(O)/aesctrhmac256sympad.o $(O)/pkcs.o $(O)/pbkdf2.o \
	$(O)/ghash.o $(O)/simonspeck.o $(O)/rc4.o $(O)/tea.o

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

$(SRC_DIR)/keys/keys.pb.cc $(SRC_DIR)/keys/keys.pb.h: $(SRC_DIR)/keys/keys.proto
	$(PROTO) --cpp_out=$(SRC_DIR)/keys $(SRC_DIR)/keys/keys.proto

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
	$(CC) $(CFLAGS1) -S -o $(O)/intel64_arith.s $(SRC_DIR)/bignum/intel64_arith.cc
	$(CC) $(CFLAGS1) -c -o $(O)/intel64_arith.o $(SRC_DIR)/bignum/intel64_arith.cc

$(O)/util.o: $(SRC_DIR)/common/util.cc
	@echo "compiling util.cc"
	$(CC) $(CFLAGS) -c -o $(O)/util.o $(SRC_DIR)/common/util.cc

$(O)/conversions.o: $(SRC_DIR)/common/conversions.cc
	@echo "compiling conversions.cc"
	$(CC) $(CFLAGS) -c -o $(O)/conversions.o $(SRC_DIR)/common/conversions.cc

$(O)/keys.o: $(SRC_DIR)/keys/keys.cc $(SRC_DIR)/keys/keys.pb.h
	@echo "compiling keys.cc"
	$(CC) $(CFLAGS) -c -o $(O)/keys.o $(SRC_DIR)/keys/keys.cc

$(O)/keys.pb.o: $(SRC_DIR)/keys/keys.pb.cc
	@echo "compiling keys.pb.cc"
	$(CC) $(CFLAGS) -c -o $(O)/keys.pb.o $(SRC_DIR)/keys/keys.pb.cc

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

$(O)/ghash.o: $(SRC_DIR)/hash/ghash.cc
	@echo "compiling ghash.cc"
	$(CC) $(CFLAGS) -c -o $(O)/ghash.o $(SRC_DIR)/hash/ghash.cc

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

$(O)/encryption_algorithm.o: $(SRC_DIR)/symmetric/encryption_algorithm.cc
	@echo "compiling encryption_algorithm.cc"
	$(CC) $(CFLAGS) -c -o $(O)/encryption_algorithm.o $(SRC_DIR)/symmetric/encryption_algorithm.cc

$(O)/aescbchmac256sympad.o: $(SRC_DIR)/symmetric/aescbchmac256sympad.cc
	@echo "compiling aescbchmac256sympad.cc"
	$(CC) $(CFLAGS) -c -o $(O)/aescbchmac256sympad.o $(SRC_DIR)/symmetric/aescbchmac256sympad.cc

$(O)/aesctrhmac256sympad.o: $(SRC_DIR)/symmetric/aesctrhmac256sympad.cc
	@echo "compiling aesctrhmac256sympad.cc"
	$(CC) $(CFLAGS) -c -o $(O)/aesctrhmac256sympad.o $(SRC_DIR)/symmetric/aesctrhmac256sympad.cc

$(O)/aesgcm.o: $(SRC_DIR)/symmetric/aesgcm.cc $(SRC_DIR)/include/aesgcm.h
	@echo "compiling aesgcm.cc"
	$(CC) $(CFLAGS) -c -o $(O)/aesgcm.o $(SRC_DIR)/symmetric/aesgcm.cc

