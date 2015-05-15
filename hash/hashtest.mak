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
#    File: symmetric.mak

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

S= $(SRC_DIR)/hash
O= $(OBJ_DIR)/hash
INCLUDE= -I$(SRC_DIR)/include -I$(S) -I/usr/local/include -I$(GOOGLE_INCLUDE)

CFLAGS=$(INCLUDE) -O3 -g -Wall

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
LDFLAGS= $(LOCAL_LIB)/libprotobuf.a -L$(LOCAL_LIB) -lgtest -lgflags -lprotobuf -lpthread

dobj=	$(O)/hashtest.o $(O)/hash.o $(O)/sha1.o $(O)/util.o $(O)/sha256.o \
	$(O)/sha3.o $(O)/hmac_sha256.o $(O)/pkcs.o $(O)/pbkdf2.o

all:	hashtest.exe
clean:
	@echo "removing object files"
	rm $(O)/*.o
	@echo "removing executable file"
	rm $(EXE_DIR)/hashtest.exe

hashtest.exe: $(dobj) 
	@echo "linking executable files"
	$(LINK) -o $(EXE_DIR)/hashtest.exe $(dobj) $(LDFLAGS)

$(O)/hashtest.o: $(S)/hashtest.cc
	@echo "compiling hashtest.cc"
	$(CC) $(CFLAGS) -c -o $(O)/hashtest.o $(S)/hashtest.cc

$(O)/hash.o: $(S)/hash.cc
	@echo "compiling hash.cc"
	$(CC) $(CFLAGS) -c -o $(O)/hash.o $(S)/hash.cc

$(O)/sha1.o: $(S)/sha1.cc
	@echo "compiling sha1.cc"
	$(CC) $(CFLAGS) -c -o $(O)/sha1.o $(S)/sha1.cc

$(O)/sha256.o: $(S)/sha256.cc
	@echo "compiling sha256.cc"
	$(CC) $(CFLAGS) -c -o $(O)/sha256.o $(S)/sha256.cc

$(O)/sha3.o: $(S)/sha3.cc
	@echo "compiling sha3.cc"
	$(CC) $(CFLAGS) -c -o $(O)/sha3.o $(S)/sha3.cc

$(O)/hmac_sha256.o: $(S)/hmac_sha256.cc
	@echo "compiling hmac_sha256.cc"
	$(CC) $(CFLAGS) -c -o $(O)/hmac_sha256.o $(S)/hmac_sha256.cc

$(O)/util.o: $(SRC_DIR)/common/util.cc
	@echo "compiling util.cc"
	$(CC) $(CFLAGS) -c -o $(O)/util.o $(SRC_DIR)/common/util.cc

$(O)/pkcs.o: $(S)/pkcs.cc
	@echo "compiling pkcs.cc"
	$(CC) $(CFLAGS) -c -o $(O)/pkcs.o $(S)/pkcs.cc

$(O)/pbkdf2.o: $(S)/pbkdf2.cc
	@echo "compiling pbkdf2.cc"
	$(CC) $(CFLAGS) -c -o $(O)/pbkdf2.o $(S)/pbkdf2.cc

