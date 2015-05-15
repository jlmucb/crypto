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
#    File: cryptutil.mak

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

S= $(SRC_DIR)/cryptutil
O= $(OBJ_DIR)/cryptutil
INCLUDE= -I$(SRC_DIR)/include -I$(S) -I/usr/local/include -I$(GOOGLE_INCLUDE) -I$(SRC_DIR)/keys

CFLAGS=$(INCLUDE) -O3 -g -Wall -std=c++11
CFLAGS1=$(INCLUDE) -O3 -g -Wall -std=c++11

include ../OSName
ifdef YOSEMITE
	LDFLAGS= $(LOCAL_LIB)/libprotobuf.a -L$(LOCAL_LIB) -lgtest -lgflags -lprotobuf -lpthread
else
	LDFLAGS= $(LOCAL_LIB)/libgtest.a  $(LOCAL_LIB)/libprotobuf.a $(LOCAL_LIB)/libgflags.a -lpthread
endif
ifdef YOSEMITE
	CC=clang++
	LINK=clang++
else
	CC=g++
	LINK=g++
endif
CRYPTOLIB= $(OBJ_DIR)/jlmcryptolib.a



dobj=	$(O)/cryptutil.o 

all:	cryptutil.exe
clean:
	@echo "removing object files"
	rm $(O)/*.o
	@echo "removing executable file"
	rm $(EXE_DIR)/cryptutil.exe

cryptutil.exe: $(dobj) 
	@echo "linking executable files"
	$(LINK) -o $(EXE_DIR)/cryptutil.exe $(dobj) $(CRYPTOLIB) $(LDFLAGS)

$(O)/cryptutil.o: $(S)/cryptutil.cc
	@echo "compiling cryptutil.cc"
	$(CC) $(CFLAGS) -c -o $(O)/cryptutil.o $(S)/cryptutil.cc


