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
#    File: common.mak


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

S= $(SRC_DIR)/common
O= $(OBJ_DIR)/common
INCLUDE= -I$(SRC_DIR)/include -I$(S) -I/usr/local/include -I$(GOOGLE_INCLUDE)

CFLAGS=$(INCLUDE) -O3 -g -Wall
LDFLAGS= $(LOCAL_LIB)/libgtest.a $(LOCAL_LIB)/libgflags.a -lpthread

dobj=	$(O)/commontest.o $(O)/conversions.o $(O)/util.o

all:	commontest.exe
clean:
	@echo "removing object files"
	rm $(O)/*.o
	@echo "removing executable file"
	rm $(EXE_DIR)/commontest.exe

commontest.exe: $(dobj) 
	@echo "linking executable files"
	$(LINK) -o $(EXE_DIR)/commontest.exe $(dobj) $(LDFLAGS)

CC=g++
LINK=g++
AR=ar

$(O)/commontest.o: $(S)/commontest.cc
	@echo "compiling commontest.cc"
	$(CC) $(CFLAGS) -c -o $(O)/commontest.o $(S)/commontest.cc

$(O)/conversions.o: $(S)/conversions.cc
	@echo "compiling conversions.cc"
	$(CC) $(CFLAGS) -c -o $(O)/conversions.o $(S)/conversions.cc

$(O)/util.o: $(S)/util.cc
	@echo "compiling util.cc"
	$(CC) $(CFLAGS) -c -o $(O)/util.o $(S)/util.cc

