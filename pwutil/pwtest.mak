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
#    File: pwutil.mak


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

S= $(SRC_DIR)/pwutil
O= $(OBJ_DIR)/pwutil
INCLUDE= -I$(SRC_DIR)/include -I$(SRC_DIR)/keys -I$(S) -I/usr/local/include -I$(GOOGLE_INCLUDE)

CRYPTOLIB= $(OBJ_DIR)/jlmcryptolib.a

include ../OSName
ifdef YOSEMITE
	CC=clang++
	LINK=clang++
	PROTO=protoc
	AR=ar
	CFLAGS=$(INCLUDE) -O3 -g -Wall -std=c++11
	CFLAGS1=$(INCLUDE) -O1 -g -Wall -std=c++11
	LDFLAGS= $(LOCAL_LIB)/libprotobuf.a -L$(LOCAL_LIB) -lgtest -lgflags -lprotobuf -lpthread
else
	CC=g++
	LINK=g++
	PROTO=protoc
	AR=ar
	export LD_LIBRARY_PATH=/usr/local/lib
	CFLAGS=$(INCLUDE) -O3 -g -Wall -std=c++11
	CFLAGS1=$(INCLUDE) -O1 -g -Wall -std=c++11
	LDFLAGS= -lprotobuf -lgtest -lgflags -lpthread
endif

dobj=	$(O)/pwutil.o $(O)/pwutil.pb.o $(O)/tokenizer.o

all:	pwutil.exe
clean:
	@echo "removing object files"
	rm $(O)/*.o
	@echo "removing executable file"
	rm $(EXE_DIR)/pwutil.exe

pwutil.exe: $(dobj) 
	@echo "linking executable files"
	$(LINK) -o $(EXE_DIR)/pwutil.exe $(dobj) $(CRYPTOLIB) $(LDFLAGS)

$(S)/pwutil.pb.cc $(S)/pwutil.pb.h: $(S)/pwutil.proto
	$(PROTO) -I=$(S) --cpp_out=$(S) $(S)/pwutil.proto

$(O)/pwutil.o: $(S)/pwutil.cc $(S)/pwutil.pb.h
	@echo "compiling pwutil.cc"
	$(CC) $(CFLAGS) -c -o $(O)/pwutil.o $(S)/pwutil.cc

$(O)/pwutil.pb.o: $(S)/pwutil.pb.cc
	@echo "compiling pwutil.pb.cc"
	$(CC) $(CFLAGS) -c -o $(O)/pwutil.pb.o $(S)/pwutil.pb.cc

$(O)/tokenizer.o: $(S)/tokenizer.cc $(S)/tokenizer.h
	@echo "compiling tokenizer.cc"
	$(CC) $(CFLAGS) -c -o $(O)/tokenizer.o $(S)/tokenizer.cc

