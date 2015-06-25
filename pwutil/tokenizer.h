
//
// Copyright 2014 John Manferdelli, All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
// or in the the file LICENSE-2.0.txt in the top level sourcedirectory
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License
// Project: New Cloudproxy Crypto
// File: tokenizer.h

#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include "pwutil.pb.h"

#ifndef _TOKENIZER_H__
#define _TOKENIZER_H__
using namespace std;

class Tokenizer {
private:
  string  delimiters_;
public:
  Tokenizer();
  Tokenizer(const char* delim);
  ~Tokenizer();
  void SetDelim(const char* delim);
  char* NextToken(char* start, bool first);
};

class ReadLines {
private:
  FILE* fp_;

public:
  ReadLines();
  ~ReadLines();
  bool Open(const string& file);
  void Close();
  int  NextLine(string& line);
};

bool FillSecretProto(const string& file, pw_message& proto);
#endif
