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
// File: tokenizer.cc

#include "tokenizer.h"
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <istream>

using namespace std;

// string  delimiters_
Tokenizer::Tokenizer() {
  delimiters_ = " :;\n";
}

Tokenizer::Tokenizer(const char* delim) {
  delimiters_ = delim;
}

Tokenizer::~Tokenizer() {
}

void Tokenizer::SetDelim(const char* delim) {
  delimiters_ = delim;
}

char* Tokenizer::NextToken(char* start, bool first) {
  if (first)
    return std::strtok(start, delimiters_.c_str());
  return std::strtok(nullptr, delimiters_.c_str());
}

ReadLines::ReadLines() {
  fp_ = nullptr;
}

ReadLines::~ReadLines() {
}

bool ReadLines::Open(const string& file) {
  fp_ = fopen(file.c_str(), "r");
  if (fp_ == nullptr)
    return false;
  return true;
}

void ReadLines::Close() {
  fclose(fp_);
}

int  ReadLines::NextLine(string& line) {
  char* lineptr = nullptr;
  size_t n;
  getline(&lineptr, &n, fp_);
  line.assign((const char*)lineptr);
  free (lineptr);
  if (n<=1) {
    return -1;
  }
  return line.length();
}

bool CollectArg(Tokenizer& tokens, string& arg) {
  char* token = tokens.NextToken(nullptr, false);
  if (token == nullptr) {
    return false;
  }
  arg.assign((const char*)token);
  while (tokens.NextToken (nullptr, false) != nullptr);
  return true;
}

bool FillSecretProto(const string& file, pw_message& proto) {
  ReadLines reader;

  if (!reader.Open(file))
    return false;

  string line;
  bool got_name = false;
  bool got_epoch = false;
  bool got_status = false;
  bool got_secret = false;
  while (reader.NextLine(line)>=0) {
    Tokenizer tokens;

    char* token = tokens.NextToken((char*)line.c_str(), true);
    if (token == nullptr || strlen(token)<=1) {
      continue;
    }
    if (*token == '#') {
      continue;
    }
    for(;;) {
      string value;
      if (strcmp(token, "name") == 0) {
        got_name = CollectArg(tokens, value);
        proto.set_pw_name(value);
      } else if (strcmp(token, "epoch") == 0) {
        got_epoch = CollectArg(tokens, value);
        int k = stoi(value);
        proto.set_pw_epoch(k);
        // ToInt(value);
      } else if (strcmp(token, "status") == 0) {
        got_status = CollectArg(tokens, value);
        proto.set_pw_status(value);
      } else if (strcmp(token, "value") == 0) {
        proto.set_pw_value(value);
        got_secret = CollectArg(tokens, value);
      }
      token = tokens.NextToken((char*)line.c_str(), false);
      if (token == nullptr ) {
        if (got_name && got_epoch && got_status && got_secret) {
          // add time
          return true;
        }
        break;
      }
    }
  }
  return false;
}

