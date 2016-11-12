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
// File: gf2_tables.cc

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include <string>
#include <iostream>
#include <fstream>
#include <memory>

#include "cryptotypes.h"
#include <gtest/gtest.h>
#include <gflags/gflags.h>


int main(int an, char** av) {
#ifdef __linux__
  gflags::ParseCommandLineFlags(&an, &av, true);
#else
  google::ParseCommandLineFlags(&an, &av, true);
#endif

  return 0;
}
