// Copyright 2020 John Manferdelli, All Rights Reserved.
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
// File: test_drng.cc

#include <gtest/gtest.h>
#include <gflags/gflags.h>
#include <stdio.h>
#include "crypto_support.h"
#include "support.pb.h"
#include "crypto_names.h"
#include "drng.h"
#include "aes.h"


DEFINE_bool(print_all, false, "Print intermediate test computations");


bool test_ctr_drng() {
  byte ent_bytes[512];
  byte bytes_out[512];
  memset(ent_bytes, 0, 512);
  memset(bytes_out, 0, 512);
 
  hash_drng obj;
  obj.set_policy(256, 512, 200);
  obj.add_entropy(512, ent_bytes, 256); 
  if (!obj.init(0, nullptr, 0, nullptr)) {
    printf("cannot init object\n");
    return false;
  }

  if (!obj.generate(256, bytes_out, 0, nullptr)) {
    printf("cannot generate bits\n");
    return false;
  }
  printf("generated: "); printf("\n");
  print_bytes(32, bytes_out);
  return true;
}

TEST (drng, test_ctr_drng) {
  EXPECT_TRUE(test_ctr_drng());
}

int main(int an, char** av) {
  gflags::ParseCommandLineFlags(&an, &av, true);
  an = 1;
  ::testing::InitGoogleTest(&an, av);

  int result = RUN_ALL_TESTS();

  printf("\n");
  return result;
}
