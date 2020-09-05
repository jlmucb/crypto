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
// File: test_rsa.cc

#include <gtest/gtest.h>
#include <gflags/gflags.h>
#include <stdio.h>
#include "crypto_support.h"
#include "support.pb.h"
#include "crypto_names.h"
#include "big_num.h"
#include "big_num_functions.h"
#include "rsa.h"


DEFINE_bool(print_all, false, "Print intermediate test computations");

bool test_rsa1() {
  rsa r;
  int num_bits = 512;

  if (!r.generate_rsa(num_bits))
    return false;
  if (!r.make_rsa_key("rsa-tst-key1", "testing", 86400.0 * 365.0))
    return false;

  string ser;
  if (!r.get_serialized_key_message(&ser))
    return false;

  key_message* km = r.get_key();
  if (km != nullptr)
    print_key_message(*km);

  byte msg_in[128];
  byte msg_out[128];
  byte msg_recovered[128];
  memset(msg_in, 0, 128);
  memset(msg_out, 0, 128);
  memset(msg_recovered, 0, 128);

  memcpy(msg_in, (byte*)"hello", 6);

  int size_out1 = 128;
  int size_out2 = 128;
  if(!r.encrypt(64, msg_in, &size_out1, msg_out, 0))
    return false;
  if (!r.decrypt(size_out1, msg_out, &size_out2, msg_recovered, 0))
    return false;
  printf("Message   :"); print_bytes(64, msg_in); printf("\n");
  printf("Encrypted :"); print_bytes(size_out1, msg_out); printf("\n");
  printf("Recovered :"); print_bytes(size_out2, msg_recovered); printf("\n");

  if (memcmp(msg_in, msg_recovered, 64) != 0)
    return false;
  return true;
}

TEST (rsa, test_rsa1) {
  EXPECT_TRUE(test_rsa1());
}

int main(int an, char** av) {
  gflags::ParseCommandLineFlags(&an, &av, true);
  an = 1;
  ::testing::InitGoogleTest(&an, av);

  if (!init_crypto()) {
    printf("init_crypto failed\n");
    return 1;
  }

  int result = RUN_ALL_TESTS();

  close_crypto();
  printf("\n");
  return 0;
}
