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
// File: test_lattice.cc

#include <gtest/gtest.h>
#include <gflags/gflags.h>
#include <stdio.h>
#include "crypto_support.h"
#include "support.pb.h"
#include "lattice.h"


DEFINE_bool(print_all, false, "Print intermediate test computations");

// lll tests
bool test_lll() {
  int n = 3;
  real_vector b[3];

  for (int i = 0; i < n; i++)
    vector_alloc(n, &b[i]); 

  (b[0])[0] = 2.0;
  (b[0])[1] = 3.0;
  (b[0])[2] = 14.0;
  (b[1])[0] = 0.0;
  (b[1])[1] = 7.0;
  (b[1])[2] = 11.0;
  (b[2])[0] = 0.0;
  (b[2])[1] = 0.0;
  (b[2])[2] = 23.0;

  // answer is (-2,4,-3), (-4,1,6), (4,6,5)

  if (FLAGS_print_all) {
    printf("Original vectors: \n");
    for (int i = 0; i < n; i++) {
      printf("\tb[%d]: ", i);
      print_vector(b[i]);
      printf("\n");
    }
  }

  if (!lll(.75, 3, b))
    return false;

  if (FLAGS_print_all) {
    printf("Reduced vectors: \n");
    for (int i = 0; i < n; i++) {
      printf("\tb[%d]: ", i);
      print_vector(b[i]);
      printf("\n");
    }
  }

  return true;
}

TEST (lll, test_lll) {
  EXPECT_TRUE(test_lll());
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
  return result;
}
