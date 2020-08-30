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
// File: test_crypto_support.cc

#include <gtest/gtest.h>
#include <gflags/gflags.h>
#include <stdio.h>
#include "crypto_support.h"
#include "support.pb.h"
#include "crypto_names.h"

DEFINE_bool(print_all, false, "Print intermediate test computations");

bool test_alg_names() {
  if (FLAGS_print_all) {
    printf("schemes:\n");
    print_schemes();
    printf("\n");
    printf("algorithms:\n");
    print_algorithms();
    printf("\n");
    printf("operations:\n");
    print_operations();
    printf("\n");
  }
  return true;
}

bool time_convert_test() {
  time_point t;
  
  t.time_now();
  if (FLAGS_print_all) {
    t.print_time();
    printf("\n");
  }

  string s1;
  if (!t.encodeTime(&s1))
    return false;
  time_point t1;
  if (FLAGS_print_all)
    printf("Encoded string: %s\n", s1.c_str());
  t1.decodeTime(s1);
  string s2;
  if (!t1.encodeTime(&s2))
    return false;
  if (FLAGS_print_all) {
    printf("Re-encoded string: %s\n", s2.c_str());
  }
  if (s1.compare(s2) != 0)
    return false;
  return true;
}

bool random_test() {
  random_source rs;

  if (!rs.start_random_source()) {
    return false;
  }
  byte b[64];
  int m = rs.get_random_bytes(64, b);
  if (m < 0)
    return false;
  if (FLAGS_print_all) {
    print_bytes(m, b);
  }
  return rs.close_random_source();
}

string test_hex_string1("012ab33");
string test_hex_string2("a012ab334466557789");

bool hex_convert_test() {
  string b1(50, 0);
  string b2(50, 0);
  b1.clear();
  b2.clear();

  if (FLAGS_print_all) {
    printf("hex 1: %s\n", test_hex_string1.c_str());
    printf("hex 2: %s\n", test_hex_string2.c_str());
  }

  if (!hex_to_bytes(test_hex_string1, &b1))
    return false;
  if (!hex_to_bytes(test_hex_string1, &b1))
    return false;
  if (!hex_to_bytes(test_hex_string2, &b2))
    return false;

  if (FLAGS_print_all) {
    printf("b1: ");
    print_bytes((int)b1.size(), (byte*)b1.data());
    printf("b2: ");
    print_bytes((int)b2.size(), (byte*)b2.data());
  }
  
  string c1(50, 0);
  string c2(50, 0);
  if (!bytes_to_hex(b1, &c1))
    return false;
  if (!bytes_to_hex(b2, &c2))
    return false;

  if (FLAGS_print_all) {
    printf("c1: %s\n", c1.c_str());
    printf("c2: %s\n", c2.c_str());
  }

  string d1(50, 0);
  string d2(50, 0);
  if (!hex_to_bytes(c1, &d1))
    return false;
  if (!hex_to_bytes(c2, &d2))
    return false;

  if (FLAGS_print_all) {
    printf("d1: ");
    print_bytes((int)d1.size(), (byte*)d1.data());
    printf("d2: ");
    print_bytes((int)d2.size(), (byte*)d2.data());
  }

  if (d1.compare(b1) != 0)
    return false;
  if (d2.compare(b2) != 0)
    return false;
  return true;
}
bool base64_convert_test() {
  string b1, b2, b3, b4;
  b1.clear();
  b1.append(1, 0x11);
  b1.append(1, 0xab);
  b1.append(1, 0x89);

  b2.clear();
  b2.append(1, 0x40);
  b2.append(1, 0x11);
  b2.append(1, 0xab);
  b2.append(1, 0x89);

  b3.clear();
  b3.append(1, 0x40);
  b3.append(1, 0x11);
  b3.append(1, 0xab);
  b3.append(1, 0x89);
  b3.append(1, 0xcc);

  b4.clear();
  b4.append(1, 0x40);
  b4.append(1, 0x11);
  b4.append(1, 0xab);
  b4.append(1, 0x89);
  b4.append(1, 0xcc);
  b4.append(1, 0x20);

  if (FLAGS_print_all) {
    printf("b1: ");
    print_bytes((int)b1.size(), (byte*)b1.data());
    printf("b2: ");
    print_bytes((int)b2.size(), (byte*)b2.data());
    printf("b3: ");
    print_bytes((int)b3.size(), (byte*)b3.data());
    printf("b4: ");
    print_bytes((int)b4.size(), (byte*)b4.data());
  }

  string h1, h2, h3, h4;
  string d1, d2, d3, d4;

  if (!bytes_to_base64(b1, &h1))
    return false;
  if (!bytes_to_base64(b2, &h2))
    return false;
  if (!bytes_to_base64(b3, &h3))
    return false;
  if (!bytes_to_base64(b4, &h4))
    return false;

  if (FLAGS_print_all) {
    printf("h1: %s\n", h1.c_str());
    printf("h2: %s\n", h2.c_str());
    printf("h3: %s\n", h3.c_str());
    printf("h4: %s\n", h4.c_str());
  }

  if (!base64_to_bytes(h1, &d1))
    return false;
  if (!base64_to_bytes(h2, &d2))
    return false;
  if (!base64_to_bytes(h3, &d3))
    return false;
  if (!base64_to_bytes(h4, &d4))
    return false;

  if (FLAGS_print_all) {
    printf("d1: ");
    print_bytes((int)d1.size(), (byte*)d1.data());
    printf("d2: ");
    print_bytes((int)d2.size(), (byte*)d2.data());
    printf("d3: ");
    print_bytes((int)d3.size(), (byte*)d3.data());
    printf("d4: ");
    print_bytes((int)d4.size(), (byte*)d4.data());
  }

  if (d1.compare(b1) != 0)
    return false;
  if (d2.compare(b2) != 0)
    return false;
  if (d3.compare(b3) != 0)
    return false;
  if (d4.compare(b4) != 0)
    return false;

  return true;
}

bool time_increment_test() {
  time_point t1, t2;
  t1.time_now();
  t2.add_interval_to_time(t1, 377 * 86400.0);
  if (FLAGS_print_all) {
    printf("\n");
    t1.print_time();
    printf("\n");
    t2.print_time();
    printf("\n");
  }
  t2.add_interval_to_time(t1, 5 * 365 * 86400.0);
  if (FLAGS_print_all) {
    printf("\n");
    t1.print_time();
    printf("\n");
    t2.print_time();
    printf("\n");
  }
  return true;
}


bool endian_test() {
  uint64_t l64, b64, r64;
  uint32_t l32, b32, r32;
  uint16_t l16, b16, r16;

  l64 = (0x12345678ULL<<32) | 0x90abcdef;
  l32 = 0x90abcdf;
  l16 = 0xbcdf;

  little_to_big_endian_64(&l64, &b64);
  big_to_little_endian_64(&b64, &r64);
  little_to_big_endian_32(&l32, &b32);
  big_to_little_endian_32(&b32, &r32);
  little_to_big_endian_16(&l16, &b16);
  big_to_little_endian_16(&b16, &r16);

  if (FLAGS_print_all) {
    printf("l64: %016lx, b64: %016lx, r64: %016lx\n", l64, b64, r64);
    printf("l32: %08x, b32: %08x, r32: %08x\n", l32, b32, r32);
    printf("l16: %04x, b16: %04x, r16: %04x\n", l16, b16, r16);
  }
  if (l64 != r64)
    return false;
  if (l32 != r32)
    return false;
  if (l16 != r16)
    return false;
  return true;
}

bool file_test() {
  return true;
}

bool key_test() {
  return true;
}

bool u64_array_bytes_test() {
  uint64_t n_in[4] = {
    0x01020104, 0xffeeddccbbaa9988, 0x7766554433221100, 0x4455
  };
  string b_out;
  uint64_t n_out[4];

  int k= u64_array_to_bytes(3, n_in, &b_out);
  if (k <= 0)
    return false;
  int m = bytes_to_u64_array(b_out, 3, n_out);
  if (m <= 0)
    return false;
  if (FLAGS_print_all) {
    printf("\n");
    printf("n in   : "); print_u64_array(3, n_in); printf("\n");
    printf("b out  : "); print_bytes(k, (byte*)b_out.data()); 
    printf("n out  : "); print_u64_array(m, n_out); printf("\n");
  }
  if (m != 3)
    return false;
  for (int i = 0; i < m; i++) {
    if (n_in[i] != n_out[i])
      return false;
  }

  for (int i = 0; i < 4; i++) {
    n_out[0] = 0ULL;
  }
  k= u64_array_to_bytes(4, n_in, &b_out);
  if (k <= 0)
    return false;
  m = bytes_to_u64_array(b_out, 4, n_out);
  if (m <= 0)
    return false;
  if (FLAGS_print_all) {
    printf("\n");
    printf("n in   : "); print_u64_array(4, n_in); printf("\n");
    printf("b out  : "); print_bytes(k, (byte*)b_out.data()); 
    printf("n out  : "); print_u64_array(m, n_out); printf("\n");
  }
  if (m != 4)
    return false;
  for (int i = 0; i < m; i++) {
    if (n_in[i] != n_out[i])
      return false;
  }
  return true;
}

TEST (algs, test_alg_names) {
  EXPECT_TRUE(test_alg_names());
}
TEST (timeutilities, time_convert_test) {
  EXPECT_TRUE(time_convert_test());
  EXPECT_TRUE(time_increment_test());
}
TEST (convertutilities, hex_convert_test) {
  EXPECT_TRUE(hex_convert_test());
}
TEST (convertutilities, base64_convert_test) {
  EXPECT_TRUE(base64_convert_test());
}
TEST (randomutilities, random_test) {
  EXPECT_TRUE(random_test());
}
TEST (endian, endian_test) {
  EXPECT_TRUE(endian_test());
}
TEST (fileutilities, file_test) {
  EXPECT_TRUE(file_test());
}
TEST (keyutilities, key_test) {
  EXPECT_TRUE(key_test());
}
TEST (u64stuff, u64_array_bytes_test) {
  EXPECT_TRUE(u64_array_bytes_test());
}


int main(int an, char** av) {
  gflags::ParseCommandLineFlags(&an, &av, true);
  an = 1;
  ::testing::InitGoogleTest(&an, av);

  uint64_t cycles_per_second = calibrateRdtsc();
  printf("This computer runs at %llu cycles per second\n", cycles_per_second);
  if (have_intel_rd_rand())
    printf("rd rand present\n");
  else
    printf("rd rand not present\n");
  if (have_intel_aes_ni())
    printf("aes ni present\n");
  else
    printf("aes ni not present\n");
  int result = RUN_ALL_TESTS();
  printf("%d tests\n", result);
  printf("Tests complete\n");
  return 0;
}