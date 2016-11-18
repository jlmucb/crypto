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
// File: symmetric.cc

#include <stdio.h>
#include <string.h>

#include <string>

#include "util.h"
#include "cryptotypes.h"
#include <gtest/gtest.h>
#include <gflags/gflags.h>
#include "gf2_common.h"
#include "splitsecret.pb.h"

#include <memory>
#include <cmath>

DEFINE_bool(printall, false, "printall flag");

class GF2Common : public ::testing::Test {
 protected:
  virtual void SetUp();
  virtual void TearDown();
};

void GF2Common::SetUp() {}

void GF2Common::TearDown() {}


bool InternalRepTest() {
  uint16_t tpoly = 0x77;
  uint16_t cpoly;
  int size_a = 16;
  byte a[16];
  EXPECT_TRUE(to_internal_representation(tpoly, &size_a, a));
  EXPECT_TRUE(from_internal_representation(size_a, a, &cpoly));
  printf("Cpoly: %02x\n", cpoly);
  EXPECT_TRUE(tpoly == cpoly);
  return true;
}

bool PrintPolyTest() {
  uint16_t tpoly = 0x77;
  int size_a = 16;
  byte a[16];
  EXPECT_TRUE(to_internal_representation(tpoly, &size_a, a));
  print_poly(size_a, a);
  printf("\n");
  return true;
}

bool Gf2AddTest() {
  uint16_t poly1 = 0x77;
  uint16_t poly2 = 0x07;

  int size_min_poly = 16;
  byte min_poly[16];

  int size_a = 16;
  byte a[16];
  int size_b = 16;
  byte b[16];
  int size_c = 16;
  byte c[16];

  EXPECT_TRUE(to_internal_representation(poly1, &size_a, a));
  EXPECT_TRUE(to_internal_representation(poly2, &size_b, b));
  EXPECT_TRUE(gf2_add(size_a, a, size_b, b, size_min_poly, min_poly, &size_c, c));

  uint16_t cpoly;
  EXPECT_TRUE(from_internal_representation(size_c, c, &cpoly));
  printf("poly1: %02x, poly2: %02x, Cpoly: %02x\n", poly1, poly2, cpoly);
  EXPECT_TRUE(cpoly == 0x70);
  return true;
}

bool Gf2ReduceTest() {
  uint16_t minpoly = 0x11b;
  uint16_t poly1 = 0x200;

  int size_min_poly = 16;
  byte min_poly[16];

  EXPECT_TRUE(to_internal_representation(minpoly, &size_min_poly, min_poly));
  printf("Min poly: "); print_poly(size_min_poly, min_poly); printf("\n");

  int size_a = 16;
  byte a[16];

  EXPECT_TRUE(to_internal_representation(poly1, &size_a, a));
  printf("Input poly: "); print_poly(size_a, a); printf("\n");
  EXPECT_TRUE(gf2_reduce(size_min_poly, min_poly, &size_a, a));

  uint16_t cpoly;
  EXPECT_TRUE(from_internal_representation(size_a, a, &cpoly));
  printf("Reduced poly: "); print_poly(size_a, a); printf(", %02x\n", cpoly);
  EXPECT_TRUE(cpoly == 0x36);
  return true;
}

bool Gf2MultiplyTest() {
  uint16_t poly1 = 0x77;
  uint16_t poly2 = 0x07;

  int size_min_poly = 16;
  byte min_poly[16];
  uint16_t minpoly = 0x11b;

  EXPECT_TRUE(to_internal_representation(minpoly, &size_min_poly, min_poly));
  printf("Min poly: "); print_poly(size_min_poly, min_poly); printf("\n");

  int size_a = 16;
  byte a[16];
  int size_b = 16;
  byte b[16];
  int size_c = 32;
  byte c[32];

  EXPECT_TRUE(to_internal_representation(poly1, &size_a, a));
  EXPECT_TRUE(to_internal_representation(poly2, &size_b, b));
  EXPECT_TRUE(gf2_mult(size_a, a, size_b, b, size_min_poly, min_poly, &size_c, c));
  print_poly(size_a, a);
  printf(" * ");
  print_poly(size_b, b);
  printf(" [mod ");
  print_poly(size_min_poly, min_poly);
  printf(" ] = ");
  print_poly(size_c, c);
  printf("\n");

  uint16_t cpoly;
  EXPECT_TRUE(from_internal_representation(size_c, c, &cpoly));
  printf("cpoly: %02x\n", cpoly);
  EXPECT_TRUE(cpoly == 0x5e);
  return true;
}

bool Gf2InverseTest() {
  int size_min_poly = 16;
  byte min_poly[16];
  uint16_t minpoly = 0x11b;

  EXPECT_TRUE(to_internal_representation(minpoly, &size_min_poly, min_poly));
  printf("Min poly: "); print_poly(size_min_poly, min_poly); printf("\n");
  EXPECT_TRUE(init_inverses(size_min_poly, min_poly));
#if 0
  for (int i = 0; i < 256; i++) {
    uint16_t z;
    from_internal_representation(8, g_gf2_inverse[i].v_, &z);
    printf("1/%02x = %02x\n", i, z);
  }
#endif
  uint16_t w;
  from_internal_representation(8, g_gf2_inverse[2].v_, &w);
  EXPECT_TRUE( w == 0x8d);
  return true;
}

bool Gf2LinearTest() {
  int size_min_poly = 16;
  byte min_poly[16];
  uint16_t minpoly = 0x11b;

  EXPECT_TRUE(to_internal_representation(minpoly, &size_min_poly, min_poly));
  printf("Min poly: "); print_poly(size_min_poly, min_poly); printf("\n");
  EXPECT_TRUE(init_inverses(size_min_poly, min_poly));

  gf2_8 a[48];
  gf2_8 x[48];
  gf2_8 y;
  byte t3[16];
  uint16_t u, w;
  int size;
  for (int i = 0; i < 48; i++) {
    w =  (uint16_t)(i + 1);
    u =  (uint16_t)(2 * i + 10);
    size = 16;
    EXPECT_TRUE(to_internal_representation(w, &size, t3));
    byte_8_copy(t3, a[i].v_);
    size = 16;
    EXPECT_TRUE(to_internal_representation(u, &size, t3));
    byte_8_copy(t3, x[i].v_);
  }

  EXPECT_TRUE(multiply_linear(48, size_min_poly, min_poly, a, x, y));

  uint16_t r, s, v;
  for (int i = 0; i < 48; i++) {
    EXPECT_TRUE(from_internal_representation(8, a[i].v_, &r));
    EXPECT_TRUE(from_internal_representation(8, x[i].v_, &s));
    printf("%02x * %02x ", r, s);
    if (i != 47)
      printf("+ ");
  }
  EXPECT_TRUE(from_internal_representation(8, y.v_, &v));
  printf(" =  %02x\n", v);
  return true;
}

void PrintSplitSecretMessage(split_secret_message& msg) {
  printf("\n");
  printf("Secret name: %s\n", msg.secret_name().c_str());
  printf("number_of_subsequences_in_secret: %d\n", msg.number_of_subsequences_in_secret());
  printf("sequence_number: %d\n", msg.sequence_number());
  printf("number_of_shards_outstanding: %d\n", msg.number_of_shards_outstanding());
  printf("number_of_shards_required: %d\n", msg.number_of_shards_required());
  printf("shard_number: %d\n", msg.shard_number());
  printf("number_of_coefficients: %d\n", msg.number_of_coefficients());
  printf("number_of_equations_in_shard: %d\n", msg.number_of_equations_in_shard());
  byte a, b;
  for (int j = 0; j < msg.equations_size(); j++) {
    for (int k = 0; k < msg.equations(j).coefficients().size(); k++) {
      a = (byte)msg.equations(j).coefficients(k);
      printf("%02x ", a);
    }
    b = (byte) msg.equations(j).value();
    printf("   =  %02x\n", b);
  }
  printf("\n");
}

void PrintShard(string& serialized) {
  split_secret_message msg;

  msg.ParseFromString(serialized);
  PrintSplitSecretMessage(msg);
}

bool RecoverAndSolve(int n, string* serialized_msg) {
  gf2_instance instance[48];
  uint16_t w;
  int size_min_poly = 16;
  byte min_poly[16];
  uint16_t minpoly = 0x11b;

  printf("\n\n*****RecoverAndSolve\n\n");
  if (!to_internal_representation(minpoly, &size_min_poly, min_poly)) {
    return false;
  }
  printf("Min poly: "); print_poly(size_min_poly, min_poly); printf("\n");

  split_secret_message msgs[3];
  for (int i = 0; i < 3; i++) {
    msgs[i].ParseFromString(serialized_msg[i]);
    PrintSplitSecretMessage(msgs[i]);
  }

  int size;
  byte c[16];
  for (int j = 0; j < 48; j++) {
    printf("-----Equation %d\n", j + 1);
    const equation_message& e_msg = msgs[j/16].equations(j%16);
    for(int i = 0; i < 48; i++) {
      w = e_msg.coefficients(i);
      size = 16;
      if(!to_internal_representation(w, &size, c)) {
        return false;
      }
      byte_8_copy(c, instance[j].a_[i].v_);
      printf("%02x * x[%d] + ", w, i);
    }
    size = 16;
    w = e_msg.value();
    if(!to_internal_representation(w, &size, c)) {
      return false;
    }
    byte_8_copy(c, instance[j].y_.v_);
    printf(" = %02x\n\n", w);
  }

  gf2_8 solved_x[48];
  if(!gaussian_solve(48, size_min_poly, min_poly, instance, solved_x)) {
      return false;
  }
  for (int i = 0; i < 48; i++) {
    if(!from_internal_representation(8, solved_x[i].v_, &w)) {
      return false;
    }
    printf("x[%d]= %02x\n", i, w);
  }
  return true;
}

bool Gf2SolveSimultaneousTest() {
  int size_min_poly = 16;
  byte min_poly[16];
  uint16_t minpoly = 0x11b;

  EXPECT_TRUE(to_internal_representation(minpoly, &size_min_poly, min_poly));
  printf("Min poly: "); print_poly(size_min_poly, min_poly); printf("\n");
  EXPECT_TRUE(init_inverses(size_min_poly, min_poly));

  gf2_8 x[48];
  byte t3[16];
  uint16_t w;
  int size;

  for (int i = 0; i < 48; i++) {
    w =  (uint16_t)(i + 1);
    size = 16;
    EXPECT_TRUE(to_internal_representation(w, &size, t3));
    byte_8_copy(t3, x[i].v_);
  }

  gf2_instance instance[48];

  for (int j = 0; j < 48; j++) {
    for (int i = 0; i < 48; i++) {
      w =  (uint16_t)((j * j * j +  7 * j * j +  31 * i * i + i * j + 1) % 256);
      size = 16;
      EXPECT_TRUE(to_internal_representation(w, &size, t3));
      byte_8_copy(t3, instance[j].a_[i].v_);
    }

    // Generate a's and y's
    if (!multiply_linear(48, size_min_poly, min_poly, instance[j].a_, x, instance[j].y_))
      return false;
  }

  split_secret_message secret_message[3];

  for (int i = 0; i < 3; i++) {
    secret_message[i].set_secret_name("TestKey1");
    secret_message[i].set_number_of_subsequences_in_secret(1);
    secret_message[i].set_sequence_number(1);
    secret_message[i].set_number_of_shards_outstanding(5);
    secret_message[i].set_number_of_shards_required(3);
    secret_message[i].set_shard_number(i + 1);
    secret_message[i].set_number_of_coefficients(48);
    secret_message[i].set_number_of_equations_in_shard(16);
  }

  for (int j = 0; j < 48; j++) {
    printf("Equation %d:\n", j + 1);
    equation_message* e_msg = secret_message[j/16].add_equations();
    for(int i = 0; i < 48; i++) {
      EXPECT_TRUE(from_internal_representation(8, instance[j].a_[i].v_, &w));
      printf("%02x * x[%d] + ", w, i);
      e_msg->add_coefficients((int)w);
    }
    EXPECT_TRUE(from_internal_representation(8, instance[j].y_.v_, &w));
    printf(" = %02x\n\n", w);
    e_msg->set_value((int)w);
  }

  string serialized_messages[3];
  for (int i = 0; i < 3; i++) {
    secret_message[i].SerializeToString(&serialized_messages[i]);
    PrintShard(serialized_messages[i]);
  }
#if 0
  gf2_8 solved_x[48];
  EXPECT_TRUE(gaussian_solve(48, size_min_poly, min_poly, instance, solved_x));
  for (int i = 0; i < 48; i++) {
    EXPECT_TRUE(from_internal_representation(8, solved_x[i].v_, &w));
    printf("x[%d]= %02x\n", i, w);  
  }
#else
  EXPECT_TRUE(RecoverAndSolve(3, serialized_messages));
#endif
  return true;
}

bool Gf2SolvePrimitivesTest() {
  int size_min_poly = 16;
  byte min_poly[16];
  uint16_t minpoly = 0x11b;

  EXPECT_TRUE(to_internal_representation(minpoly, &size_min_poly, min_poly));
  printf("Min poly: "); print_poly(size_min_poly, min_poly); printf("\n");
  EXPECT_TRUE(init_inverses(size_min_poly, min_poly));

  byte t3[16];
  uint16_t w;
  int size;

  gf2_instance one_instance;
  gf2_instance two_instance;
  for (int i = 0; i < 48; i++) {
    w =  (uint16_t)((2 * i + 3) % 256);
    size = 16;
    EXPECT_TRUE(to_internal_representation(w, &size, t3));
    byte_8_copy(t3, one_instance.a_[i].v_);
    w =  (uint16_t)((3 * i + 5) % 256);
    size = 16;
    EXPECT_TRUE(to_internal_representation(w, &size, t3));
    byte_8_copy(t3, two_instance.a_[i].v_);
  }
  printf("one_instance: ");
  print_row(48, one_instance);
  EXPECT_TRUE(divide_equation_by(48, size_min_poly, min_poly, 0, one_instance));
  printf("after divide by: ");
  print_row(48, one_instance);

  printf("Before subtract: ");
  print_row(48, two_instance);
  if (!subtract_equation_by(48, size_min_poly, min_poly, 0,
                          one_instance, two_instance))
    return false;
  printf("After subtract: ");
  print_row(48, two_instance);
  return true;
}

bool Gf2GenMatrixTest() {
  uint16_t minpoly = 0x11b;
  int size_min_poly = 16;
  byte min_poly[16];

  EXPECT_TRUE(to_internal_representation(minpoly, &size_min_poly, min_poly));

  printf("Min poly: "); print_poly(size_min_poly, min_poly); printf("\n");

  gf2_8 a[48 * 48];
  EXPECT_TRUE(generate_invertible_matrix(48, size_min_poly, min_poly, a));
  printf("\nMatrix:\n");
  print_array(48, a);
  printf("\n");
  return true;
}

bool Gf2EquationSetup(int size_min_poly, byte* min_poly, gf2_instance* instance,
      gf2_8* x) {
  gf2_8 a[48 * 48];

  if (!generate_invertible_matrix(48, size_min_poly, min_poly, a)) {
    printf("generate_invertible_matrix fails\n");
    return false;
  }

  printf("\nGenerated matrix:\n");
  print_array(48, a);
  printf("\n");

  for (int i = 0; i < 48 * 48; i++) {
    gf2_8_copy(a[i], instance[i / 48].a_[i % 48]);
  }

  for (int j = 0; j < 48; j++) {
    if (!multiply_linear(48, size_min_poly, min_poly, instance[j].a_, x, instance[j].y_)) {
      printf("multiply_linear %d fails\n", j);
      return false;
    }
  }
  
  return true;
}

bool Gf2GenMatrixAndSolveTest() {
  uint16_t minpoly = 0x11b;
  int size_min_poly = 16;
  byte min_poly[16];

  gf2_instance instance[48];
  gf2_8 x[48];
  gf2_8 solved_x[48];
  uint16_t u, w;

  printf("\n\nGf2GenMatrixAndSolveTest():\n");
  if (!to_internal_representation(minpoly, &size_min_poly, min_poly)) {
    return false;
  }
  printf("Min poly: "); print_poly(size_min_poly, min_poly); printf("\n");

  int size;
  byte c[16];
  for (int i = 0; i < 48; i++) {
    w = (uint16_t)(i + 1);
    size = 16;
    if (!to_internal_representation(w, &size, c)) {
      return false;
    }
    byte_8_copy(c, x[i].v_);
  }

  if (!Gf2EquationSetup(size_min_poly, min_poly, instance, x)) {
    printf("Gf2EquationSetup failed\n");
    return false;
  }

  if(!gaussian_solve(48, size_min_poly, min_poly, instance, solved_x)) {
      printf("gaussian_solve fails\n");
      return false;
  }

  for (int i = 0; i < 48; i++) {
    if(!from_internal_representation(8, x[i].v_, &w)) {
      return false;
    }
    if(!from_internal_representation(8, solved_x[i].v_, &u)) {
      return false;
    }
    printf("x[%2d], solved_x[%2d]:  %02x %02x\n", i, i, w, u);
    if (!gf2_8_equal(x[i], solved_x[i])) {
      printf("x[%2d] != solved_x[%2d]\n", i, i);
      return false;
    }
  }
  return true;
}

TEST(InternalRep, InternalRepTest) {
  EXPECT_TRUE(InternalRepTest());
}
TEST(Gf2Add, Gf2AddTest) {
  EXPECT_TRUE(Gf2AddTest());
}
TEST(Gf2Reduce, Gf2ReduceTest) {
  EXPECT_TRUE(Gf2ReduceTest());
}
TEST(Gf2Multiply, Gf2MultiplyTest) {
  EXPECT_TRUE(Gf2MultiplyTest());
}
TEST(PrintPoly, PrintPolyTest) {
  EXPECT_TRUE(PrintPolyTest());
}
TEST(Gf2Inverse, Gf2InverseTest) {
  EXPECT_TRUE(Gf2InverseTest());
}
TEST(Gf2Linear, Gf2LinearTest) {
  EXPECT_TRUE(Gf2LinearTest());
}
TEST(Gf2SolvePrimitives, Gf2SolvePrimitivesTest) {
  EXPECT_TRUE(Gf2SolvePrimitivesTest());
}
TEST(Gf2SolveSimultaneous, Gf2SolveSimultaneousTest) {
  EXPECT_TRUE(Gf2SolveSimultaneousTest());
}
TEST(Gf2GenMatrix, Gf2GenMatrixTest) {
  EXPECT_TRUE(Gf2GenMatrixTest());
}
TEST(Gf2GenMatrixAndSolve, Gf2GenMatrixAndSolveTest) {
  EXPECT_TRUE(Gf2GenMatrixAndSolveTest());
}


DEFINE_string(log_file, "gf2_common_test.log", "gf2_common_test file name");

int main(int an, char** av) {
  ::testing::InitGoogleTest(&an, av);
#ifdef __linux__
  gflags::ParseCommandLineFlags(&an, &av, true);
#else
  google::ParseCommandLineFlags(&an, &av, true);
#endif
  int result = RUN_ALL_TESTS();
  return result;
}
