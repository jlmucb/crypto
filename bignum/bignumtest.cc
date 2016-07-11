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
// File: bignumtest.cc

#include <gtest/gtest.h>
#include <gflags/gflags.h>
#include <stdio.h>
#include <string>
#include "conversions.h"
#include "util.h"
#include "bignum.h"
#include "intel64_arith.h"
#include "keys.h"
#include "ecc.h"

using namespace std;


DEFINE_bool(printall, false, "printall flag");


EccKey* ext_ecc_key = nullptr;

class BigNumTest : public ::testing::Test {
 protected:
  virtual void SetUp();
  virtual void TearDown();
};

void BigNumTest::SetUp() {}

void BigNumTest::TearDown() {}

uint64_t cycles_per_second = 10;

bool makeTestData(const char* filename, int sizeBytes) {
  byte* buf = new byte[sizeBytes];

  int randfd = open("/dev/urandom", O_RDONLY);
  int randfile = creat(filename, S_IRWXU | S_IRWXG);
  if (randfd < 0 || randfile < 0) {
    printf("makeTestData: cant create test file\n");
    delete buf;
    return false;
  }
  int bytes_in_file = read(randfd, buf, sizeBytes);
  if (bytes_in_file != sizeBytes) {
    printf("makeTestData: Cant read %d bytes in data file\n", sizeBytes);
    delete buf;
    return false;
  }
  if (write(randfile, buf, sizeBytes) < 0) {
    printf("makeTestData: Cant write test file\n");
    delete buf;
    return false;
  }
  close(randfd);
  close(randfile);
  delete buf;
  return true;
}

bool readTestData(const char* filename, int sizeBytes, byte* buf) {
  int randfd = open(filename, O_RDONLY);
  bool ret = true;
  int bytes_in_file;

  if (randfd < 0) {
    printf("readTestData: Cant open read file\n");
    ret = false;
    goto done;
  }
  bytes_in_file = read(randfd, buf, sizeBytes);
  if (bytes_in_file != sizeBytes) {
    printf("readTestData: bytes read/requested don't match %d, %d\n", sizeBytes,
           bytes_in_file);
    ret = false;
    goto done;
  }

done:
  close(randfd);
  return ret;
}

// --------------------------------------------------------------------------------------

uint64_t test_a[4] = {0xffffffffULL, 0x4ULL, 0xffffffffffffffffULL, 0x5ULL};
uint64_t test_b[4] = {0xffffffffULL, 0x4ULL, 0xffffffffffffffffULL, 0x6ULL};
uint64_t test_x1[4] = {0xffffffffffffffffULL, 0ULL, 0ULL, 0ULL};
uint64_t test_x[4] = {0xffffffffffffffffULL, 0xffffffffffffffffULL, 0ULL, 0ULL};
uint64_t test_y[8] = {0x1ULL, 0ULL, 0ULL, 0ULL};
uint64_t test_t[8] = {0x1ULL, 0x222ULL, 9ULL, 0ULL};

uint64_t test_d1[8] = {0xffffffffffffffffULL, 0xffffffffffffffffULL, 0ULL, 0ULL};
uint64_t test_d2[8] = {
    0xffffffffffffffffULL, 0xffffffffffffffffULL, 0xffffffffffffffffULL,
    0xffffffffffffffffULL,
};
uint64_t test_d3[8] = {0ULL, 0xffffffffffffffffULL, 0xffffffffffffffffULL,
                       0xffffffffffffffffULL, 0xffffffffffffffffULL};
uint64_t test_c[8];
uint64_t test_z[8];

uint64_t test_r1[4] = {0x00000001fffffffeULL, 0x0000000000000008ULL, 0xfffffffffffffffeULL, 0x000000000000000cULL};
uint64_t test_r2[4] = {0x00000001fffffffeULL, 0x0000000000000008ULL, 0xfffffffffffffffeULL, 0x000000000000000cULL};
uint64_t test_r3[3] = {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff};
uint64_t test_r4[3] = {0x0000000000000000ULL, 0x8000000000000111ULL, 0x0000000000000004};

bool simpletest() {
  uint64_t a, b, result, carry;
  uint64_t carry_in, carry_out;
  uint64_t borrow_in, borrow_out;
  int m = 0;
  int n = 0;

  printf("\nBEGIN_SIMPLETEST\n");
  a = (uint64_t)-1ULL;
  b = (uint64_t)1ULL;
  Uint64AddStep(a, b, &result, &carry);
  if (carry != 1ULL || result != 0ULL) {
    printf("Test 1 failed\n");
    return false;
  }

  a = 1ULL;
  b = 1ULL;
  Uint64AddStep(a, b, &result, &carry);
  if (carry != 0ULL || result != 2ULL) {
    printf("Test 2 failed\n");
    return false;
  }

  a = 0x0ULL;
  b = 0x1ULL;
  Uint64MultStep(a, b, &result, &carry);
  if (carry != 0ULL || result != 0ULL) {
    printf("Test 3 failed\n");
    return false;
  }

  a = (uint64_t)-1ULL;
  b = (uint64_t)1ULL;
  carry_in = 0ULL;
  Uint64AddWithCarryStep(a, b, carry_in, &result, &carry_out);
  if (carry_out != 1ULL || result != 0ULL) {
    printf("Test 4 failed\n");
    return false;
  }

  a = (uint64_t)-1ULL;
  b = (uint64_t)1ULL;
  carry_in = 1ULL;
  Uint64AddWithCarryStep(a, b, carry_in, &result, &carry_out);
  if (carry_out != 1ULL || result != 1ULL) {
    printf("Test 5 failed\n");
    return false;
  }

  a = (uint64_t)1ULL;
  b = (uint64_t)0ULL;
  borrow_in = 0ULL;
  Uint64SubWithBorrowStep(a, b, borrow_in, &result, &borrow_out);
  if (borrow_out != 0ULL || result != 1ULL) {
    printf("Test 6 failed\n");
    return false;
  }

  a = (uint64_t)0ULL;
  b = (uint64_t)1ULL;
  borrow_in = 0ULL;
  Uint64SubWithBorrowStep(a, b, borrow_in, &result, &borrow_out);
  if (borrow_out != 1ULL || result != 0xffffffffffffffffULL) {
    printf("Test 7 failed\n");
    return false;
  }

  int size_test_a = sizeof(test_a) / sizeof(uint64_t);
  int size_test_b = sizeof(test_b) / sizeof(uint64_t);
  int size_test_c = sizeof(test_c) / sizeof(uint64_t);
  int size_test_t = sizeof(test_t) / sizeof(uint64_t);
  int size_test_x = sizeof(test_x) / sizeof(uint64_t);
  int size_test_x1 = sizeof(test_x1) / sizeof(uint64_t);
  int size_test_y = sizeof(test_y) / sizeof(uint64_t);
  int size_test_z = sizeof(test_z) / sizeof(uint64_t);
  int real_size_test_a = DigitArrayComputedSize(size_test_a, test_a);
  int real_size_test_b = DigitArrayComputedSize(size_test_b, test_b);
  int real_size_test_t = DigitArrayComputedSize(size_test_t, test_t);
  int real_size_test_x = DigitArrayComputedSize(size_test_x, test_x);
  int real_size_test_x1 = DigitArrayComputedSize(size_test_x1, test_x1);
  int real_size_test_y = DigitArrayComputedSize(size_test_y, test_y);
  // int real_size_test_z=  DigitArrayComputedSize(size_test_z, test_z);
  DigitArrayZeroNum(sizeof(test_c) / sizeof(uint64_t), test_c);
  int k = DigitArrayAdd(real_size_test_a, test_a, real_size_test_b, test_b,
                        size_test_c, test_c);
  if (FLAGS_printall) {
    printf("   ");
    TempPrintNum(real_size_test_a, test_a);
    printf(" + ");
    TempPrintNum(real_size_test_b, test_b);
    printf(" = ");
    TempPrintNum(k, test_c);
    printf("\n");
    printf("\n");
  }
  if (DigitArrayCompare(4, test_r1, 4, test_c) != 0) {
    printf("Add 1 failed\n");
    return false;
  }

  DigitArrayZeroNum(sizeof(test_c) / sizeof(uint64_t), test_c);
  k = DigitArrayAdd(real_size_test_b, test_b, real_size_test_a, test_a,
                    size_test_c, test_c);
  if (FLAGS_printall) {
    printf("   ");
    TempPrintNum(4, test_a);
    printf("\n + ");
    TempPrintNum(real_size_test_b, test_b);
    printf("\n");
    printf(" = ");
    TempPrintNum(k, test_c);
    printf("\n");
    printf("\n");
  }
  if (DigitArrayCompare(4, test_r2, 4, test_c) != 0) {
    printf("Add21 failed\n");
    return false;
  }

  DigitArrayZeroNum(sizeof(test_c) / sizeof(uint64_t), test_c);
  test_a[0] = 0x100000000;
  k = DigitArraySub(real_size_test_b, test_b, real_size_test_a, test_a,
                    size_test_c, test_c);
  if (FLAGS_printall) {
    printf("   ");
    TempPrintNum(real_size_test_b, test_b);
    printf("\n - ");
    TempPrintNum(real_size_test_a, test_a);
    printf("\n");
    printf(" = ");
    TempPrintNum(k, test_c);
    printf("\n");
    printf("\n");
  }
  if (DigitArrayCompare(3, test_r3, 3, test_c) != 0) {
    printf("Sub1 failed\n");
    return false;
  }

  DigitArrayZeroNum(sizeof(test_c) / sizeof(uint64_t), test_c);
  k = DigitArrayMult(real_size_test_y, test_y, real_size_test_x1, test_x1,
                     size_test_c, test_c);
  if (test_c[0] != test_x1[0] || test_c[1] != test_x1[1]) {
    printf("Test 9 failed\n");
    return false;
  }

  DigitArrayZeroNum(sizeof(test_c) / sizeof(uint64_t), test_c);
  k = DigitArrayMult(real_size_test_y, test_y, real_size_test_x, test_x,
                     size_test_c, test_c);
  if (test_c[0] != test_x[0] || test_c[1] != test_x[1]) {
    printf("Test 9 failed\n");
    return false;
  }

  DigitArrayZeroNum(sizeof(test_c) / sizeof(uint64_t), test_c);
  k = DigitArrayMult(real_size_test_x, test_x, real_size_test_y, test_y,
                     size_test_c, test_c);
  if (test_c[0] != test_x[0] || test_c[1] != test_x[1]) {
    printf("Test 9 failed\n");
    return false;
  }

  DigitArrayZeroNum(sizeof(test_c) / sizeof(uint64_t), test_c);
  k = DigitArrayMult(real_size_test_x1, test_x1, real_size_test_x, test_x,
                     size_test_c, test_c);

  DigitArrayZeroNum(sizeof(test_c) / sizeof(uint64_t), test_c);
  k = DigitArrayMult(real_size_test_x, test_x, real_size_test_x, test_x,
                     size_test_c, test_c);
  if (test_c[0] != 1 || test_c[1] != 0 || test_c[2] != 0xfffffffffffffffe ||
      test_c[3] != 0xffffffffffffffff) {
    printf("Test 10 failed\n");
    return false;
  }

  DigitArrayZeroNum(sizeof(test_c) / sizeof(uint64_t), test_c);
  b = 0x2;
  uint64_t t = 0ULL;
  n = size_test_c;
  if (!DigitArrayShortDivisionAlgorithm(real_size_test_t, test_t, b, &n, test_c,
                                        &t)) {
    printf("DigitArrayShortDivisionAlgorithm failed\n");
    return false;
  }
  if (FLAGS_printall) {
    TempPrintNum(real_size_test_t, test_t);
    printf("/ %lx= \n", (unsigned long)b);
    TempPrintNum(n, test_c);
    printf(" remainder: %lx\n", (unsigned long)t);
    printf("\n");
    printf("\n");
  }
  if (DigitArrayCompare(3, test_r4, 3, test_c) != 0 || t != 0x01ULL) {
    printf("DigitArrayShortDivisionAlgorithm failed 2\n");
    return false;
  }

  uint64_t a1 = 0x33ULL;
  uint64_t a2 = 0x7070707066666666ULL;
  uint64_t a3 = 0x222222222ULL;
  uint64_t b1 = 0xaaaaULL;
  uint64_t b2 = 0x5555555555555555ULL;
  uint64_t est = 0ULL;
  EstimateQuotient(a1, a2, a3, b1, b2, &est);
  if (FLAGS_printall) {
    printf("\nEstimateQuotient\n");
    printf("a1: %016lx, a2: %016lx, a3: %016lx\n", (unsigned long)a1,
           (unsigned long)a2, (unsigned long)a3);
    printf("b1: %016lx, b2: %016lx\n", (unsigned long)b1, (unsigned long)b2);
    printf("est: %016lx, est*b1: %016lx\n\n", (unsigned long)est,
           (unsigned long)(est * b1));
  }
  if (est != 0x004d28cf3d103821) {
    printf("EstimateQuotient fails\n");
    return false;
  }

  n = size_test_c;
  m = size_test_z;

  DigitArrayZeroNum(size_test_c, test_c);
  DigitArrayZeroNum(size_test_z, test_z);
  int size_d1 = sizeof(test_d1) / sizeof(uint64_t);
  int size_d2 = sizeof(test_d2) / sizeof(uint64_t);
  int size_d3 = sizeof(test_d3) / sizeof(uint64_t);
  int real_size_d1 = DigitArrayComputedSize(size_d1, test_d1);
  int real_size_d2 = DigitArrayComputedSize(size_d2, test_d2);
  int real_size_d3 = DigitArrayComputedSize(size_d3, test_d3);
  if (!DigitArrayDivisionAlgorithm(real_size_d2, test_d2, real_size_d1, test_d1,
                                   &n, test_c, &m, test_z)) {
    printf("DigitArrayShortDivisionAlgorithm failed\n");
    return false;
  }
  if (DigitArrayComputedSize(size_test_c, test_c) != 3 || test_c[0] != 1ULL ||
      test_c[1] != 0ULL || test_c[2] != 1ULL ||
      DigitArrayComputedSize(size_test_z, test_z) != 1 || test_z[0] != 0ULL) {
    TempPrintNum(real_size_d2, test_d2);
    printf("\n");
    printf("/ ");
    TempPrintNum(real_size_d1, test_d1);
    printf("\n");
    printf("quotient: ");
    TempPrintNum(n, test_c);
    printf("\n");
    printf("remainder: ");
    TempPrintNum(m, test_z);
    printf("\n");
    printf("\n");
    return false;
  }

  n = size_test_c;
  m = size_test_z;

  DigitArrayZeroNum(size_test_c, test_c);
  DigitArrayZeroNum(size_test_z, test_z);
  if (!DigitArrayDivisionAlgorithm(real_size_d3, test_d3, real_size_d1, test_d1,
                                   &n, test_c, &m, test_z)) {
    printf("DigitArrayShortDivisionAlgorithm failed\n");
    return false;
  }
  if (FLAGS_printall) {
    TempPrintNum(real_size_d3, test_d3);
    printf("\n");
    printf("/ ");
    TempPrintNum(real_size_d1, test_d1);
    printf("\n");
    printf("quotient: ");
    TempPrintNum(n, test_c);
    printf("\n");
    printf("remainder: ");
    TempPrintNum(m, test_z);
    printf("\n");
    printf("\n");
  }

  a1 = 2ULL;
  DigitArrayZeroNum(size_test_c, test_c);
  DigitArrayZeroNum(sizeof(test_c) / sizeof(uint64_t), test_c);
  k = DigitArrayMult(real_size_test_x, test_x, 1, &a1, size_test_c, test_c);
  if (FLAGS_printall) {
    TempPrintNum(real_size_test_x, test_x);
    printf(" *  %016lx=\n", (unsigned long)a1);
    printf(" = ");
    TempPrintNum(k, test_c);
    printf("\n");
    printf("\n");
  }

  DigitArrayZeroNum(size_test_c, test_c);
  m = size_test_c;
  DigitArrayShortDivisionAlgorithm(real_size_test_x, test_x, a1, &m, test_c,
                                   &a2);
  if (FLAGS_printall) {
    TempPrintNum(real_size_test_x, test_x);
    printf(" /  %016lx=\n", (unsigned long)a1);
    printf(" = ");
    TempPrintNum(m, test_c);
    printf(", rem: %016lx\n", (unsigned long)a2);
    printf("\n");
    printf("\n");
  }

  char str[128];
  a1 = 29384ULL;

  m = 128;
  if (!DigitArrayConvertToDecimal(1, &a1, &m, str)) {
    printf("DigitArrayConvertToDecimal fails\n");
    return false;
  }
  if (strcmp(str, "29384") != 0) {
    printf("Decimal string(%ld): %s\n", (unsigned long)a1, str);
    return false;
  }

  m = 128;
  memset(str, 0, 128);
  if (!DigitArrayConvertToHex(1, &a1, &m, str)) {
    printf("DigitArrayConvertToHex fails\n");
    return false;
  }
  if (strcmp(str, "00000000000072c8") != 0) {
    printf("Hex string(%lx): %s\n", (unsigned long)a1, str);
    return false;
  }

  m = 128;
  memset(str, 0, 128);
  if (!DigitArrayConvertToDecimal(real_size_test_x, test_x, &m, str)) {
    printf("DigitArrayConvertToDecimal fails\n");
    return false;
  }
  if (strcmp(str, "340282366920938463463374607431768211455") != 0) {
    printf("Decimal string: %s\n", str);
    return false;
  }

  m = 128;
  memset(str, 0, 128);
  if (!DigitArrayConvertToHex(real_size_test_x, test_x, &m, str)) {
    printf("DigitArrayConvertToHex fails\n");
    return false;
  }
  if (strcmp(str, "ffffffffffffffffffffffffffffffff") != 0) {
    printf("Hex string: %s\n", str);
    return false;
  }

  int shift;

  DigitArrayZeroNum(size_test_c, test_c);
  shift = 64;
  m = DigitArrayShiftUp(real_size_test_b, test_b, shift, size_test_c, test_c);
  if (m < 0) {
    printf("error: %d\n", m);
  } 
  if (FLAGS_printall) {
    TempPrintNum(real_size_test_b, test_b);
    printf("<< %d = ", shift);
    TempPrintNum(m, test_c);
    printf("\n");
    printf("\n");
  }

  DigitArrayZeroNum(size_test_c, test_c);
  shift = 72;
  m = DigitArrayShiftUp(real_size_test_b, test_b, shift, size_test_c, test_c);
  if (m < 0) {
    printf("error: %d\n", m);
  }
  if (FLAGS_printall) {
    printf("<< %d = \n", shift);
    TempPrintNum(m, test_c);
    printf("\n");
    printf("\n");
  }

  DigitArrayZeroNum(size_test_c, test_c);
  shift = 64;
  m = DigitArrayShiftDown(real_size_test_b, test_b, shift, size_test_c, test_c);
  if (m < 0) {
    printf("error: %d\n", m);
  }
  if (FLAGS_printall) {
    TempPrintNum(real_size_test_b, test_b);
    printf(">> %d = ", shift);
    TempPrintNum(m, test_c);
    printf("\n");
    printf("\n");
  }

  DigitArrayZeroNum(size_test_c, test_c);
  shift = 72;
  m = DigitArrayShiftDown(real_size_test_b, test_b, shift, size_test_c, test_c);
  if (m < 0) {
    printf("error: %d\n", m);
  } 
  if (FLAGS_printall) {
    TempPrintNum(real_size_test_b, test_b);
    printf(">> %d = ", shift);
    TempPrintNum(m, test_c);
    printf("\n");
    printf("\n");
  }
  printf("\nEND_SIMPLETEST\n\n");

  return true;
}

bool print_tests() {
  BigNum neg(Big_Three);

  printf("BEGIN PRINT_TESTS\n");
  PrintNumToConsole(Big_One, 16ULL);
  printf("\n");
  PrintNumToConsole(Big_Three, 16ULL);
  printf("\n");
  neg.sign_ = true;
  PrintNumToConsole(neg, 10ULL);
  printf("\n");

  BigNum* p = new BigNum(4);
  p->value_[3] = 0xffffffff00000001ULL;
  p->value_[2] = 0ULL;
  p->value_[1] = 0x00000000ffffffffULL;
  p->value_[0] = 0xffffffffffffffffULL;
  p->Normalize();

  PrintNumToConsole(*p, 16ULL);
  printf("\n");
  PrintNumToConsole(*p, 10ULL);
  printf("\n");
  printf("END PRINT_TESTS\n");

  return true;
}

bool CompareEccAdd(EccCurve& c, CurvePoint& P, CurvePoint& Q) {
  CurvePoint R1(9);
  CurvePoint R2(9);

  if (!EccAdd(c, P, Q, R1)) {
    printf("CompareEccAdd fails in EccMult\n");
    return false;
  }
  if (!ProjectiveAdd(c, P, Q, R2)) {
    printf("CompareEccAdd fails in ProjectiveMult\n");
    return false;
  }
  if (!ProjectiveToAffine(c, R2)) {
    printf("CompareEccAdd fails in ProjectiveToAffine\n");
    return false;
  }
  if (FLAGS_printall) {
    P.PrintPoint();
    printf(" + ");
    Q.PrintPoint();
    printf("\n");
    R1.PrintPoint();
    printf("\n");
    R2.PrintPoint();
    printf("\n");
    printf("\n");
  }
  if (BigCompare(*R1.x_, *R2.x_) != 0 || BigCompare(*R1.y_, *R2.y_) != 0) {
    printf("CompareEccAdd results differ\n");
    return false;
  }
  return true;
}

bool CompareEccMultiply(EccCurve& c, BigNum& x, CurvePoint& P) {
  CurvePoint R1(9);
  CurvePoint R2(9);

  if (!EccMult(c, P, x, R1)) {
    printf("CompareEccMultiply fails in EccMult\n");
    return false;
  }
  if (!ProjectivePointMult(c, x, P, R2)) {
    printf("CompareEccMultiply fails in ProjectiveMult\n");
    return false;
  }
  if (!ProjectiveToAffine(c, R2)) {
    printf("CompareEccMultiply fails in ProjectiveToAffine\n");
    return false;
  }
  if (FLAGS_printall) {
    PrintNumToConsole(x, 10ULL);
    P.PrintPoint();
    printf("\n");
    R1.PrintPoint();
    printf("\n");
    R2.PrintPoint();
    printf("\n");
    printf("\n");
  }
  if (BigCompare(*R1.x_, *R2.x_) != 0 || BigCompare(*R1.y_, *R2.y_) != 0) {
    printf("CompareEccMultiply results differ\n");
    return false;
  }
  return true;
}

// --------------------------------------------------------------------------------------

bool getrand_time_tests(int num_tests) {
  printf("\nGETRAND_TIME_TESTS\n");
  byte buf[64];
  int size = 256;
  int num_tests_executed;

  uint64_t cycles_start_test = ReadRdtsc();
  for (num_tests_executed = 0; num_tests_executed < num_tests;
       num_tests_executed++) {
    if (!GetCryptoRand(size, buf)) {
      return false;
    }
  }
  uint64_t cycles_end_test = ReadRdtsc();
  uint64_t cycles_diff = cycles_end_test - cycles_start_test;
  printf("get_rand_time_test number of successful tests: %d\n",
         num_tests_executed);
  printf("total ellapsed time %le\n",
         ((double)cycles_diff) / ((double)cycles_per_second));
  printf("time per %d bit pull %le\n", size,
         ((double)cycles_diff) /
             ((double)(num_tests_executed * cycles_per_second)));
  printf("\nEND GETRAND_TIME_TESTS\n");
  return true;
}

bool basic_tests() {
  printf("\nBASIC_TESTS\n");
  BigNum a(2);
  a.value_[0] = 0xaa000000000aa000ULL;
  a.value_[1] = 0xaaaaaaaaULL;
  a.Normalize();
  BigNum b(2);
  b.value_[0] = 0x0a000000000aa000ULL;
  b.value_[1] = 0xaaaaaaaaULL;
  b.Normalize();
  BigNum c(2);
  c.value_[0] = 0xaa000000000aa000ULL;
  c.value_[1] = 0xaaaaaaaaULL;
  c.sign_ = true;
  c.Normalize();
  PrintNumToConsole(a, 16ULL);
  printf("\n");
  PrintNumToConsole(b, 16ULL);
  printf("\n");
  PrintNumToConsole(c, 16ULL);
  printf("\n");
  if (!Big_One.IsOne()) return false;
  if (!Big_Zero.IsZero()) return false;
  if (Big_Zero.IsOne()) return false;
  if (Big_One.IsZero()) return false;
  if (!Big_One.IsPositive()) return false;
  if (!c.IsNegative()) return false;
  if (c.IsPositive()) return false;
  if (BigCompare(a, b) <= 0) return false;
  if (DigitArrayCompare(2, a.value_, 2, b.value_) <= 0) return false;
  if (DigitArrayCompare(2, a.value_, 2, a.value_) != 0) return false;
  if (DigitArrayCompare(2, b.value_, 2, a.value_) >= 0) return false;

  uint64_t b1 = 0xaaaaULL;
  int m = HighBitInDigit(b1);
  if (m != 16) {
    printf("HighBit of %016lx is %d\n", (unsigned long)b1, m);
    return false;
  }
  printf("END BASIC_TESTS\n");
  return true;
}

bool convert_tests() {
  printf("\nCONVERT_TESTS\n");
  bool ret = true;
  BigNum p(4);

  p.value_[3] = 0xffffffff00000001ULL;
  p.value_[2] = 0ULL;
  p.value_[1] = 0x00000000ffffffffULL;
  p.value_[0] = 0xffffffffffffffffULL;
  p.Normalize();

  string* s = BigConvertToDecimal(p);
  const char* s1 =
      "(11579208921035624876269744694940757353008614341529031419553363130886709"
      "7853951)";
  BigNum* t = BigConvertFromDecimal(s->c_str());
  PrintNumToConsole(p, 10);
  printf("\n");
  printf("s: %s\n", s->c_str());
  PrintNumToConsole(*t, 10);
  printf("\n");
  if (strcmp(s1, s->c_str()) != 0) {
    // ret= false;
    goto done;
  }
  if (BigCompare(p, *t) != 0) {
    // ret= false;
    goto done;
  }

done:
  printf("END CONVERT_TESTS\n");
  return ret;
}

bool bit_tests() {
  BigNum a(2);
  a.value_[0] = 0xaa000000000aa000ULL;
  a.value_[1] = 0xaaaaaaaaULL;
  a.Normalize();
  int i, n;

  printf("\nBIT_TESTS\n");
  i = BigHighDigit(a);
  if (i != 2) {
    printf("HighDigit: %d\n", i);
    PrintNumToConsole(a, 16ULL);
    printf("\n");
    return false;
  }
  i = BigMaxPowerOfTwoDividing(a);
  if (i != 13) {
    printf("BigMaxPowerOfTwoDividing: %d\n", i);
    return false;
  }
  n = BigHighBit(a);
  printf("Bits on: ");
  for (i = 1; i <= n; i++) {
    if (BigBitPositionOn(a, i)) printf("%d ", i);
  }
  printf("\nEND BIT_TESTS\n");
  if (n != 96) {
    printf("HighBit: %d\n", n);
    return false;
  }
  return true;
}

bool shift_tests() {
  BigNum a(2);
  a.value_[0] = 0xff00ff00ff00ff00ULL;
  a.value_[1] = 0xff00ff00ULL;
  a.Normalize();
  BigNum r(4);

  printf("\nSHIFT_TESTS\n");
  int n = 64;
  if (FLAGS_printall) {
    PrintNumToConsole(a, 16ULL);
    printf(", shift %d= ", n);
    PrintNumToConsole(r, 16ULL);
    printf("\n");
    printf("\n");
  }
  if (!BigShift(a, n, r)) return false;

  r.ZeroNum();
  n = -64;
  if (!BigShift(a, n, r)) return false;
  if (FLAGS_printall) {
    PrintNumToConsole(a, 16ULL);
    printf(", shift %d= ", n);
    PrintNumToConsole(r, 16ULL);
    printf("\n");
    printf("\n");
  }

  r.ZeroNum();
  n = 2;
  if (FLAGS_printall) {
    PrintNumToConsole(a, 16ULL);
    printf(", shift %d= ", n);
    PrintNumToConsole(r, 16ULL);
    printf("\n");
    printf("\n");
  }
  if (!BigShift(a, n, r)) return false;

  r.ZeroNum();
  n = -2;
  if (!BigShift(a, n, r)) return false;
  if (FLAGS_printall) {
    PrintNumToConsole(a, 16ULL);
    printf(", shift %d= ", n);
    PrintNumToConsole(r, 16ULL);
    printf("\n");
    printf("\n");
  }

  r.ZeroNum();
  n = 66;
  if (!BigShift(a, n, r)) return false;
  if (FLAGS_printall) {
    PrintNumToConsole(a, 16ULL);
    printf(", shift %d= ", n);
    PrintNumToConsole(r, 16ULL);
    printf("\n");
    printf("\n");
  }

  r.ZeroNum();
  n = -66;
  if (!BigShift(a, n, r)) return false;
  if (FLAGS_printall) {
    PrintNumToConsole(a, 16ULL);
    printf(", shift %d= ", n);
    PrintNumToConsole(r, 16ULL);
    printf("\n");
    printf("\n");
  }

  r.ZeroNum();

  printf("END SHIFT_TESTS\n");
  return true;
}

bool raw_arith_tests() {
  printf("\nRAW_ARITH_TESTS\n");
  int size_a = 4;
  int size_b = 5;
  int size_c = 5;
  int i;
  uint64_t a[4];
  uint64_t b[5];
  uint64_t c[5];
  int size_d = 15;
  uint64_t d[15];

  DigitArrayZeroNum(size_d, d);
  d[4] = 1ULL;
  if (DigitArrayComputedSize(size_d, d) != 5) {
    printf("DigitArrayComputedSize test 1 failed\n");
    return false;
  }
  DigitArrayZeroNum(size_d, d);
  d[10] = 1ULL;
  if (DigitArrayComputedSize(size_d, d) != 11) {
    printf("DigitArrayComputedSize test 2 failed\n");
    return false;
  }
  DigitArrayZeroNum(size_d, d);
  if (DigitArrayComputedSize(size_d, d) != 1) {
    printf("DigitArrayComputedSize test 3 failed\n");
    return false;
  }

  for (i = 0; i < 4; i++) {
    a[i] = (uint64_t)i;
    b[i] = (uint64_t)i + 0xfffff0000;
  }
  c[0] = 1ULL;

  if (DigitArrayIsZero(size_c, c)) {
    printf("DigitArrayIsZero test failed\n");
    return false;
  }
  DigitArrayZeroNum(size_c, c);
  if (!DigitArrayIsZero(size_c, c)) {
    printf("DigitArrayIsZero test failed\n");
    return false;
  }
  if (!DigitArrayCopy(size_a, a, size_c, c)) {
    printf("DigitArrayIsZero test failed\n");
    return false;
  }
  if (DigitArrayCopy(size_c, c, size_a, a)) {
    printf("DigitArrayIsZero test failed\n");
    return false;
  }
  if (DigitArrayCompare(size_a, a, size_c, c) != 0) {
    printf("DigitArrayCompare test failed\n");
    return false;
  }
  if (DigitArrayCompare(size_b, b, size_c, c) != 1) {
    printf("DigitArrayCompare test failed\n");
    return false;
  }
  if (DigitArrayCompare(size_c, c, size_b, b) != (-1)) {
    printf("DigitArrayCompare test failed\n");
    return false;
  }
  for (i = 3; i > 0; i--) {
    if (DigitArrayComputedSize(size_c, c) != (i + 1)) {
      printf("DigitComputedSizeTest test %d failed (value: %d)\n", i,
             DigitArrayComputedSize(size_c, c));
      printf("c[%d]= %llx\n", i, (uint64_t)c[i]);
      return false;
    }
    c[i] = 0ULL;
  }
  c[0] = 0ULL;
  if (DigitArrayComputedSize(size_c, c) != 1) {
    printf("DigitComputedSizeTest test failed\n");
    return false;
  }
  int n = DigitArrayComputedSize(size_a, a);
  int k;
  for (i = 0; i < 2; i++) {
    if (FLAGS_printall) {
      printf("a: ");
      TempPrintNum(size_a, a);
      printf("\n");
      printf("d: ");
      TempPrintNum(size_d, d);
      printf("\n");
    printf("\n");
    }
    if (DigitArrayShiftUp(size_a, a, 64 * i, size_d, d) < 0) {
      printf("DigitArrayShiftUp test failed\n (1)");
      return false;
    }
    k = DigitArrayComputedSize(size_d, d);
    if (k != (n + i)) {
      printf("DigitArrayShiftUp test failed. n: %d, i: %d, k: %d\n", n, i, k);
      return false;
    }
    if (DigitArrayShiftDown(size_a, a, 64 * i, size_d, d) < 0) {
      printf("DigitArrayShiftDown test failed (1)\n");
      return false;
    }
    k = DigitArrayComputedSize(size_d, d);
    if (k != (n - i)) {
      printf("DigitArrayShiftDown test failed. n: %d, i: %d, k: %d\n", n, i, k);
      return false;
    }
  }

  uint64_t x, y, z, t, u, v;
  x = 0xfffffffffffffffd;
  y = 0xffff;
  for (i = 0; i < 256; i++) {
    z = (uint64_t)i;
    Uint64AddStep(x, z, &u, &t);
    if (i > 3 && t == 0) return false;
    Uint64AddStep(y, z, &u, &t);
    if (t == 1) return false;
    x = 0xfffffffffffffffd;
    y = (uint64_t)2 * i;
    z = (uint64_t)i;
    t = (uint64_t)i;
    Uint64MultWithCarryStep(x, y, z, t, &u, &v);
  }
  for (i = 0; i < 4; i++) {
    a[i] = (uint64_t)0xffffffffffffffff;
    b[i] = (uint64_t)0xffffffffffffffff;
  }
  if (DigitArrayAdd(size_a, a, size_b, b, 5, c) < 0) {
    printf("DigitArrayAdd test failed (1)\n");
    return false;
  }
  if (DigitArrayAdd(size_a, a, size_b, b, 4, c) >= 0) {
    printf("DigitArrayAdd test failed (2)\n");
    return false;
  }

  uint64_t a1, a2, a3, b1, b2;
  a1 = 1ULL;
  a2 = 1ULL;
  a3 = 1ULL;
  b1 = 0xffffffffffffffffULL;
  b2 = 1ULL;
  // (a1 a2)_b >= b1_b
  EstimateQuotient(a1, a2, a3, b1, b2, &x);
  if (FLAGS_printall) {
    printf("%lx:%lx/%lx= %lx\n", (long unsigned)a1, (long unsigned)a2,
           (long unsigned)b1, (long unsigned)x);
    printf("\n");
  }
  b1 = 0xfffffffffffffffULL;
  EstimateQuotient(a1, a2, a3, b1, b2, &x);
  if (FLAGS_printall) {
    printf("%lx:%lx/%lx= %lx\n", (long unsigned)a1, (long unsigned)a2,
         (long unsigned)b1, (long unsigned)x);
  }

  /*
    void    Uint64AddStep(uint64_t a, uint64_t b, uint64_t* result, uint64_t*
    carry);
    void    Uint64SubStep(uint64_t a, uint64_t b, uint64_t* result, uint64_t*
    borrow);
    void    Uint64MultStep(uint64_t a, uint64_t b, uint64_t* result, uint64_t*
    carry);
    void    Uint64DivStep(uint64_t a, uint64_t b, uint64_t c,
                      uint64_t* result, uint64_t* carry);
    void    Uint64AddWithCarryStep(uint64_t a, uint64_t b, uint64_t carry_in,
                               uint64_t* result, uint64_t* carry_out);
    void    Uint64SubWithBorrowStep(uint64_t a, uint64_t b, uint64_t borrow_in,
                                uint64_t* result, uint64_t* borrow_out);
    int     DigitArrayAdd(int size_a, uint64_t* a, int size_b, uint64_t* b,
                          int size_result, uint64_t* result);
    int     DigitArraySub(int size_a, uint64_t* a, int size_b, uint64_t* b,
                          int size_result, uint64_t* result);
    int     DigitArrayMult(int size_a, uint64_t* a, int size_b, uint64_t* b,
                       int size_result, uint64_t* result);
    int     DigitArraySquare(int size_a, uint64_t* a, int size_result,
                        uint64_t* result);
    int     DigitArrayMultBy(int capacity_a, int size_a, uint64_t* a, uint64_t
    x);
    int     DigitArrayAddTo(int capacity_a, int size_a, uint64_t* a, int size_b,
                            uint64_t* b);
    int     DigitArraySubFrom(int capacity_a, int size_a, uint64_t* a, int
    size_b,
                          uint64_t* b);
    bool    DigitArrayShortDivisionAlgorithm(int size_a, uint64_t* a, uint64_t
    b,
                                    int* size_q, uint64_t* q, uint64_t* r);
    bool    DigitArrayDivisionAlgorithm(int size_a, uint64_t* a, int size_b,
                          uint64_t* b, int* size_q, uint64_t* q, int* size_r,
                          uint64_t* r);
   */
  printf("END RAW_ARITH_TESTS\n");
  return true;
}

uint64_t square_tests[] = {0x1ULL, 0x2ULL,  0x4ULL,  0x5ULL, 0x6ULL, 0x7ULL,
                           0x8ULL, 0x9ULL,  0xaULL,  0xbULL, 0xcULL, 0xdULL,
                           0xeULL, 0xf1ULL, 0xe1ULL, 0xe1ULL};

bool square_test() {
  int size_a = 2;
  uint64_t a[10];
  int size_r = 10;
  uint64_t r[10];
  int size_s = 10;
  uint64_t s[10];
  int i, j, k, n;

  memset(a, 0, sizeof(uint64_t) * 10);
  memset(r, 0, sizeof(uint64_t) * 10);
  a[0] = 0xffffffffffffffffULL;
  a[1] = 0xffffffffffffffffULL;

  n = DigitArraySquare(size_a, a, size_r, r);
  k = DigitArrayMult(size_a, a, size_a, a, size_s, s);
  if (FLAGS_printall) {
    printf("a: ");
    TempPrintNum(size_a, a);
    printf("\n");
    printf("r: ");
    TempPrintNum(n, r);
    printf("\n");
    printf("s: ");
    TempPrintNum(k, s);
    printf("\n");
    printf("\n");
  }
  if (k != n || 0 != DigitArrayCompare(n, r, k, s)) {
    printf("square test doesnt match\n");
    return false;
  } 

  for (i = 0; i < 6; i++) {
    memset(a, 0, sizeof(uint64_t) * size_a);
    memset(r, 0, sizeof(uint64_t) * size_r);
    memset(s, 0, sizeof(uint64_t) * size_s);

    for (j = 0; j < 4; j++) a[j] = square_tests[j];

    k = DigitArrayMult(size_a, a, size_a, a, size_s, s);
    n = DigitArraySquare(size_a, a, size_r, r);
    if (k != n || 0 != DigitArrayCompare(k, r, n, s)) {
      printf("square test doesnt match\n");
      return false;
    }
    if (FLAGS_printall) {
      printf("a: ");TempPrintNum(size_a, a); printf("\n");
      printf("r: ");TempPrintNum(k, r); printf("\n");
      printf("s: ");TempPrintNum(k, s); printf("\n");
      printf("\n");
    }
  }
  return true;
}

bool addto_subfrom_and_compare(BigNum& a, BigNum& b) {
  BigNum c(a.capacity_ + 1);

  a.CopyTo(c);
  if (!BigUnsignedAddTo(a, b)) {
    printf("BigUnsignedAddTo failed\n");
    return false;
  }
  if (FLAGS_printall) {
    printf("a: ");
    TempPrintNum(a.size_, a.value_);
    printf(" += ");
    printf("b: ");
    TempPrintNum(b.size_, b.value_);
    printf("\n");
    printf("\n");
  }
  if (!BigUnsignedSubFrom(a, b)) {
    printf("BigUnsignedSub failed\n");
    return false;
  }
  if (FLAGS_printall) {
    printf("a: ");
    TempPrintNum(a.size_, a.value_);
    printf("\n");
    printf("b: ");
    TempPrintNum(b.size_, b.value_);
    printf("\n");
    printf("c: ");
    TempPrintNum(c.size_, c.value_);
    printf("\n");
    printf("\n");
  }
  if (BigCompare(a, c) != 0) {
    printf("Unsigned AddTo/SubFrom dont match\n\n");
    return false;
  }
  return true;
}

bool inc_dec_and_compare(BigNum& a) {
  BigNum c(a.capacity_ + 1);

  a.CopyTo(c);
  if (!BigUnsignedInc(a)) {
    printf("BigUnsignedInc failed\n");
    return false;
  }
  if (FLAGS_printall) {
    printf("a: ");
    TempPrintNum(a.size_, a.value_);
    printf("\n");
    printf("\n");
  }
  if (!BigUnsignedDec(a)) {
    printf("BigUnsignedDec failed\n");
    return false;
  }
  if (FLAGS_printall) {
    printf("a: ");
    TempPrintNum(a.size_, a.value_);
    printf("\n");
    printf("c: ");
    TempPrintNum(c.size_, c.value_);
    printf("\n");
    printf("\n");
  }
  if (BigCompare(a, c) != 0) {
    printf("Unsigned Inc/Dec dont match\n\n");
    return false;
  }
  return true;
}

bool add_sub_and_compare(BigNum& a, BigNum& b, BigNum& c, BigNum& d) {
  if (!BigUnsignedAdd(a, b, c)) {
    printf("BigUnsignedAdd failed\n");
    return false;
  }
  if (FLAGS_printall) {
    printf("a: ");
    TempPrintNum(a.size_, a.value_);
    printf("\n");
    printf("b: ");
    TempPrintNum(b.size_, b.value_);
    printf("\n");
    printf("c: ");
    TempPrintNum(c.size_, c.value_);
    printf("\n");
    printf("\n");
  }
  if (!BigUnsignedSub(c, a, d)) {
    printf("BigUnsignedSub failed\n");
    return false;
  }
  if (FLAGS_printall) {
    printf("c: ");
    TempPrintNum(c.size_, c.value_);
    printf("\n");
    printf("a: ");
    TempPrintNum(a.size_, a.value_);
    printf("\n");
    printf("d: ");
    TempPrintNum(d.size_, d.value_);
    printf("\n");
    printf("\n");
  }
  if (BigCompare(b, d) != 0) {
    printf("Unsigned Add/Sub dont match\n\n");
    return false;
  }
  return true;
}

bool mult_div_and_compare(BigNum& a, BigNum& b, BigNum& c, BigNum& d) {
  BigNum r(c.capacity_);
  BigNum q(c.capacity_);

  if (!BigUnsignedMult(a, b, c)) {
    printf("BigUnsignedMult failed\n");
    return false;
  }
  if (FLAGS_printall) {
    printf("a: ");
    TempPrintNum(a.size_, a.value_);
    printf("\n");
    printf("b: ");
    TempPrintNum(b.size_, b.value_);
    printf("\n");
    printf("c: ");
    TempPrintNum(c.size_, c.value_);
    printf("\n");
    printf("\n");
  }
  if (!BigUnsignedDiv(c, b, d)) {
    printf("BigUnsignedDiv failed\n");
    return false;
  }
  if (FLAGS_printall) {
    printf("c: ");
    TempPrintNum(c.size_, c.value_);
    printf("\n");
    printf("b: ");
    TempPrintNum(b.size_, b.value_);
    printf("\n");
    printf("d: ");
    TempPrintNum(d.size_, d.value_);
    printf("\n");
    printf("\n");
  }
  if (BigCompare(a, d) != 0) {
    printf("Unsigned Mult/Div dont match\n\n");
    return false;
  }
  if (!BigUnsignedEuclid(c, b, q, r)) {
    printf("BigUnsignedEuclid fails\n");
  }
  if (!r.IsZero()) {
    printf("BigUnsignedEuclid fails, remainder not zero\n");
  }
  if (BigCompare(q, d) != 0) {
    printf("BigUnsignedEuclid quotient not dividend\n");
    return false;
  }
  if (FLAGS_printall) {
    printf("c: ");
    TempPrintNum(c.size_, c.value_);
    printf("\n");
    printf("b: ");
    TempPrintNum(b.size_, b.value_);
    printf("\n");
    printf("d: ");
    TempPrintNum(d.size_, d.value_);
    printf("\n");
    printf("q: ");
    TempPrintNum(q.size_, q.value_);
    printf("\n");
    printf("r: ");
    TempPrintNum(r.size_, r.value_);
    printf("\n");
    printf("\n");
  }
  return true;
}

bool unsigned_arith_tests() {
  printf("\nUNSIGNED_ARITH_TESTS\n");
  BigNum a(8);
  BigNum b(8);
  BigNum c(8);
  BigNum d(8);
  BigNum r(8);
  int i;
  int k;

  for (k = 0; k < 128; k++) {
    for (i = 0; i < 4; i++) {
      a.value_[i] = (uint64_t)i + 5673 * k;
      b.value_[i] = (uint64_t)i + 0xfffff0000 + 27 * k;
    }
    a.Normalize();
    b.Normalize();
    if (!add_sub_and_compare(a, b, c, d)) {
      return false;
    }

    for (i = 0; i < 2; i++) {
      a.value_[i] = (uint64_t)i + 5673 * k;
      b.value_[i] = (uint64_t)i + 0xfffff0000 + 27 * k;
    }
    a.Normalize();
    b.Normalize();
    if (!mult_div_and_compare(a, b, c, d)) {
      return false;
    }
    for (i = 0; i < 4; i++) {
      a.value_[i] = (uint64_t)i + 5673 * k;
      b.value_[i] = (uint64_t)i + 0xfffff0000 + 27 * k;
    }
    a.Normalize();
    b.Normalize();
    if (!inc_dec_and_compare(a)) return false;
    if (!addto_subfrom_and_compare(a, b)) return false;
  }

  for (i = 0; i < 4; i++) {
    a.value_[i] = (uint64_t)0xffffffffffffffff;
    b.value_[i] = (uint64_t)0xffffffffffffffff;
  }
  a.Normalize();
  b.Normalize();
  if (!inc_dec_and_compare(a)) return false;
  if (!addto_subfrom_and_compare(a, Big_One)) return false;

  BigNum Q(17);
  BigNum R(17);

  const char* a_str =
      "123156823404782910121024946712567222665642798668420718538939445897248991"
      "733851289416549247722965050432339644199386046370655483770528664974881940"
      "590501302765437761575275991136879199642615707975737850000859496491042042"
      "357510457188664283912908488011210409384512322567663463163682741741325385"
      "5638120984384315025";
  const char* b_str =
      "122980474900061984380727174111076580838572096470049122456004131667359250"
      "138531158095630011520340691199347065433643921865956356389566874187818772"
      "74488908841";

  BigNum* A = BigConvertFromDecimal(a_str);
  string* A_str = BigConvertToDecimal(*A);
  if (strcmp(a_str, A_str->c_str()) != 0) {
    printf("\n\n%s\n\n%s\n\n", a_str, A_str->c_str());
    printf("A-capacity: %d, A-size: %d\n", A->capacity_, A->size_);
    return false;
  }
  BigNum* B = BigConvertFromDecimal(b_str);
  if (!BigUnsignedEuclid(*A, *B, Q, R)) {
    printf("BigUnsignedEuclid failed 1\n");
    return false;
  }

  BigNum AA(8);
  BigNum AB(8);
  BigNum AC(8);
  AA.value_[1] = 1;
  AA.value_[0] = 0;
  AB.value_[0] = 0x8bf67f59d9dcac0d;
  AA.Normalize();
  AB.Normalize();
  BigUnsignedSub(AA, AB, AC);
  if (FLAGS_printall) {
    PrintNumToConsole(AA, 16ULL);
    printf(" - ");
    PrintNumToConsole(AB, 16ULL);
    printf(" = ");
    PrintNumToConsole(AC, 16ULL);
    printf("\n");
    printf("should be: 740980a6262353f3\n");
    printf("\n");
  }
  BigUnsignedSubFrom(AA, AB);
  if (FLAGS_printall) {
    printf("Subfrom: ");
    PrintNumToConsole(AA, 16ULL);
    printf("\n");
    printf("\n");
  }
  printf("END UNSIGNED_ARITH_TESTS\n");
  return true;
}

bool signed_arith_tests() {
  printf("\nSIGNED_ARITH_TESTS\n");
  BigNum a(8);
  BigNum b(8);
  BigNum c(8);
  BigNum d(8);
  int i;
  int k;

  for (k = 0; k < 128; k++) {
    for (i = 0; i < 4; i++) {
      a.value_[i] = (uint64_t)i + 573 * k;
      b.value_[i] = (uint64_t)i + 0xfffff0000 + 27 * k;
    }
    a.Normalize();
    b.Normalize();
    a.sign_ = true;
    if (!BigAdd(b, a, c)) {
      printf("Signed Add failed\n");
      return false;
    }
    if (!BigUnsignedSub(b, a, d)) {
      printf("Unsigned Sub failed\n");
      return false;
    }
    if (FLAGS_printall) {
      printf("a: ");
      TempPrintNum(a.size_, a.value_);
      printf("\n");
      printf("b: ");
      TempPrintNum(b.size_, b.value_);
      printf("\n");
      printf("c: ");
      TempPrintNum(c.size_, c.value_);
      printf("\n");
      printf("d: ");
      TempPrintNum(d.size_, d.value_);
      printf("\n");
      printf("\n");
    }
    if (BigCompare(c, d) != 0) {
      printf("SignedAdd, UnsignedSub mismatch\n");
      return false;
    }
  }

  a.CopyTo(b);
  b.ToggleSign();
  if (!BigAdd(a, b, c)) {
    printf("Signed Add failed\n");
    return false;
  }
  if (FLAGS_printall) {
    printf("c: ");
    TempPrintNum(c.size_, c.value_);
    printf("\n");
    printf("\n");
  }
  if (!c.IsZero()) {
    printf("BigAdd fails (should be 0\n");
    return false;
  }
  if (FLAGS_printall) {
    printf("c: ");
    TempPrintNum(c.size_, c.value_);
    printf("\n");
    printf("\n");
  }
  c.ZeroNum();  // why  do I have to zero?
  if (!BigSub(a, b, c)) {
    printf("Signed Sub failed\n");
    return false;
  }
  if (c.IsZero()) {
    printf("Signed Sub failed: should be 0\n");
    return false;
  }
  printf("END SIGNED_ARITH_TESTS\n");
  return true;
}

bool number_theory_tests() {
  printf("\nNUMBER_THEORY_TESTS\n");
  BigNum s1(1, 97ULL);
  BigNum s2(1, 23ULL);
  BigNum s3(2);
  BigNum s4(2, 21ULL);
  BigNum s5(2, 6ULL);
  BigNum s6(2, 7ULL);
  BigNum x(2);
  BigNum y(2);
  BigNum g(2);
  BigNum b(1, 9ULL);
  BigNum e(1, 22ULL);
  BigNum p(1, 23ULL);
  int i;

  if (!BigMod(s1, s2, s3)) {
    printf("BigMod failed\n");
    return false;
  }
  if (FLAGS_printall) {
    printf("s1: ");
    PrintNumToConsole(s1, 10ULL);
    printf("\n");
    printf("s2: ");
    PrintNumToConsole(s2, 10ULL);
    printf("\n");
    printf("s3: ");
    PrintNumToConsole(s3, 10ULL);
    printf("\n");
    printf("\n");
  }
  if (s3.size_ != 1 || s3.value_[0] != 5ULL) {
    printf("BigMod failed\n");
    return false;
  }

  s1.ToggleSign();
  if (!BigMod(s1, s2, s3)) {
    printf("BigMod failed\n");
    return false;
  }
  if (FLAGS_printall) {
    printf("s1: ");
    PrintNumToConsole(s1, 10ULL);
    printf("\n");
    printf("s2: ");
    PrintNumToConsole(s2, 10ULL);
    printf("\n");
    printf("s3: ");
    PrintNumToConsole(s3, 10ULL);
    printf("\n");
    printf("\n");
  }
  if (s3.size_ != 1 || s3.value_[0] != 18ULL) {
    printf("BigMod 2 failed\n");
    return false;
  }
  s1.ToggleSign();

  if (!BigModAdd(s4, s5, s2, s3)) {
    printf("BigModAdd failed\n");
    return false;
  }
  if (FLAGS_printall) {
    printf("s4: ");
    PrintNumToConsole(s4, 10ULL);
    printf("\n");
    printf("s5: ");
    PrintNumToConsole(s5, 10ULL);
    printf("\n");
    printf("s2: ");
    PrintNumToConsole(s2, 10ULL);
    printf("\n");
    printf("s3: ");
    PrintNumToConsole(s3, 10ULL);
    printf("\n");
    printf("\n");
  }
  if (s3.size_ != 1 || s3.value_[0] != 4ULL) {
    printf("ModAdd failed\n");
    return false;
  }

  if (!BigModSub(s4, s5, s2, s3)) {
    printf("BigModSub failed\n");
    return false;
  }
  if (FLAGS_printall) {
    PrintNumToConsole(s4, 10ULL);
    printf("\n");
    printf("s5: ");
    PrintNumToConsole(s5, 10ULL);
    printf("\n");
    printf("s2: ");
    PrintNumToConsole(s2, 10ULL);
    printf("\n");
    printf("s3: ");
    PrintNumToConsole(s3, 10ULL);
    printf("\n");
    printf("\n");
  }
  if (s3.size_ != 1 || s3.value_[0] != 15ULL) {
    printf("BigModSub 1 failed\n");
    return false;
  }

  if (FLAGS_printall) {
    printf("s4: ");
    PrintNumToConsole(s4, 10ULL);
    printf("\n");
    printf("s5: ");
    PrintNumToConsole(s5, 10ULL);
    printf("\n");
    printf("s2: ");
    PrintNumToConsole(s2, 10ULL);
    printf("\n");
    printf("s3: ");
    PrintNumToConsole(s3, 10ULL);
    printf("\n");
    printf("\n");
  }
  if (!BigModSub(s5, s4, s2, s3)) {
    printf("BigModSub failed\n");
    return false;
  }
  if (s3.size_ != 1 || s3.value_[0] != 8ULL) {
    printf("BigModSub 2 failed\n");
    return false;
  }

  if (!BigModMult(s4, s5, s2, s3)) {
    printf("BigModMult failed\n");
    return false;
  }
  if (FLAGS_printall) {
    printf("s4: ");
    PrintNumToConsole(s4, 10ULL);
    printf("\n");
    printf("s5: ");
    PrintNumToConsole(s5, 10ULL);
    printf("\n");
    printf("s2: ");
    PrintNumToConsole(s2, 10ULL);
    printf("\n");
    printf("s3: ");
    PrintNumToConsole(s3, 10ULL);
    printf("\n");
    printf("\n");
  }
  if (s3.size_ != 1 || s3.value_[0] != 11ULL) {
    printf("BigModMult failed\n");
    return false;
  }

  if (!BigExtendedGCD(s4, s5, x, y, g)) {
    printf("BigExtendedGCD failed\n");
    return false;
  }
  if (FLAGS_printall) {
    printf("s4: ");
    PrintNumToConsole(s4, 10ULL);
    printf("\n");
    printf("s5: ");
    PrintNumToConsole(s5, 10ULL);
    printf("\n");
    printf("\n");
  }
  if (x.size_ != 1 || x.value_[0] != 1ULL || y.size_ != 1 ||
      y.value_[0] != 3ULL || !y.sign_ || g.size_ != 1 || g.value_[0] != 3ULL) {
    printf("BigExtendedGCD failed\n");
    return false;
  }

  if (!BigCRT(s4, s5, s2, s6, g)) {
    printf("BigCRT failed\n");
    return false;
  }
  if (FLAGS_printall) {
    printf("s4: ");
    PrintNumToConsole(s4, 10ULL);
    printf("\n");
    printf("s2: ");
    PrintNumToConsole(s2, 10ULL);
    printf("\n");
    printf("s5: ");
    PrintNumToConsole(s5, 10ULL);
    printf("\n");
    printf("s6: ");
    PrintNumToConsole(s6, 10ULL);
    printf("\n");
    printf("\n");
  }
  if (g.size_ != 1 || g.value_[0] != 90ULL) {
    printf("BigCRT failed\n");
    return false;
  }

  if (!BigModExp(s6, s5, s2, s3)) {
    printf("BigModExp failed\n");
    return false;
  }
  if (FLAGS_printall) {
    printf("s6: ");
    PrintNumToConsole(s6, 10ULL);
    printf("\n");
    printf("s5: ");
    PrintNumToConsole(s5, 10ULL);
    printf("\n");
    printf("s2: ");
    PrintNumToConsole(s2, 10ULL);
    printf("\n");
    printf("s3: ");
    PrintNumToConsole(s3, 10ULL);
    printf("\n");
    printf("\n");
  }
  if (s3.size_ != 1 || s3.value_[0] != 4ULL) {
    printf("BigModExp wrong result\n");
    return false;
  }

  if (FLAGS_printall) {
    printf("b: ");
    PrintNumToConsole(b, 10ULL);
    printf("\n");
    printf("p: ");
    PrintNumToConsole(p, 10ULL);
    printf("\n");
    printf("\n");
  }
  if (!BigModIsSquare(b, p)) {
    printf("BigModIsSquare 1 failed\n");
    return false;
  }

  if (FLAGS_printall) {
    printf("e: ");
    PrintNumToConsole(e, 10ULL);
    printf("\n");
    printf("p: ");
    PrintNumToConsole(p, 10ULL);
    printf("\n");
    printf("\n");
  }
  if (BigModIsSquare(e, p)) {
    printf("BigModIsSquare 2 failed\n");
    return false;
  }

  if (!BigModInv(s6, s2, s3)) {
    printf("BigModInv failed\n");
    return false;
  }
  if (FLAGS_printall) {
    printf("s6: ");
    PrintNumToConsole(s6, 10ULL);
    printf("\n");
    printf("s2: ");
    PrintNumToConsole(s2, 10ULL);
    printf("\n");
    printf("\n");
  }
  if (s3.size_ != 1 || s3.value_[0] != 10ULL) {
    printf("BigModInv wrong result\n");
    return false;
  }

  if (!BigModDiv(s5, s6, s2, s3)) {
    printf("BigModDiv failed\n");
    return false;
  }
  if (FLAGS_printall) {
    printf("s5: ");
    PrintNumToConsole(s5, 10ULL);
    printf(" / ");
    printf("s6: ");
    PrintNumToConsole(s6, 10ULL);
    printf("\n");
    printf("s2: ");
    PrintNumToConsole(s2, 10ULL);
    printf("\n");
    printf("\n");
  }
  if (s3.size_ != 1 || s3.value_[0] != 14ULL) {
    printf("BigModDiv wrong result\n");
    return false;
  }

  if (FLAGS_printall) {
    printf("s2: ");
    PrintNumToConsole(s2, 10ULL);
    printf("\n");
    printf("\n");
  }
  if (!BigIsPrime(s2)) {
    printf("BigIsPrime failed\n");
    return false;
  }

  if (!BigModSquareRoot(b, p, s3)) {
    printf("BigModSquareRoot failed\n");
    return false;
  }
  if (FLAGS_printall) {
    printf("b: ");
    PrintNumToConsole(b, 10ULL);
    printf("\n");
    printf("s3: ");
    PrintNumToConsole(s3, 10ULL);
    printf("\n");
    printf("\n");
  }
  if (s3.size_ != 1 || s3.value_[0] != 3ULL) {
    printf("sqrt failed\n");
    return false;
  }

  if (!BigModTonelliShanks(b, p, s3)) {
    printf("BigModTonelliShanksfailed\n");
    return false;
  }
  if (FLAGS_printall) {
    printf("b: ");
    PrintNumToConsole(b, 10ULL);
    printf("\n");
    printf("s3: ");
    PrintNumToConsole(s2, 10ULL);
    printf("\n");
    printf("\n");
  }
  if (s3.size_ != 1 || s3.value_[0] != 3ULL) {
    printf("BigModTonelliShanks failed\n");
    return false;
  }

  p.value_[0] = 31ULL;
  if (!BigModSquareRoot(b, p, s3)) {
    printf("BigModSquareRoot failed\n");
    return false;
  }
  if (FLAGS_printall) {
    printf("b: ");
    PrintNumToConsole(b, 10ULL);
    printf("\n");
    printf("s3: ");
    PrintNumToConsole(s3, 10ULL);
    printf("\n");
    printf("\n");
  }
  if (s3.size_ != 1 || s3.value_[0] != 28ULL) {
    printf("BigModSquareRoot failed\n");
    return false;
  }

  p.value_[0] = 29ULL;
  if (!BigModSquareRoot(b, p, s3)) {
    printf("BigModSquareRoot failed\n");
    return false;
  }
  if (FLAGS_printall) {
    printf("b: ");
    PrintNumToConsole(b, 10ULL);
    printf("\n");
    printf("s3: ");
    PrintNumToConsole(s3, 10ULL);
    printf("\n");
    printf("\n");
  }
  if (s3.size_ != 1 || s3.value_[0] != 26ULL) {
    printf("BigModSquareRoot failed\n");
    return false;
  }

  int max_rn = 3;
  BigNum* temp_rn[3];
  temp_rn[0] = new BigNum(1, 2ULL);
  temp_rn[1] = new BigNum(1, 3ULL);
  temp_rn[2] = new BigNum(1, 5ULL);

  // BigNum test_prime(1, 97ULL);
  BigNum test_prime(1, 2063ULL);
  if (!BigMillerRabin(test_prime, temp_rn, max_rn)) {
    PrintNumToConsole(test_prime, 10ULL);
    printf("actually is prime\n");
    return false;
  }
  BigNum test_q(16);
  if (!BigGenPrime(test_q, 64)) {
    return false;
  }
  if (FLAGS_printall) {
    PrintNumToConsole(test_q, 10ULL);
    printf(" is proposed prime\n");
    printf("\n");
  }
  test_q.ZeroNum();
  if (!BigGenPrime(test_q, 128)) {
    printf("No prime found\n");
    return false;
  }
  PrintNumToConsole(test_q, 10ULL);
  printf(" is proposed prime\n");
  test_q.ZeroNum();
  if (!BigGenPrime(test_q, 256)) {
    printf("No prime found\n");
    return false;
  }

  // add ExtendedGCD sanity checks
  // exponent index tests
  // a**(p-1)=1 (mod p)

  BigNum A(8);
  BigNum B(8);
  BigNum C(8);
  BigNum M(8);
  BigNum N(8);
  BigNum T(8);
  BigNum U(8);
  BigNum E(8);
  BigNum P(8);
  BigNum PM1(8);

  M.value_[0] = 2ULL;
  M.Normalize();
  E.value_[0] = 12ULL;
  E.Normalize();

  P.value_[0] = 3001;
  P.Normalize();
  PM1.CopyFrom(P);
  if (!BigUnsignedSubFrom(PM1, Big_One)) {
    printf("number_theory_tests: BigUnsignedSubFrom failed\n");
    return false;
  }
  if (!BigModExp(M, PM1, P, N)) {
    printf("number_theory_tests: BigModExp 1 failed\n");
    return false;
  }
  if (FLAGS_printall) {
    PrintNumToConsole(M, 10);
    printf(" ** ");
    PrintNumToConsole(PM1, 10);
    printf(" (mod ");
    PrintNumToConsole(P, 10);
    printf(") = ");
    PrintNumToConsole(N, 10);
    printf("\n");
    printf("\n");
  }
  if (!N.IsOne()) {
    printf("BigModExp 9 failed\n");
    return false;
  }
  P.ZeroNum();
  N.ZeroNum();

  P.value_[3] = 0xffffffff00000001ULL;
  P.value_[2] = 0ULL;
  P.value_[1] = 0x00000000ffffffffULL;
  P.value_[0] = 0xffffffffffffffffULL;
  P.Normalize();
  PM1.CopyFrom(P);
  if (!BigUnsignedSubFrom(PM1, Big_One)) {
    printf("number_theory_tests: BigUnsignedSubFrom failed\n");
    return false;
  }

  BigUnsignedAdd(P, Big_Three, A);
  BigUnsignedAdd(A, A, B);
  BigModMult(A, A, P, N);
  PrintNumToConsole(A, 10);
  printf("**2= ");
  PrintNumToConsole(N, 10);
  printf("\n");
  N.ZeroNum();
  BigModMult(B, B, P, N);
  if (FLAGS_printall) {
    PrintNumToConsole(B, 10);
    printf("**2 = ");
    PrintNumToConsole(N, 10);
    printf("\n");
    printf("\n");
  }
  N.ZeroNum();

  T.value_[0] = 2;
  A.CopyFrom(M);
  for (i = 0; i < 200; i++) {
    BigModMult(A, A, P, B);
    BigModExp(M, T, P, C);
    if (BigCompare(B, C) != 0) {
      printf("Square failure %d\n", i);
      printf("M: ");
      PrintNumToConsole(M, 16);
      printf("\n");
      printf("A: ");
      PrintNumToConsole(A, 16);
      printf("\n");
      printf("B: ");
      PrintNumToConsole(B, 16);
      printf("\n");
      printf("C: ");
      PrintNumToConsole(C, 16);
      printf("\n");
      printf("T: ");
      PrintNumToConsole(T, 16);
      printf("\n");
    }
    BigUnsignedAdd(T, T, U);
    A.CopyFrom(B);
    T.CopyFrom(U);
  }

  if (!BigModExp(M, PM1, P, N)) {
    printf("BigModExp 1 failed\n");
    return false;
  }
  if (BigCompare(N, Big_One) != 0) {
    printf("Fermat fails on p\n");
    return false;
  }
  if (FLAGS_printall) {
    PrintNumToConsole(M, 10);
    printf(" ** ");
    PrintNumToConsole(PM1, 10);
    printf(" (mod  ");
    PrintNumToConsole(P, 10);
    printf(")= ");
    PrintNumToConsole(N, 10);
    printf("\n");
    printf("\n");
  }
  if (!N.IsOne()) {
    printf("BigModExp 11 failed\n");
    return false;
  }

  printf("END NUMBER_THEORY_TESTS\n");
  return true;
}

bool mult_time_test(const char* filename, int size, int num_tests) {
  printf("\nMULT_TIME_TESTS\n");
  struct stat file_info;
  int k = stat(filename, &file_info);
  byte* buf = new byte[512];
  bool ret = true;

  if (k < 0) {
    if (!makeTestData(filename, 2048)) {
      printf("Cant make test data file\n");
      delete buf;
      return false;
    }
  }
  if (!readTestData(filename, 512, buf)) {
    delete buf;
    return false;
  }

  BigNum a(size + 1);
  BigNum b(size + 1);
  BigNum c(2 * size + 2);
  int byte_size_copy = size * sizeof(uint64_t);
  byte* pbuf = buf;
  byte* pa = (byte*)a.value_;
  byte* pb = (byte*)b.value_;
  int num_tests_executed;

  memcpy(pa, pbuf, byte_size_copy);
  pbuf += byte_size_copy;
  memcpy(pb, pbuf, byte_size_copy);
  pbuf += byte_size_copy;
  a.Normalize();
  b.Normalize();

  uint64_t cycles_start_test = ReadRdtsc();
  for (num_tests_executed = 0; num_tests_executed < num_tests;
       num_tests_executed++) {
    if (!BigUnsignedMult(a, b, c)) {
      printf("BigUnsignedMult failed\n");
      ret = false;
      goto done;
    }
    if (FLAGS_printall) {
      PrintNumToConsole(a, 16);
      printf("\n");
      PrintNumToConsole(b, 16);
      printf("\n");
      printf("\n");
    }
  }

done:
  delete buf;
  uint64_t cycles_end_test = ReadRdtsc();
  uint64_t cycles_diff = cycles_end_test - cycles_start_test;
  printf("mult_time_test number of successful tests: %d\n", num_tests_executed);
  printf("total ellapsed time %le\n",
         ((double)cycles_diff) / ((double)cycles_per_second));
  printf("time per %d bit multiply %le\n", size * NBITSINUINT64,
         ((double)cycles_diff) /
             ((double)(num_tests_executed * cycles_per_second)));
  printf("END_MULT_TIME_TESTS\n");
  return ret;
}

bool square_time_test(const char* filename, int size, int num_tests) {
  printf("\nSQUARE_TIME_TESTS\n");
  struct stat file_info;
  int k = stat(filename, &file_info);
  byte* buf = new byte[2048];
  bool ret = true;
  uint64_t cycles_start_test;

  if (k < 0) {
    if (!makeTestData(filename, 2048)) {
      printf("Cant make test data file\n");
      delete buf;
      return false;
    }
  }
  if (!readTestData(filename, 128, buf)) {
    delete buf;
    return false;
  }

  BigNum a(size + 1);
  BigNum c(2 * size + 2);
  int byte_size_copy = size * sizeof(uint64_t);
  byte* pbuf = buf;
  byte* pa = (byte*)a.value_;
  int num_tests_executed;

  memcpy(pa, pbuf, byte_size_copy);
  pbuf += byte_size_copy;
  a.Normalize();

  cycles_start_test = ReadRdtsc();
  for (num_tests_executed = 0; num_tests_executed < num_tests;
       num_tests_executed++) {
    if (!BigUnsignedSquare(a, c)) {
      printf("BigUnsignedMult failed\n");
      PrintNumToConsole(a, 16);
      printf("\n");
      ret = false;
      goto done;
    }
  }

done:
  delete buf;
  uint64_t cycles_end_test = ReadRdtsc();
  uint64_t cycles_diff = cycles_end_test - cycles_start_test;
  printf("mult_time_test number of successful tests: %d\n", num_tests_executed);
  printf("total ellapsed time %le\n",
         ((double)cycles_diff) / ((double)cycles_per_second));
  printf("time per %d bit multiply %le\n", size * NBITSINUINT64,
         ((double)cycles_diff) /
             ((double)(num_tests_executed * cycles_per_second)));
  printf("END_SQUARE_TIME_TESTS\n");
  return ret;
}

bool mult_div_stress(const char* filename, int size, int num_tests) {
  printf("\nMULT_DIV_STRESS_TESTS\n");
  struct stat file_info;
  int k = stat(filename, &file_info);
  byte* buf = new byte[512];
  bool ret = true;
  uint64_t cycles_start_test;

  if (k < 0) {
    if (!makeTestData(filename, 2048)) {
      printf("Cant make test data file\n");
      delete buf;
      return false;
    }
  }
  if (!readTestData(filename, 128, buf)) {
    delete buf;
    return false;
  }

  BigNum a(size + 1);
  BigNum b(size + 1);
  BigNum c(2 * size + 2);
  BigNum d(size + 1);
  int byte_size_copy = size * sizeof(uint64_t);
  byte* pbuf = buf;
  byte* pa = (byte*)a.value_;
  byte* pb = (byte*)b.value_;
  int num_tests_executed;

  memcpy(pa, pbuf, byte_size_copy);
  pbuf += byte_size_copy;
  memcpy(pb, pbuf, byte_size_copy);
  pbuf += byte_size_copy;
  a.Normalize();
  b.Normalize();

  cycles_start_test = ReadRdtsc();
  for (num_tests_executed = 0; num_tests_executed < num_tests;
       num_tests_executed++) {
    if (!a.IsZero() && !b.IsZero() && !mult_div_and_compare(a, b, c, d)) {
      printf("mult_div_and_compare failed\n");
      PrintNumToConsole(a, 16);
      printf("\n");
      PrintNumToConsole(b, 16);
      printf("\n");
      ret = false;
      goto done;
    }
  }

done:
  delete buf;
  uint64_t cycles_end_test = ReadRdtsc();
  uint64_t cycles_diff = cycles_end_test - cycles_start_test;
  printf("mult_div_stress number of successful tests: %d\n",
         num_tests_executed);
  printf("total ellapsed time %le\n",
         ((double)cycles_diff) / ((double)cycles_per_second));
  printf("END_MULT_DIV_STRESS_TESTS\n");
  return ret;
}

bool div_time_test(const char* filename, int size, int num_tests) {
  if (FLAGS_printall) {
    printf("\nDIV_TIME_TESTS\n");
  }
  struct stat file_info;
  int k = stat(filename, &file_info);
  byte* buf = new byte[512];
  bool ret = true;
  uint64_t cycles_start_test;

  if (k < 0) {
    if (!makeTestData(filename, size)) {
      printf("Can't make test data file\n");
      delete buf;
      return false;
    }
  }
  if (!readTestData(filename, 512, buf)) {
    printf("Can't read test data file\n");
    delete buf;
    return false;
  }

  BigNum a(3 * size + 2);
  BigNum b(2 * size + 1);
  BigNum q(2 * size + 1);
  BigNum r(2 * size + 1);
  int byte_size_copy = size * sizeof(uint64_t);
  byte* pbuf = buf;
  byte* pa = (byte*)a.value_;
  byte* pb = (byte*)b.value_;
  int num_tests_executed;

  memcpy(pa, pbuf, 2 * byte_size_copy);
  pbuf += 2 * byte_size_copy;
  memcpy(pb, pbuf, byte_size_copy);
  pbuf += byte_size_copy;
  a.Normalize();
  b.Normalize();

  cycles_start_test = ReadRdtsc();
  for (num_tests_executed = 0; num_tests_executed < num_tests;
       num_tests_executed++) {
    if (FLAGS_printall) {
      PrintNumToConsole(a, 16);
      printf("\n");
      PrintNumToConsole(b, 16);
      printf("\n");
      printf("\n");
    }
    if (!BigUnsignedEuclid(a, b, q, r)) {
      printf("BigUnsignedEuclid failed 2\n");
      ret = false;
      goto done;
    }
  }

done:
  delete buf;
  uint64_t cycles_end_test = ReadRdtsc();
  uint64_t cycles_diff = cycles_end_test - cycles_start_test;
  printf("div_time_test number of successful tests: %d\n", num_tests_executed);
  printf("total ellapsed time %le\n",
         ((double)cycles_diff) / ((double)cycles_per_second));
  if (num_tests_executed > 0)
    printf("time per %d bit divide %le\n", size * NBITSINUINT64,
           ((double)cycles_diff) /
               ((double)(num_tests_executed * cycles_per_second)));
  printf("END_DIV_TIME_TESTS\n");
  return ret;
}

bool exp_time_test(const char* filename, int size, int num_tests) {
  printf("\nEXP_TIME_TESTS\n");
  struct stat file_info;
  int k = stat(filename, &file_info);
  byte* buf = new byte[2048];
  bool ret = true;
  uint64_t cycles_start_test;

  if (k < 0) {
    if (!makeTestData(filename, 2048)) {
      printf("Cant make test data file\n");
      delete buf;
      return false;
    }
  }
  if (!readTestData(filename, 2048, buf)) {
    delete buf;
    return false;
  }

  BigNum b(size + 1);
  BigNum e(size + 1);
  BigNum m(size + 1);
  BigNum r(2 * size + 2);
  int byte_size_copy = size * sizeof(uint64_t);
  byte* pbuf = buf;
  byte* pb = (byte*)b.value_;
  byte* pe = (byte*)e.value_;
  byte* pm = (byte*)m.value_;
  int num_tests_executed;

  memcpy(pb, pbuf, byte_size_copy);
  pbuf += byte_size_copy;
  memcpy(pe, pbuf, byte_size_copy);
  pbuf += byte_size_copy;
  memcpy(pm, pbuf, byte_size_copy);
  pbuf += byte_size_copy;
  b.Normalize();
  e.Normalize();
  m.Normalize();

  for (int u = 0; u < 5; u++) {
    if (m.IsZero() || m.IsOne()) {
      memcpy(pm, pbuf, byte_size_copy);
      pbuf += byte_size_copy;
    }
  }
  if (m.IsZero() || m.IsOne()) {
    printf("MontExp cant get non zero modulus\n");
    return true;
  }

  cycles_start_test = ReadRdtsc();
  for (num_tests_executed = 0; num_tests_executed < num_tests;
       num_tests_executed++) {
    if (!BigModExp(b, e, m, r)) {
      printf("BigModExp failed\n");
      PrintNumToConsole(b, 16);
      printf("\n");
      PrintNumToConsole(e, 16);
      printf("\n");
      PrintNumToConsole(m, 16);
      printf("\n");
      ret = false;
      goto done;
    }
  }

done:
  delete buf;
  uint64_t cycles_end_test = ReadRdtsc();
  uint64_t cycles_diff = cycles_end_test - cycles_start_test;
  printf("exp_time_test number of successful tests: %d\n", num_tests_executed);
  printf("total ellapsed time %le\n",
         ((double)cycles_diff) / ((double)cycles_per_second));
  printf("time per %d bit exp %le\n", size * NBITSINUINT64,
         ((double)cycles_diff) /
             ((double)(num_tests_executed * cycles_per_second)));
  printf("END_EXP_TIME_TESTS\n");
  return ret;
}

bool mont_exp_time_test(const char* filename, int size, int num_tests) {
  printf("\nMONT_EXP_TESTS\n");
  struct stat file_info;
  int k = stat(filename, &file_info);
  byte* buf = new byte[2048];
  bool ret = true;
  uint64_t cycles_start_test;

  if (k < 0) {
    if (!makeTestData(filename, 2048)) {
      printf("Cant make test data file\n");
      delete buf;
      return false;
    }
  }
  if (!readTestData(filename, 2048, buf)) {
    delete buf;
    return false;
  }

  BigNum b(size + 1);
  BigNum e(size + 1);
  BigNum m(size + 1);
  BigNum r(4 * size + 2);
  BigNum m_prime(4 * size + 2);
  int byte_size_copy = size * sizeof(uint64_t);
  byte* pbuf = buf;
  byte* pb = (byte*)b.value_;
  byte* pe = (byte*)e.value_;
  byte* pm = (byte*)m.value_;
  int num_tests_executed;

  memcpy(pb, pbuf, byte_size_copy);
  pbuf += byte_size_copy;
  memcpy(pe, pbuf, byte_size_copy);
  pbuf += byte_size_copy;
  memcpy(pm, pbuf, byte_size_copy);
  pbuf += byte_size_copy;
  b.Normalize();
  e.Normalize();
  m.Normalize();

  for (int u = 0; u < 5; u++) {
    if (m.IsZero() || m.IsOne()) {
      memcpy(pm, pbuf, byte_size_copy);
      pbuf += byte_size_copy;
    }
  }
  if (m.IsZero() || m.IsOne()) {
    printf("MontExp cant get non zero modulus\n");
    return true;
  }

  uint64_t l = BigHighBit(m);
  if (!BigMontParams(m, l, m_prime)) {
    printf("BigMontParams fails\n");
    ret = false;
    goto done;
  }

done:
  delete buf;
  cycles_start_test = ReadRdtsc();
  for (num_tests_executed = 0; num_tests_executed < num_tests;
       num_tests_executed++) {
    if (!BigMontExp(b, e, l, m, m_prime, r)) {
      printf("BigMontExp failed\n");
      PrintNumToConsole(e, 16);
      printf("\n");
      PrintNumToConsole(b, 16);
      printf("\n");
      return false;
    }
  }
  uint64_t cycles_end_test = ReadRdtsc();
  uint64_t cycles_diff = cycles_end_test - cycles_start_test;
  printf("exp_time_test number of successful tests: %d\n", num_tests_executed);
  printf("total ellapsed time %le\n",
         ((double)cycles_diff) / ((double)cycles_per_second));
  printf("time per %d bit exp %le\n", size * NBITSINUINT64,
         ((double)cycles_diff) /
             ((double)(num_tests_executed * cycles_per_second)));
  printf("END_MONT_EXP_TESTS\n");
  return ret;
}

bool square_root_time_test(const char* filename, int size, BigNum& p,
                           int num_tests) {
  printf("\nSQUARE_ROOT_TIME_TESTS\n");
  struct stat file_info;
  int k = stat(filename, &file_info);
  byte* buf = new byte[2048];
  bool ret = true;
  uint64_t cycles_start_test;
  int i;
  int num_tests_executed;

  if (k < 0) {
    if (!makeTestData(filename, 2048)) {
      printf("Cant make test data file\n");
      delete buf;
      return false;
    }
  }
  if (!readTestData(filename, 2048, buf)) {
    delete buf;
    return false;
  }

  BigNum b(size + 1);
  BigNum r(size + 1);
  int byte_size_copy = size * sizeof(uint64_t);
  byte* pbuf = buf;
  byte* pb = (byte*)b.value_;
  uint64_t cycles_end_test;
  uint64_t cycles_diff;

  cycles_start_test = ReadRdtsc();
  memcpy(pb, pbuf, byte_size_copy);
  pbuf += byte_size_copy;
  b.value_[0] &= 0xf;
  b.Normalize();

  for (i = 0; i < 16; i++) {
    b.value_[0] |= (uint64_t)i;
    if (BigModIsSquare(b, p)) {
      break;
    }
  }
  if (i >= 16) {
    printf("square_root_time_test: Cant find square\n");
    ret = false;
    goto done;
  }

  cycles_start_test = ReadRdtsc();
  for (num_tests_executed = 0; num_tests_executed < num_tests;
       num_tests_executed++) {
    if (!BigModSquareRoot(b, p, r)) {
      printf("square_root_time_test: Cant find square\n");
      ret = false;
      break;
    }
  }

  cycles_end_test = ReadRdtsc();
  cycles_diff = cycles_end_test - cycles_start_test;
  printf("square_root_time_test number of successful tests: %d\n",
         num_tests_executed);
  printf("total ellapsed time %le\n",
         ((double)cycles_diff) / ((double)cycles_per_second));
  printf("time per %d bit square root %le\n", size * NBITSINUINT64,
         ((double)cycles_diff) /
             ((double)(num_tests_executed * cycles_per_second)));
done:
  delete buf;
  printf("END_SQUARE_ROOT_TIME_TESTS\n");
  return ret;
}

uint64_t T1 = 0x6666666666666666;

bool ecc_add_time_test(const char* filename, EccKey* ecc_key, int num_tests) {
  printf("\nECC_ADD_TIME_TEST\n");
  if (ecc_key == nullptr) return false;
  CurvePoint P(8);
  CurvePoint Q(8);
  CurvePoint R(8);
  P.MakeZero();
  Q.MakeZero();
  R.MakeZero();

  P.x_->value_[0] = 0x7ULL;
  P.y_->value_[0] = 0x9ULL;
  Q.x_->value_[0] = 0x7ULL;
  Q.y_->value_[0] = 0x9ULL;

  uint64_t cycles_start_test = ReadRdtsc();
  int num_tests_executed;
  for (num_tests_executed = 0; num_tests_executed < num_tests;
       num_tests_executed++) {
    if (!EccAdd(ecc_key->c_, P, Q, R)) {
      return false;
    }
  }
  uint64_t cycles_end_test = ReadRdtsc();
  uint64_t cycles_diff = cycles_end_test - cycles_start_test;
  printf("ecc_add_time_test number of successful tests: %d\n",
         num_tests_executed);
  printf("total ellapsed time %le\n",
         ((double)cycles_diff) / ((double)cycles_per_second));
  printf("time per add %le\n",
         ((double)cycles_diff) /
             ((double)(num_tests_executed * cycles_per_second)));
  printf("END ECC_ADD_TIME_TEST\n");
  return true;
}

bool ecc_double_time_test(const char* filename, EccKey* ecc_key,
                          int num_tests) {
  printf("\nECC_DOUBLE_TIME_TEST\n");
  if (ecc_key == nullptr) return false;
  CurvePoint P(8);
  CurvePoint R(8);
  P.MakeZero();
  R.MakeZero();

  P.x_->value_[0] = 0x7ULL;
  P.y_->value_[0] = 0x9ULL;

  uint64_t cycles_start_test = ReadRdtsc();
  int num_tests_executed;
  for (num_tests_executed = 0; num_tests_executed < num_tests;
       num_tests_executed++) {
    if (!EccDouble(ecc_key->c_, P, R)) {
      return false;
    }
  }
  uint64_t cycles_end_test = ReadRdtsc();
  uint64_t cycles_diff = cycles_end_test - cycles_start_test;
  printf("ecc_double_time_test number of successful tests: %d\n",
         num_tests_executed);
  printf("total ellapsed time %le\n",
         ((double)cycles_diff) / ((double)cycles_per_second));
  printf("time per add %le\n",
         ((double)cycles_diff) /
             ((double)(num_tests_executed * cycles_per_second)));
  printf("END ECC_DOUBLE_TIME_TEST\n");
  return true;
}

bool ecc_projective_compare_tests(EccKey* ecc_key, int n) {
  CurvePoint P(9);
  CurvePoint Q(9);
  BigNum x(9);
  BigNum m(9);
  BigNum u(9);
  BigNum t(9);
  int i;
  int k = 0;

  printf("\nECC_PROJECTIVE_COMPARE_TEST\n");

  m.value_[0] = 0x70707070ULL;
  m.value_[1] = 0x30303030ULL;
  m.value_[2] = 0x30303030ULL;
  m.value_[3] = 0xffffffffffULL;
  m.Normalize();
  x.value_[0] = 0x70707070ULL;
  x.Normalize();
  u.value_[0] = 0x23ULL;
  u.Normalize();
  for (i = 0; i < n; i++) {
    t.ZeroNum();
    if (!BigModAdd(m, u, *(ecc_key->c_.p_), t)) {
      printf("BigModMult failure\n");
      continue;
    }
    t.CopyTo(m);
    if (!EccEmbed(ecc_key->c_, m, P, 10, 500)) {
      printf("Embed failure\n");
      continue;
    }
    if (!EccEmbed(ecc_key->c_, m, Q, 10, 500)) {
      printf("Embed failure\n");
      continue;
    }
    k++;
    if (!CompareEccAdd(ecc_key->c_, P, Q)) {
      return false;
    }
    if (!CompareEccAdd(ecc_key->c_, P, P)) {
      return false;
    }
    if (!CompareEccMultiply(ecc_key->c_, x, P)) {
      return false;
    }
  }

  x.ZeroNum();
  x.CopyFrom(Big_Two);
  if (!CompareEccAdd(ecc_key->c_, ecc_key->g_, ecc_key->g_)) {
    printf("FAILED on generator add 1\n");
    return false;
  }
  if (!CompareEccMultiply(ecc_key->c_, x, ecc_key->g_)) {
    printf("FAILED on generator mult\n");
    return false;
  }
  printf("END ECC_PROJECTIVE_COMPARE_TEST %d\n", k);
  return true;
}

CurvePoint extP(16);

bool ecc_mult_time_test(const char* filename, EccKey* ecc_key, int num_tests) {
  printf("\nECC_MULT_TIME_TEST\n");
  if (ecc_key == nullptr) return false;
  CurvePoint P(8);
  CurvePoint R(8);
  BigNum x(8);
  P.MakeZero();
  R.MakeZero();

  P.x_->value_[0] = 0x7ULL;
  P.y_->value_[0] = 0x9ULL;

  int i;
  for (i = 0; i < 3; i++) x.value_[i] = T1;
  x.Normalize();

  uint64_t cycles_start_test = ReadRdtsc();
  int num_tests_executed;
  for (num_tests_executed = 0; num_tests_executed < num_tests;
       num_tests_executed++) {
    if (!EccMult(ecc_key->c_, P, x, R)) {
      return false;
    }
  }
  uint64_t cycles_end_test = ReadRdtsc();
  uint64_t cycles_diff = cycles_end_test - cycles_start_test;
  printf("ecc_mult__time_test number of successful tests: %d\n",
         num_tests_executed);
  printf("total ellapsed time %le\n",
         ((double)cycles_diff) / ((double)cycles_per_second));
  printf("time per mult %le\n",
         ((double)cycles_diff) /
             ((double)(num_tests_executed * cycles_per_second)));

  cycles_start_test = ReadRdtsc();
  for (num_tests_executed = 0; num_tests_executed < num_tests;
       num_tests_executed++) {
    if (!FasterEccMult(ecc_key->c_, P, x, R)) {
      return false;
    }
  }
  cycles_end_test = ReadRdtsc();
  cycles_diff = cycles_end_test - cycles_start_test;
  printf("ecc_mult__time_test number of successful fast tests: %d\n",
         num_tests_executed);
  printf("total ellapsed time %le\n",
         ((double)cycles_diff) / ((double)cycles_per_second));
  printf("time per faster mult %le\n",
         ((double)cycles_diff) /
             ((double)(num_tests_executed * cycles_per_second)));
  printf("END ECC_MULT_TIME_TEST\n");
  return true;
}

bool ecc_projective_mult_time_test(const char* filename, EccKey* ecc_key,
                                   int num_tests) {
  printf("\nECC_PROJECTIVE_MULT_TIME_TEST\n");
  if (ecc_key == nullptr) return false;
  CurvePoint P(8);
  CurvePoint R(8);
  BigNum x(8);
  P.MakeZero();
  R.MakeZero();

  P.x_->value_[0] = 0x7ULL;
  P.y_->value_[0] = 0x9ULL;

  int i;
  for (i = 0; i < 3; i++) x.value_[i] = T1;
  x.Normalize();

  uint64_t cycles_start_test = ReadRdtsc();
  int num_tests_executed;
  for (num_tests_executed = 0; num_tests_executed < num_tests;
       num_tests_executed++) {
    if (!ProjectivePointMult(ecc_key->c_, x, P, R)) {
      return false;
    }
  }
  uint64_t cycles_end_test = ReadRdtsc();
  uint64_t cycles_diff = cycles_end_test - cycles_start_test;
  printf("ecc_mult__time_test number of successful tests: %d\n",
         num_tests_executed);
  printf("total ellapsed time %le\n",
         ((double)cycles_diff) / ((double)cycles_per_second));
  printf("time per mult %le\n",
         ((double)cycles_diff) /
             ((double)(num_tests_executed * cycles_per_second)));
  printf("END ECC_PROJECTIVE_MULT_TIME_TEST\n");
  return true;
}

bool ecc_extract_time_test(const char* filename, EccKey* ecc_key,
                           int num_tests) {
  printf("\nECC_EXTRACT_TIME_TEST\n");
  if (ecc_key == nullptr) return false;
  CurvePoint P(16);
  BigNum x(16);

  P.CopyFrom(extP);

  uint64_t cycles_start_test = ReadRdtsc();
  int num_tests_executed;
  for (num_tests_executed = 0; num_tests_executed < num_tests;
       num_tests_executed++) {
    if (!EccExtract(ecc_key->c_, P, x, 8)) {
      printf("Extract failure at %d\n", num_tests_executed);
      // return false;
    }
  }
  uint64_t cycles_end_test = ReadRdtsc();
  uint64_t cycles_diff = cycles_end_test - cycles_start_test;
  printf("ecc_extract_time_test number of successful tests: %d\n",
         num_tests_executed);
  printf("total ellapsed time %le\n",
         ((double)cycles_diff) / ((double)cycles_per_second));
  printf("time per extract %le\n",
         ((double)cycles_diff) /
             ((double)(num_tests_executed * cycles_per_second)));
  printf("END ECC_EXTRACT_TIME_TEST\n");
  return true;
}

bool ecc_embed_time_test(const char* filename, EccKey* ecc_key, int num_tests) {
  printf("\nECC_EMBED_TIME_TEST\n");
  if (ecc_key == nullptr) return false;
  CurvePoint P(16);
  BigNum x(16);
  P.MakeZero();
  int i;

  for (i = 0; i < 6; i++) x.value_[0] = T1;

  uint64_t cycles_start_test = ReadRdtsc();
  int num_tests_executed;
  for (num_tests_executed = 0; num_tests_executed < num_tests;
       num_tests_executed++) {
    if (!EccEmbed(ecc_key->c_, x, P, 8, 20)) {
      return false;
    }
  }
  uint64_t cycles_end_test = ReadRdtsc();
  uint64_t cycles_diff = cycles_end_test - cycles_start_test;
  printf("ecc_embed_time_test number of successful tests: %d\n",
         num_tests_executed);
  printf("total ellapsed time %le\n",
         ((double)cycles_diff) / ((double)cycles_per_second));
  printf("time per embed %le\n",
         ((double)cycles_diff) /
             ((double)(num_tests_executed * cycles_per_second)));
  extP.CopyFrom(P);
  printf("END ECC_EMBED_TIME_TEST\n");
  return true;
}

bool rsa1024_gen_time_test(const char* filename, int num_tests) {
  printf("\nRSA1024_GEN_TIME_TEST\n");
  uint64_t cycles_start_test = ReadRdtsc();
  int num_tests_executed;
  RsaKey* key;
  for (num_tests_executed = 0; num_tests_executed < num_tests;
       num_tests_executed++) {
    key = new RsaKey();
    if (!key->GenerateRsaKey("test-key", "test", "test", 1024,
                             COMMON_YEAR_SECONDS)) {
      printf("Cant generate 1024 bit key\n");
      return false;
    }
    delete key;
    key = nullptr;
  }
  uint64_t cycles_end_test = ReadRdtsc();
  uint64_t cycles_diff = cycles_end_test - cycles_start_test;
  printf("rsa1024_gen_time_test number of successful tests: %d\n",
         num_tests_executed);
  printf("total ellapsed time %le\n",
         ((double)cycles_diff) / ((double)cycles_per_second));
  printf("time per gen %le\n",
         ((double)cycles_diff) /
             ((double)(num_tests_executed * cycles_per_second)));
  printf("\nEND RSA1024_GEN_TIME_TEST\n");
  return true;
}

bool rsa2048_gen_time_test(const char* filename, int num_tests) {
  printf("\nRSA2048_GEN_TIME_TEST\n");
  uint64_t cycles_start_test = ReadRdtsc();
  RsaKey* key;
  int num_tests_executed;
  for (num_tests_executed = 0; num_tests_executed < num_tests;
       num_tests_executed++) {
    key = new RsaKey();
    if (!key->GenerateRsaKey("test-key", "test", "test", 2048,
                             COMMON_YEAR_SECONDS)) {
      printf("Cant generate 2048 bit key\n");
      return false;
    }
    delete key;
    key = nullptr;
  }
  uint64_t cycles_end_test = ReadRdtsc();
  uint64_t cycles_diff = cycles_end_test - cycles_start_test;
  printf("rsa1024_gen_time_test number of successful tests: %d\n",
         num_tests_executed);
  printf("total ellapsed time %le\n",
         ((double)cycles_diff) / ((double)cycles_per_second));
  printf("time per gen %le\n",
         ((double)cycles_diff) /
             ((double)(num_tests_executed * cycles_per_second)));
  printf("\nEND RSA1024_GEN_TIME_TEST\n");
  printf("\nEND RSA2048_GEN_TIME_TEST\n");
  return true;
}

bool simple_mult_time_test(const char* filename, int size, int num_tests) {
  printf("\nSIMPLE_MULT_TESTS\n");
  struct stat file_info;
  int k = stat(filename, &file_info);
  byte* buf = new byte[128];
  byte* pbuf = buf;
  uint64_t* pa;
  uint64_t* pb;
  int num_tests_executed;
  bool ret = true;

  if (k < 0) {
    if (!makeTestData(filename, size)) {
      printf("Cant make test data file\n");
      delete buf;
      return false;
    }
  }
  if (!readTestData(filename, 128, buf)) {
    printf("Cant read  test data file %s\n", filename);
    delete buf;
    return false;
  }

  pa = (uint64_t*)pbuf;
  pbuf += sizeof(uint64_t);
  pb = (uint64_t*)pbuf;
  pbuf += sizeof(uint64_t);
  uint64_t carry;
  uint64_t r;

  uint64_t a = *pa;
  uint64_t b = *pb;
  uint64_t cycles_start_test = ReadRdtsc();

  for (num_tests_executed = 0; num_tests_executed < num_tests;
       num_tests_executed++) {
    Uint64MultStep(a, b, &r, &carry);
  }

  delete buf;
  uint64_t cycles_end_test = ReadRdtsc();
  uint64_t cycles_diff = cycles_end_test - cycles_start_test;
  printf("simple_mult_time_test number of successful tests: %d\n",
         num_tests_executed);
  printf("total ellapsed time %le\n",
         ((double)cycles_diff) / ((double)cycles_per_second));
  printf("time per 64 bit multiply %le\n",
         ((double)cycles_diff) /
             ((double)(num_tests_executed * cycles_per_second)));
  printf("END_SIMPLE_MULT_TESTS\n");
  return ret;
}

bool simple_div_time_test(const char* filename, int size, int num_tests) {
  printf("\nSIMPLE_DIV_TESTS\n");
  struct stat file_info;
  int k = stat(filename, &file_info);
  byte* buf = new byte[128];
  byte* pbuf = buf;
  uint64_t* pb;
  uint64_t* pc;
  int num_tests_executed;
  bool ret = true;

  if (k < 0) {
    if (!makeTestData(filename, size)) {
      printf("Cant make test data file\n");
      delete buf;
      return false;
    }
  }
  if (!readTestData(filename, 128, buf)) {
    delete buf;
    return false;
  }

  pb = (uint64_t*)pbuf;
  pbuf += sizeof(uint64_t);
  pc = (uint64_t*)pbuf;
  uint64_t a = 0ULL;
  uint64_t b = *pb;
  uint64_t c = *pc;
  uint64_t carry;
  uint64_t r;

  uint64_t cycles_start_test = ReadRdtsc();
  for (num_tests_executed = 0; num_tests_executed < num_tests;
       num_tests_executed++) {
    Uint64DivStep(a, b, c, &r, &carry);
  }
  uint64_t cycles_end_test = ReadRdtsc();
  uint64_t cycles_diff = cycles_end_test - cycles_start_test;
  printf("simple_div_time_test number of successful tests: %d\n",
         num_tests_executed);
  printf("total ellapsed time %le\n",
         ((double)cycles_diff) / ((double)cycles_per_second));
  printf("time per 64 bit divide %le\n",
         ((double)cycles_diff) /
             ((double)(num_tests_executed * cycles_per_second)));
  printf("END_SIMPLE_DIV_TESTS\n");
  return ret;
}

bool ecc_speed_tests(EccKey* key, const char* filename, int size,
                     int num_tests) {
  printf("\nECC_SPEED_TESTS\n");
  struct stat file_info;
  int k = stat(filename, &file_info);
  byte* buf = new byte[2048];
  byte* pbuf = buf;
  int num_tests_executed;
  bool ret = true;
  uint64_t cycles_start_test;
  uint64_t cycles_end_test;
  uint64_t cycles_diff;
  extern EccKey P256_Key;

  if (k < 0) {
    if (!makeTestData(filename, size)) {
      printf("Cant make test data file\n");
      delete buf;
      return false;
    }
  }
  if (!readTestData(filename, 2048, buf)) {
    delete buf;
    return false;
  }

  if (!InitEccCurves()) {
    printf("InitEccCurves failed\n");
    return false;
  }

  BigNum secret(8);
  secret.ZeroNum();
  if (key == nullptr) {
    key = new EccKey();
    secret.ZeroNum();
    if (!GetCryptoRand(4 * NBITSINUINT64 - 64, (byte*)secret.value_)) {
      printf("Cant generate ecc key\n");
      return false;
    }
    secret.Normalize();
    if (key == nullptr ||
        !key->MakeEccKey((const char*)"test-key", (const char*)"test",
                         (const char*)"test", 256, COMMON_YEAR_SECONDS,
                         &P256_Key.c_, &P256_Key.g_, nullptr,
                         P256_Key.order_of_g_, &secret)) {
      printf("Cant generate ecc key\n");
      return false;
    }
  }
  if (FLAGS_printall) {
    ((CryptoKey*)key)->PrintKey();
    printf("\n");
  }

  byte M[256];
  byte C[256];
  memset(M, 0, 256);
  memset(C, 0, 256);
  memcpy(M, pbuf, 30);
  int n = 128;
  CurvePoint P1(16);
  CurvePoint P2(16);
  BigNum ksecret(8);
  ksecret.ZeroNum();
  if (!GetCryptoRand(192, (byte*)ksecret.value_)) {
    LOG(ERROR) << "GetCryptoRandom error in EccKey::Encrypt\n";
    return false;
  }
  ksecret.Normalize();
  P1.MakeZero();
  P2.MakeZero();

  // ECC, Encrypt
  cycles_start_test = ReadRdtsc();
  for (num_tests_executed = 0; num_tests_executed < num_tests;
       num_tests_executed++) {
    n = 128;
    if (!key->Encrypt(32, M, ksecret, P1, P2)) {
      printf("ecc encrypt test %d failed\n", num_tests_executed);
      ret = false;
      goto done;
    }
  }
  cycles_end_test = ReadRdtsc();
  cycles_diff = cycles_end_test - cycles_start_test;
  printf("ECC encrypt, number of tests: %d\n", num_tests_executed);
  printf("total ellapsed time %le\n",
         ((double)cycles_diff) / ((double)cycles_per_second));
  printf("time per encrypt %le\n",
         ((double)cycles_diff) /
             ((double)(num_tests_executed * cycles_per_second)));
  // ECC, decrypt
  cycles_start_test = ReadRdtsc();
  for (num_tests_executed = 0; num_tests_executed < num_tests;
       num_tests_executed++) {
    n = 128;
    if (!key->Decrypt(P1, P2, &n, C)) {
      printf("ecc decrypt test %d failed\n", num_tests_executed);
      ret = false;
      goto done;
    }
  }
  cycles_end_test = ReadRdtsc();
  cycles_diff = cycles_end_test - cycles_start_test;
  printf("ECC decrypt, number of tests: %d\n", num_tests_executed);
  printf("total ellapsed time %le\n",
         ((double)cycles_diff) / ((double)cycles_per_second));
  printf("time per decrypt %le\n",
         ((double)cycles_diff) /
             ((double)(num_tests_executed * cycles_per_second)));

done:
  delete buf;
  printf("END_ECC_SPEED_TESTS\n");
  return ret;
}

bool rsa_speed_tests(RsaKey* key1, RsaKey* key2, const char* filename, int size,
                     int num_tests) {
  printf("\nRSA_SPEED_TESTS\n");
  struct stat file_info;
  int k = stat(filename, &file_info);
  byte* buf = new byte[2048];
  byte* pbuf = buf;
  int num_tests_executed;
  bool ret = true;
  uint64_t cycles_start_test;
  uint64_t cycles_end_test;
  uint64_t cycles_diff;

  if (k < 0) {
    if (!makeTestData(filename, size)) {
      printf("Cant make test data file\n");
      delete buf;
      return false;
    }
  }
  if (!readTestData(filename, 2048, buf)) {
    delete buf;
    return false;
  }

  if (key1 == nullptr) {
    key1 = new RsaKey();
    if (key1 == nullptr ||
        !key1->GenerateRsaKey("test-key", "test", "test", 1024,
                              COMMON_YEAR_SECONDS)) {
      printf("Cant generate 1024 bit key\n");
      return false;
    }
  }

  if (key2 == nullptr) {
    key2 = new RsaKey();
    if (key2 == nullptr ||
        !key2->GenerateRsaKey("test-key", "test", "test", 2048,
                              COMMON_YEAR_SECONDS)) {
      printf("Cant generate 2048 bit key\n");
      return false;
    }
  }
  if (FLAGS_printall) {
    ((CryptoKey*)key1)->PrintKey();
    ((CryptoKey*)key2)->PrintKey();
    printf("\n");
  }

  byte M[512];
  byte C[512];

  memset(M, 0, 512);
  memset(C, 0, 512);

  memcpy(M, pbuf, 127);
  int n = 128;

  // 1024, speed 0, Encrypt
  cycles_start_test = ReadRdtsc();
  for (num_tests_executed = 0; num_tests_executed < num_tests;
       num_tests_executed++) {
    n = 128;
    if (!key1->Encrypt(128, M, &n, C, 0)) {
      printf("rsa 1024 bit encrypt test %d failed\n", num_tests_executed);
      ret = false;
      goto done;
    }
  }
  cycles_end_test = ReadRdtsc();
  cycles_diff = cycles_end_test - cycles_start_test;
  printf("rsa1024 encrypt, speed 0, number of tests: %d\n", num_tests_executed);
  printf("total ellapsed time %le\n",
         ((double)cycles_diff) / ((double)cycles_per_second));
  printf("time per encrypt %le\n",
         ((double)cycles_diff) /
             ((double)(num_tests_executed * cycles_per_second)));

  // 1024, speed 0, Decrypt
  cycles_start_test = ReadRdtsc();
  for (num_tests_executed = 0; num_tests_executed < num_tests;
       num_tests_executed++) {
    n = 128;
    if (!key1->Decrypt(128, M, &n, C, 0)) {
      printf("rsa 1024 bit decrypt test %d failed\n", num_tests_executed);
      ret = false;
      goto done;
    }
  }
  cycles_end_test = ReadRdtsc();
  cycles_diff = cycles_end_test - cycles_start_test;
  printf("rsa1024 decrypt, speed 0, number of tests: %d\n", num_tests_executed);
  printf("total ellapsed time %le\n",
         ((double)cycles_diff) / ((double)cycles_per_second));
  printf("time per decrypt %le\n",
         ((double)cycles_diff) /
             ((double)(num_tests_executed * cycles_per_second)));
  printf("\n");

  // 1024, speed 1, Encrypt
  cycles_start_test = ReadRdtsc();
  for (num_tests_executed = 0; num_tests_executed < num_tests;
       num_tests_executed++) {
    n = 128;
    if (!key1->Encrypt(128, M, &n, C, 1)) {
      printf("rsa 1024 bit encrypt test %d failed\n", num_tests_executed);
      ret = false;
      goto done;
    }
  }
  cycles_end_test = ReadRdtsc();
  cycles_diff = cycles_end_test - cycles_start_test;
  printf("rsa1024 encrypt, speed 1, number of tests: %d\n", num_tests_executed);
  printf("total ellapsed time %le\n",
         ((double)cycles_diff) / ((double)cycles_per_second));
  printf("time per encrypt %le\n",
         ((double)cycles_diff) /
             ((double)(num_tests_executed * cycles_per_second)));

  // 1024, speed 1, Decrypt
  cycles_start_test = ReadRdtsc();
  for (num_tests_executed = 0; num_tests_executed < num_tests;
       num_tests_executed++) {
    n = 128;
    if (!key1->Decrypt(128, M, &n, C, 1)) {
      printf("rsa 1024 bit decrypt test %d failed\n", num_tests_executed);
      ret = false;
      goto done;
    }
  }
  cycles_end_test = ReadRdtsc();
  cycles_diff = cycles_end_test - cycles_start_test;
  printf("rsa1024 decrypt, speed 1, number of tests: %d\n", num_tests_executed);
  printf("total ellapsed time %le\n",
         ((double)cycles_diff) / ((double)cycles_per_second));
  printf("time per decrypt %le\n",
         ((double)cycles_diff) /
             ((double)(num_tests_executed * cycles_per_second)));
  printf("\n");

  // 1024, speed 2, Encrypt
  cycles_start_test = ReadRdtsc();
  for (num_tests_executed = 0; num_tests_executed < num_tests;
       num_tests_executed++) {
    n = 128;
    if (!key1->Encrypt(128, M, &n, C, 2)) {
      printf("rsa 1024 bit encrypt test %d failed\n", num_tests_executed);
      ret = false;
      goto done;
    }
  }
  cycles_end_test = ReadRdtsc();
  cycles_diff = cycles_end_test - cycles_start_test;
  printf("rsa1024 encrypt, speed 2, number of tests: %d\n", num_tests_executed);
  printf("total ellapsed time %le\n",
         ((double)cycles_diff) / ((double)cycles_per_second));
  printf("time per encrypt %le\n",
         ((double)cycles_diff) /
             ((double)(num_tests_executed * cycles_per_second)));

  // 1024, speed 2, Decrypt
  cycles_start_test = ReadRdtsc();
  for (num_tests_executed = 0; num_tests_executed < num_tests;
       num_tests_executed++) {
    n = 128;
    if (!key1->Decrypt(128, M, &n, C, 2)) {
      printf("rsa 1024 bit decrypt test %d failed\n", num_tests_executed);
      ret = false;
      goto done;
    }
  }
  cycles_end_test = ReadRdtsc();
  cycles_diff = cycles_end_test - cycles_start_test;
  printf("rsa1024 decrypt, speed 2, number of tests: %d\n", num_tests_executed);
  printf("total ellapsed time %le\n",
         ((double)cycles_diff) / ((double)cycles_per_second));
  printf("time per decrypt %le\n",
         ((double)cycles_diff) /
             ((double)(num_tests_executed * cycles_per_second)));
  printf("\n");

  // 1024, speed 3, Encrypt
  cycles_start_test = ReadRdtsc();
  for (num_tests_executed = 0; num_tests_executed < num_tests;
       num_tests_executed++) {
    n = 128;
    if (!key1->Encrypt(128, M, &n, C, 3)) {
      printf("rsa 1024 bit encrypt test %d failed\n", num_tests_executed);
      ret = false;
      goto done;
    }
  }
  cycles_end_test = ReadRdtsc();
  cycles_diff = cycles_end_test - cycles_start_test;
  printf("rsa1024 encrypt, speed 3, number of tests: %d\n", num_tests_executed);
  printf("total ellapsed time %le\n",
         ((double)cycles_diff) / ((double)cycles_per_second));
  printf("time per encrypt %le\n",
         ((double)cycles_diff) /
             ((double)(num_tests_executed * cycles_per_second)));

  // 1024, speed 3, Decrypt
  cycles_start_test = ReadRdtsc();
  for (num_tests_executed = 0; num_tests_executed < num_tests;
       num_tests_executed++) {
    n = 128;
    if (!key1->Decrypt(128, M, &n, C, 3)) {
      printf("rsa 1024 bit decrypt test %d failed\n", num_tests_executed);
      ret = false;
      goto done;
    }
  }
  cycles_end_test = ReadRdtsc();
  cycles_diff = cycles_end_test - cycles_start_test;
  printf("rsa1024 decrypt, speed 3, number of tests: %d\n", num_tests_executed);
  printf("total ellapsed time %le\n",
         ((double)cycles_diff) / ((double)cycles_per_second));
  printf("time per decrypt %le\n",
         ((double)cycles_diff) /
             ((double)(num_tests_executed * cycles_per_second)));
  printf("\n");

  // 2048, speed 0, Encrypt
  cycles_start_test = ReadRdtsc();
  for (num_tests_executed = 0; num_tests_executed < num_tests;
       num_tests_executed++) {
    n = 256;
    if (!key2->Encrypt(256, M, &n, C, 0)) {
      printf("rsa 2048 bit encrypt test %d failed\n", num_tests_executed);
      ret = false;
      goto done;
    }
  }
  cycles_end_test = ReadRdtsc();
  cycles_diff = cycles_end_test - cycles_start_test;
  printf("rsa2048 encrypt, speed 0, number of tests: %d\n", num_tests_executed);
  printf("total ellapsed time %le\n",
         ((double)cycles_diff) / ((double)cycles_per_second));
  printf("time per encrypt %le\n",
         ((double)cycles_diff) /
             ((double)(num_tests_executed * cycles_per_second)));

  // 2048, speed 0, Decrypt
  cycles_start_test = ReadRdtsc();
  for (num_tests_executed = 0; num_tests_executed < num_tests;
       num_tests_executed++) {
    n = 256;
    if (!key2->Decrypt(256, M, &n, C, 0)) {
      printf("rsa 2048 bit decrypt test %d failed\n", num_tests_executed);
      ret = false;
      goto done;
    }
  }
  cycles_end_test = ReadRdtsc();
  cycles_diff = cycles_end_test - cycles_start_test;
  printf("rsa2048 decrypt, speed 0, number of tests: %d\n", num_tests_executed);
  printf("total ellapsed time %le\n",
         ((double)cycles_diff) / ((double)cycles_per_second));
  printf("time per decrypt %le\n",
         ((double)cycles_diff) /
             ((double)(num_tests_executed * cycles_per_second)));
  printf("\n");

  // 2048, speed 1, Encrypt
  cycles_start_test = ReadRdtsc();
  for (num_tests_executed = 0; num_tests_executed < num_tests;
       num_tests_executed++) {
    n = 256;
    if (!key2->Encrypt(256, M, &n, C, 1)) {
      printf("rsa 2048 bit encrypt test %d failed\n", num_tests_executed);
      ret = false;
      goto done;
    }
  }
  cycles_end_test = ReadRdtsc();
  cycles_diff = cycles_end_test - cycles_start_test;
  printf("rsa2048 encrypt, speed 1, number of tests: %d\n", num_tests_executed);
  printf("total ellapsed time %le\n",
         ((double)cycles_diff) / ((double)cycles_per_second));
  printf("time per encrypt %le\n",
         ((double)cycles_diff) /
             ((double)(num_tests_executed * cycles_per_second)));

  // 2048, speed 1, Decrypt
  cycles_start_test = ReadRdtsc();
  for (num_tests_executed = 0; num_tests_executed < num_tests;
       num_tests_executed++) {
    n = 256;
    if (!key2->Decrypt(256, M, &n, C, 1)) {
      printf("rsa 2048 bit decrypt test %d failed\n", num_tests_executed);
      ret = false;
      goto done;
    }
  }
  cycles_end_test = ReadRdtsc();
  cycles_diff = cycles_end_test - cycles_start_test;
  printf("rsa2048 decrypt, speed 1, number of tests: %d\n", num_tests_executed);
  printf("total ellapsed time %le\n",
         ((double)cycles_diff) / ((double)cycles_per_second));
  printf("time per decrypt %le\n",
         ((double)cycles_diff) /
             ((double)(num_tests_executed * cycles_per_second)));
  printf("\n");

  // 2048, speed 2, Encrypt
  cycles_start_test = ReadRdtsc();
  for (num_tests_executed = 0; num_tests_executed < num_tests;
       num_tests_executed++) {
    n = 256;
    if (!key2->Encrypt(256, M, &n, C, 2)) {
      printf("rsa 2048 bit encrypt test %d failed\n", num_tests_executed);
      ret = false;
      goto done;
    }
  }
  cycles_end_test = ReadRdtsc();
  cycles_diff = cycles_end_test - cycles_start_test;
  printf("rsa2048 encrypt, speed 2, number of tests: %d\n", num_tests_executed);
  printf("total ellapsed time %le\n",
         ((double)cycles_diff) / ((double)cycles_per_second));
  printf("time per encrypt %le\n",
         ((double)cycles_diff) /
             ((double)(num_tests_executed * cycles_per_second)));

  // 2048, speed 2, Decrypt
  cycles_start_test = ReadRdtsc();
  for (num_tests_executed = 0; num_tests_executed < num_tests;
       num_tests_executed++) {
    n = 256;
    if (!key2->Decrypt(256, M, &n, C, 2)) {
      printf("rsa 2048 bit decrypt test %d failed\n", num_tests_executed);
      ret = false;
      goto done;
    }
  }
  cycles_end_test = ReadRdtsc();
  cycles_diff = cycles_end_test - cycles_start_test;
  printf("rsa2048 decrypt, speed 2, number of tests: %d\n", num_tests_executed);
  printf("total ellapsed time %le\n",
         ((double)cycles_diff) / ((double)cycles_per_second));
  printf("time per decrypt %le\n",
         ((double)cycles_diff) /
             ((double)(num_tests_executed * cycles_per_second)));
  printf("\n");

  // need to calculate p_prime_ and q_prime_
  // 2048, speed 3, Encrypt
  cycles_start_test = ReadRdtsc();
  for (num_tests_executed = 0; num_tests_executed < num_tests;
       num_tests_executed++) {
    n = 256;
    if (!key2->Encrypt(256, M, &n, C, 3)) {
      printf("rsa 2048 bit encrypt test %d failed\n", num_tests_executed);
      ret = false;
      goto done;
    }
  }
  cycles_end_test = ReadRdtsc();
  cycles_diff = cycles_end_test - cycles_start_test;
  printf("rsa2048 encrypt, speed 3, number of tests: %d\n", num_tests_executed);
  printf("total ellapsed time %le\n",
         ((double)cycles_diff) / ((double)cycles_per_second));
  printf("time per encrypt %le\n",
         ((double)cycles_diff) /
             ((double)(num_tests_executed * cycles_per_second)));

  // 2048, speed 0, Decrypt
  cycles_start_test = ReadRdtsc();
  for (num_tests_executed = 0; num_tests_executed < num_tests;
       num_tests_executed++) {
    n = 256;
    if (!key2->Decrypt(256, M, &n, C, 3)) {
      printf("rsa 2048 bit decrypt test %d failed\n", num_tests_executed);
      ret = false;
      goto done;
    }
  }
  cycles_end_test = ReadRdtsc();
  cycles_diff = cycles_end_test - cycles_start_test;
  printf("rsa2048 encrypt, speed 3, number of tests: %d\n", num_tests_executed);
  printf("total ellapsed time %le\n",
         ((double)cycles_diff) / ((double)cycles_per_second));
  printf("time per decrypt %le\n",
         ((double)cycles_diff) /
             ((double)(num_tests_executed * cycles_per_second)));
  printf("\n");

done:
  delete buf;
  printf("END_RSA_SPEED_TESTS\n");
  return ret;
}

bool mont_arith_tests() {
  printf("\nMONT_ARITH_TESTS\n");
  BigNum a(8);
  BigNum b(8);
  BigNum ab2(8);
  BigNum ab(8);
  BigNum aR(8);
  BigNum bR(8);
  BigNum abR(8);
  BigNum m(8);
  BigNum m_prime(8);
  BigNum out(8);

  a.value_[0] = 5ULL;
  b.value_[0] = 7ULL;
  m.value_[0] = 97ULL;
  a.Normalize();
  b.Normalize();
  m.Normalize();
  uint64_t r = BigHighBit(m);

  if (!BigMontParams(m, r, m_prime)) {
    printf("BigMontParams fails\n");
    return false;
  }
  if (!BigMakeMont(a, r, m, aR)) {
    printf("BigMakeMont 1 fails\n");
    return false;
  }
  if (!BigMakeMont(b, r, m, bR)) {
    printf("BigMakeMont 2 fails\n");
    return false;
  }
  if (!BigMontMult(aR, bR, m, r, m_prime, abR)) {
    printf("BigMakeMult fails\n");
    return false;
  }
  if (!BigMontReduce(abR, r, m, m_prime, ab)) {
    printf("BigMakeReduce fails\n");
    return false;
  }
  if (!BigModMult(a, b, m, ab2)) {
    printf("BigModMult  fails\n");
    return false;
  }
  if (FLAGS_printall) {
    printf("ab2: ");
    PrintNumToConsole(ab2, 10);
    printf("\n");
    printf("\n");
  }
  if (BigCompare(ab, ab2) != 0) {
    printf("Mont Mult compare fails\n");
    return false;
  }

  BigNum e(1, 10ULL);
  if (!BigMontExp(Big_Two, e, r, m, m_prime, out)) {
    printf("BigMontExp fails\n");
    return false;
  }
  if (FLAGS_printall) {
    PrintNumToConsole(Big_Two, 10);
    printf("**");
    PrintNumToConsole(e, 10);
    printf("(mod ");
    PrintNumToConsole(m, 10);
    printf(") = ");
    PrintNumToConsole(out, 10);
    printf("\n");
    printf("\n");
  }

  printf("END_MONT_ARITH_TESTS\n");
  return true;
}

bool key_format_tests() {
  if (FLAGS_printall) {
    printf("\nKEY_FORMAT_TESTS\n");
  }
  EccKey* ecc_key = new EccKey();
  extern EccKey P256_Key;
  extern bool P256_key_valid;

  if (!InitEccCurves()) {
    printf("InitEccCurves failed\n");
    return false;
  }
  if (!P256_key_valid) {
    printf("P256 key not valid\n");
    return false;
  }
  BigNum secret(256 / NBITSINUINT64);
  secret.ZeroNum();
  if (!GetCryptoRand(248, (byte*)secret.value_)) {
    printf("cant get random bits\n");
    return false;
  }
  secret.Normalize();

  if (!ecc_key->MakeEccKey("JohnsECCKey1", "channel-encryption",
                           "John Manferdelli", 256, COMMON_YEAR_SECONDS,
                           &P256_Key.c_, &P256_Key.g_, nullptr,
                           P256_Key.order_of_g_, &secret)) {
    printf("Cant make ecc key\n");
    return false;
  }
  if (FLAGS_printall) {
    ((CryptoKey*)ecc_key)->PrintKey();
  }

  // Save key and restore it
  EccKey* new_key = new EccKey();
  crypto_key_message message;
  ((CryptoKey*)ecc_key)->SerializeKeyToMessage(message);
  ((CryptoKey*)new_key)->DeserializeKeyFromMessage(message);
  if (FLAGS_printall) {
    printf("Serialized and DeserializeKeyFromMessage:\n");
    ((CryptoKey*)new_key)->PrintKey();
  }

  // Check equality
  printf("END_KEY_FORMAT_TESTS\n");
  return true;
}

bool key_store_tests() {
  printf("\nKEY_STORE_TESTS\n");
  KeyStore key_store;
  SymmetricKey the_key;

  if (!the_key.GenerateAesKey("JohnsStoreKey1", "channel-encryption",
                              "John Manferdelli", 128, COMMON_YEAR_SECONDS)) {
    printf("GenerateAesKey failed\n");
    return false;
  }

  if (!key_store.ReadStore("TestKeyStore")) {
    printf("Cant read key store\n");
    return false;
  }
  if (!key_store.AddKey((CryptoKey*)&the_key)) {
    printf("Cant add to key store\n");
    return false;
  }

  CryptoKey* p_msg = nullptr;
  string* p_string = nullptr;
  if (!key_store.FindKey("JohnsStoreKey1", &p_string, &p_msg)) {
    printf("Cant find key in store\n");
    return false;
  }
  if (FLAGS_printall) {
    p_msg->PrintKey();
  }
  SymmetricKey* new_key = new SymmetricKey();
  crypto_key_message message;
  p_msg->SerializeKeyToMessage(message);
  ((CryptoKey*)new_key)->DeserializeKeyFromMessage(message);
  if (FLAGS_printall) {
    printf("\nSerialize and DeserializeKeyFromMessage:\n");
    ((CryptoKey*)new_key)->PrintKey();
  }
  printf("END KEY_STORE_TESTS\n");
  return true;
}

bool rsa_tests() {
  if (FLAGS_printall) {
    printf("\nSTART RSA_TESTS\n");
  }
  int bit_size = 256;
  BigNum M(8);
  BigNum N(8);
  BigNum T(8);
  BigNum E(8);
  BigNum P(8);
  BigNum PM1(8);
  BigNum QM1(8);

  M.value_[0] = 2ULL;
  M.Normalize();
  E.value_[0] = 12ULL;
  E.Normalize();

  RsaKey* rsa_key = new (RsaKey);
  if (!rsa_key->GenerateRsaKey("JLM rsa key", "Signing", "John", bit_size,
                               COMMON_YEAR_SECONDS)) {
    printf("GenerateRsaKey failed\n");
    return false;
  }
  if (FLAGS_printall) {
    ((CryptoKey*)rsa_key)->PrintKey();
  }

  PM1.CopyFrom(*rsa_key->p_);
  if (!BigUnsignedSubFrom(PM1, Big_One)) {
    printf("rsa_tests: BigUnsignedSubFrom failed\n");
    return false;
  }

  QM1.CopyFrom(*rsa_key->q_);
  if (!BigUnsignedSubFrom(QM1, Big_One)) {
    printf("rsa_tests: BigUnsignedSubFrom failed\n");
    return false;
  }

  if (!BigModExp(M, PM1, *rsa_key->p_, N)) {
    printf("rsa_tests: BigModExp 1 failed\n");
    return false;
  }
  if (FLAGS_printall) {
    PrintNumToConsole(M, 16);
    printf("**");
    PrintNumToConsole(PM1, 16);
    printf("(mod ");
    PrintNumToConsole(*rsa_key->p_, 16);
    printf(") = ");
    PrintNumToConsole(N, 16);
    printf("\n");
    printf("\n");
  }
  if (BigCompare(N, Big_One) != 0) {
    printf("Fermat fails on p\n");
    return false;
  }
  N.ZeroNum();

  if (!BigModExp(M, QM1, *rsa_key->q_, N)) {
    printf("rsa_tests: BigModExp 1 failed\n");
    return false;
  }
  if (FLAGS_printall) {
    PrintNumToConsole(M, 16);
    printf("**");
    PrintNumToConsole(QM1, 16);
    printf("(mod ");
    PrintNumToConsole(*rsa_key->q_, 16);
    printf(") = ");
    PrintNumToConsole(N, 16);
    printf("\n");
    printf("\n");
  }
  if (!N.IsOne()) {
    printf("BigModExp 12 failed\n");
    return false;
  }
  if (BigCompare(N, Big_One) != 0) {
    printf("Fermat fails on q\n");
    return false;
  }
  N.ZeroNum();

  if (FLAGS_printall) {
    printf("Message: ");
    PrintNumToConsole(M, 16);
    printf("\n");
    printf("\n");
  }
  if (!BigModExp(M, *rsa_key->e_, *rsa_key->m_, N)) {
    printf("rsa_tests: BigModExp 1 failed\n");
    return false;
  }
  if (FLAGS_printall) {
    printf("Encrypted: ");
    PrintNumToConsole(N, 16);
    printf("\n");
    printf("\n");
  }
  if (!BigModExp(N, *rsa_key->d_, *rsa_key->m_, T)) {
    printf("rsa_tests: BigModExp 2 failed\n");
    return false;
  }
  if (FLAGS_printall) {
    printf("Decrypted: ");
    PrintNumToConsole(T, 16);
    printf("\n");
    printf("\n");
  }
  if (BigCompare(M, T) != 0) {
    printf("cant recover ciphertext\n");
    return false;
  }

  RsaKey* rsa_key2 = new (RsaKey);
  if (!rsa_key2->GenerateRsaKey("JLM rsa key", "Signing", "John", 1024,
                                COMMON_YEAR_SECONDS)) {
    printf("GenerateRsaKey failed\n");
    return false;
  }
  if (FLAGS_printall) {
    ((CryptoKey*)rsa_key2)->PrintKey();
  }

  byte in[256];
  byte out[256];
  byte new_out[256];

  memset(in, 0, 256);
  memset(out, 0, 256);
  memset(new_out, 0, 256);
  in[0] = 2;

  int size_out = 256;
  if (!rsa_key2->Encrypt(128, in, &size_out, out, 0)) {
    printf("rsa Encrypt failed\n");
    return false;
  }
  size_out = 256;
  if (!rsa_key2->Decrypt(128, out, &size_out, new_out, 0)) {
    printf("rsa Decrypt failed\n");
    return false;
  }
  if (FLAGS_printall) {
    printf("in (%d): ", size_out);
    PrintBytes(size_out, in);
    printf("\n");
    printf("out: ");
    PrintBytes(size_out, out);
    printf("\n");
    printf("new_out (%d): ", size_out);
    PrintBytes(size_out, new_out);
    printf("\n");
    printf("\n");
  }
  if (memcmp(in, new_out, size_out) != 0) {
    printf("RSA-1024 input does not match decrypted encrypted version\n");
    return false;
  }

  size_out = 256;
  if (!rsa_key2->Encrypt(128, in, &size_out, out, 1)) {
    printf("rsa Encrypt failed\n");
    return false;
  }
  size_out = 256;
  if (!rsa_key2->Decrypt(128, out, &size_out, new_out, 1)) {
    printf("rsa Decrypt failed\n");
    return false;
  }
  if (FLAGS_printall) {
    printf("in (%d): ", size_out);
    PrintBytes(size_out, in);
    printf("\n");
    printf("out: ");
    PrintBytes(size_out, out);
    printf("\n");
    printf("new_out: ");
    PrintBytes(size_out, new_out);
    printf("\n");
    printf("\n");
  }
  if (memcmp(in, new_out, size_out) != 0) {
    printf("RSA-1024 input does not match decrypted encrypted version\n");
    return false;
  }
  printf("END RSA_TESTS\n");
  return true;
}

bool simple_ecc_tests() {
  if (FLAGS_printall) {
    printf("\nSIMPLE_ECC_TESTS\n");
  }
  BigNum b(1, 4ULL);
  BigNum c(1, 4ULL);
  BigNum p(1, 5ULL);
  EccCurve curve_1(b, c, p);

  BigNum x1(1, 1ULL);
  BigNum y1(1, 2ULL);
  BigNum x2(1, 4ULL);
  BigNum y2(1, 3ULL);
  CurvePoint P1(x1, y1);
  CurvePoint P2(x2, y2);
  CurvePoint R1(9);
  // For y^2= x^3+4x+4 (mod 5), (1,2)+(4,3)= (4,2)
  if (!EccAdd(curve_1, P1, P2, R1)) {
    return false;
  }

  if (FLAGS_printall) {
    P1.PrintPoint();
    printf(" + ");
    P2.PrintPoint();
    printf(" = ");
    R1.PrintPoint();
    printf("\n");
    printf("\n");
  }
  if (R1.x_->value_[0] != 4ULL || R1.y_->value_[0] != 2ULL) {
    return false;
  }

  BigNum q(1, 2773ULL);
  EccCurve curve_2(b, c, q);
  BigNum x3(1, 1ULL);
  BigNum y3(1, 3ULL);
  BigNum t(1, 2ULL);
  CurvePoint P3(x3, y3);
  CurvePoint R2(9);
  // For y^2= x^3+4x+4 (mod 2773), 2(1,3)= (1771, 705)

  if (FLAGS_printall) {
    printf("PrintCurve: ");
    curve_2.PrintCurve();
    printf("\n");
    printf("\n");
  }
  if (!EccMult(curve_2, P3, t, R2)) {
    printf("cant Ecc Mult\n");
    return false;
  }
  if (FLAGS_printall) {
    PrintNumToConsole(t, 10ULL);
    printf(" * ");
    P3.PrintPoint();
    printf(" = ");
    R2.PrintPoint();
    printf("\n");
    printf("\n");
  }
  if (R2.x_->value_[0] != 1771ULL || R2.y_->value_[0] != 705ULL) {
    return false;
  }

  if (FLAGS_printall) {
    printf("PrintCurve: ");
    curve_2.PrintCurve();
    printf("\n");
  }
  if (!EccAdd(curve_2, P3, P3, R2)) {
    printf("cant Ecc Add\n");
    return false;
  }
  if (FLAGS_printall) {
    P3.PrintPoint();
    printf(" + ");
    P3.PrintPoint();
    printf(" = ");
    R2.PrintPoint();
    printf("\n");
    printf("\n");
  }
  if (R2.x_->value_[0] != 1771ULL || R2.y_->value_[0] != 705ULL) {
    return false;
  }

  CurvePoint z(1);
  CurvePoint w(1);
  z.MakeZero();
  if (!EccMult(curve_2, z, t, w)) {
    printf("cant Ecc Mult\n");
    return false;
  }
  if (FLAGS_printall) {
    PrintNumToConsole(t, 10ULL);
    printf(" * ");
    z.PrintPoint();
    printf(" = ");
    w.PrintPoint();
    printf("\n");
    printf("\n");
  }

  CurvePoint R3(1);
  if (!EccSub(curve_2, P1, P1, R3)) {
    printf("cant EccSub\n");
    return false;
  }
  if (FLAGS_printall) {
    P1.PrintPoint();
    printf(" - ");
    P1.PrintPoint();
    printf(" = ");
    R3.PrintPoint();
    printf("\n");
    printf("\n");
  }

  printf("END SIMPLE_ECC_TESTS\n");

  return true;
}

bool simple_projective_ecc_tests() {
  printf("\nSIMPLE_PROJECTIVE_ECC_TESTS\n");
  BigNum b(1, 4ULL);
  BigNum c(1, 4ULL);
  BigNum p(1, 5ULL);
  EccCurve curve_1(b, c, p);

  BigNum x1(1, 1ULL);
  BigNum y1(1, 2ULL);
  BigNum x2(1, 4ULL);
  BigNum y2(1, 3ULL);
  CurvePoint P1(x1, y1);
  CurvePoint P2(x2, y2);
  CurvePoint R1(9);

  // For y^2= x^3+4x+4 (mod 5), (1,2)+(4,3)= (4,2)
  if (FLAGS_printall) {
    printf("PrintCurve: ");
    curve_1.PrintCurve();
    printf("\n");
    printf("\n");
  }
  if (!ProjectiveAdd(curve_1, P1, P2, R1)) {
    return false;
  }
  if (FLAGS_printall) {
    P1.PrintPoint();
    printf(" + ");
    P2.PrintPoint();
    printf(" = ");
    R1.PrintPoint();
    printf("\n");
    printf("\n");
  }
  if (!ProjectiveToAffine(curve_1, R1)) {
    printf("ProjectiveToAffine failed\n");
    return false;
  }
  if (FLAGS_printall) {
    printf("Affine: ");
    R1.PrintPoint();
    printf("\n");
    printf("\n");
  }
  if (R1.x_->value_[0] != 4ULL || R1.y_->value_[0] != 2ULL) {
    return false;
  }

  BigNum q(1, 2773ULL);
  EccCurve curve_2(b, c, q);
  BigNum x3(1, 1ULL);
  BigNum y3(1, 3ULL);
  BigNum t(1, 2ULL);
  CurvePoint P3(x3, y3);
  CurvePoint R2(9);
  // For y^2= x^3+4x+4 (mod 2773), 2(1,3)= (1771, 705)

  if (FLAGS_printall) {
    printf("PrintCurve: ");
    curve_2.PrintCurve();
    printf("\n");
    printf("\n");
  }
  if (!ProjectiveDouble(curve_2, P3, R2)) {
    printf("cant Ecc Mult\n");
    return false;
  }
  if (FLAGS_printall) {
    printf("Double ");
    P3.PrintPoint();
    printf(" = ");
    R2.PrintPoint();
    printf("\n");
    printf("\n");
  }
  if (!ProjectiveToAffine(curve_2, R2)) {
    printf("JacobianToAffine failed\n");
    return false;
  }
  if (FLAGS_printall) {
    printf("Affine: ");
    R2.PrintPoint();
    printf("\n");
    printf("\n");
  }
  if (R2.x_->value_[0] != 1771ULL || R2.y_->value_[0] != 705ULL) {
    return false;
  }

  if (!ProjectiveAdd(curve_2, P3, P3, R2)) {
    printf("cant Ecc Mult\n");
    return false;
  }
  if (FLAGS_printall) {
    P3.PrintPoint();
    printf(" + ");
    P3.PrintPoint();
    printf(" = ");
    R2.PrintPoint();
    printf("\n");
    printf("\n");
  }
  if (!ProjectiveToAffine(curve_2, R2)) {
    printf("JacobianToAffine failed\n");
  }
  if (FLAGS_printall) {
    printf("Affine: ");
    R2.PrintPoint();
    printf("\n");
    printf("\n");
  }

  if (!ProjectivePointMult(curve_2, t, P3, R2)) {
    printf("cant Ecc Mult\n");
    return false;
  }
  if (FLAGS_printall) {
    PrintNumToConsole(t, 10ULL);
    printf(" * ");
    P3.PrintPoint();
    printf(" = ");
    R2.PrintPoint();
    printf("\n");
    printf("\n");
  }
  if (!ProjectiveToAffine(curve_2, R2)) {
    printf("JacobianToAffine failed\n");
    return false;
  }
  if (FLAGS_printall) {
    printf("Affine: ");
    R2.PrintPoint();
    printf("\n");
    printf("\n");
  }
  if (R2.x_->value_[0] != 1771ULL || R2.y_->value_[0] != 705ULL) {
    return false;
  }

  if (FLAGS_printall) {
    printf("PrintCurve: ");
    curve_2.PrintCurve();
    printf("\n");
    printf("\n");
  }

  CurvePoint z(1);
  CurvePoint w(1);
  z.MakeZero();
  if (!ProjectivePointMult(curve_2, t, z, w)) {
    printf("cant Ecc Mult\n");
    return false;
  }
  if (FLAGS_printall) {
    PrintNumToConsole(t, 10ULL);
    printf(" * ");
    z.PrintPoint();
    printf(" = ");
    w.PrintPoint();
    printf("\n");
    printf("Affine: ");
    w.PrintPoint();
    printf("\n");
    printf("\n");
  }

  printf("END SIMPLE_PROJECTIVE_ECC_TESTS\n");
  return true;
}

bool ecc_tests() {
  printf("\nECC_TESTS\n");

  if (!InitEccCurves()) {
    printf("Can't init nist curve\n");
    return false;
  }
  BigNum secret(8);
  secret.ZeroNum();
  if (!GetCryptoRand(252, (byte*)secret.value_)) {
    printf("Cant get random bits\n");
    return false;
  }
  secret.Normalize();
  EccKey* ecc_key = new EccKey();
  extern EccKey P256_Key;
  ext_ecc_key = ecc_key;

  if (!ecc_key->MakeEccKey("JlmEccCode1", "key-exchange", "jlm", 256,
                           COMMON_YEAR_SECONDS, &P256_Key.c_, &P256_Key.g_,
                           nullptr, P256_Key.order_of_g_, &secret)) {
    printf("Cant MakeEccKey\n");
    return false;
  }
  if (FLAGS_printall) {
    ((CryptoKey*)ecc_key)->PrintKey();
  }

  CurvePoint pt1(8);
  CurvePoint pt2(8);
  byte plain[32] = {
      0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x55, 0x55, 0x55,
      0x55, 0x55, 0x55, 0x55, 0x55, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
      0x33, 0x33, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  };
  byte decrypted[32];
  int size = 30;
  BigNum ksecret(8);

  ksecret.ZeroNum();
  if (!GetCryptoRand(252, (byte*)ksecret.value_)) {
    LOG(ERROR) << "GetCryptoRandom error in EccKey::Encrypt\n";
    return false;
  }

  memset(decrypted, 0, 32);
  if (FLAGS_printall) {
    printf("Plain bytes: ");
    PrintBytes(32, plain);
    printf("\n");
    printf("\n");
  }
  if (!ecc_key->Encrypt(32, plain, ksecret, pt1, pt2)) {
    printf("EccEncrypt fails\n");
    return false;
  }
  if (!ecc_key->Decrypt(pt1, pt2, &size, decrypted)) {
    printf("Eccdecrypt fails\n");
    return false;
  }
  if (FLAGS_printall) {
    printf("Encrypted Point 1: ");
    pt1.PrintPoint();
    printf("\n");
    printf("Encrypted Point 2: ");
    pt2.PrintPoint();
    printf("\n");
    printf("Decrypted bytes: ");
    PrintBytes(32, decrypted);
    printf("\n");
    printf("\n");
  }
  if (memcmp(plain, decrypted, size) != 0) {
    printf("plain and decrypted don't match\n");
    return false;
  }
  printf("END_ECC_TESTS\n");
  return true;
}

// --------------------------------------------------------------------------------------

bool RunTestSuite() { return true; }

#define TESTBUFSIZE 2048

TEST(BigNum, RandTest) {
  EXPECT_TRUE(getrand_time_tests(100));
}

TEST(BigNum, SimpleTest) {
  EXPECT_TRUE(simpletest());
}

TEST(BigNum, UnsignedArithTest) {
  EXPECT_TRUE(unsigned_arith_tests());
}

TEST(BigNum, SquareTest) {
  EXPECT_TRUE(square_test());
}

TEST(BigNum, PrintTest) {
  EXPECT_TRUE(print_tests());
}

TEST(BigNum, BasicTest) {
  EXPECT_TRUE(basic_tests());
}

TEST(BigNum, ConvertTest) {
  EXPECT_TRUE(convert_tests());
}

TEST(BigNum, BitTest) {
  EXPECT_TRUE(bit_tests());
}

TEST(BigNum, ShiftTest) {
  EXPECT_TRUE(shift_tests());
}

TEST(BigNum, RawArithTest) {
  EXPECT_TRUE(raw_arith_tests());
}

TEST(BigNum, SignedArithTest) {
  EXPECT_TRUE(signed_arith_tests());
}

TEST(BigNum, NumberTheoryTest) {
  EXPECT_TRUE(number_theory_tests());
}

TEST(BigNum, KeyFormatTest) {
  EXPECT_TRUE(key_format_tests());
}

TEST(BigNum, KeyStoreTest) {
  EXPECT_TRUE(key_store_tests());
}

TEST(BigNum, MontTest) {
  EXPECT_TRUE(mont_arith_tests());
}

TEST(BigNum, SImpleMultTest) {
  EXPECT_TRUE(simple_mult_time_test("test_data", TESTBUFSIZE, 1000000));
}

TEST(BigNum, SimpleDivTest) {
  EXPECT_TRUE(simple_div_time_test("test_data", TESTBUFSIZE, 1000000));
}

TEST(BigNum, MultDivTest) {
  EXPECT_TRUE(mult_div_stress("test_data", 32, 5000));
}

TEST(BigNum, MultTimeTest) {
  EXPECT_TRUE(mult_time_test("test_data", 32, 5000));
  EXPECT_TRUE(mult_time_test("test_data", 64, 5000));
}

TEST(BigNum, DivTimeTest) {
  EXPECT_TRUE(div_time_test("test_data", 32, 5000));
}

TEST(BigNum, ExpTimeTest) {
  EXPECT_TRUE(exp_time_test("test_data", 16, 50));
}

TEST(BigNum, MontTimeTest) {
  EXPECT_TRUE(mont_exp_time_test("test_data", 16, 50));
}

TEST(BigNum, SimpleEccTest) {
  EXPECT_TRUE(simple_ecc_tests());
}

TEST(BigNum, ProjectiveEccTest) {
  EXPECT_TRUE(simple_projective_ecc_tests());
}

TEST(BigNum, EccTest) {
  EXPECT_TRUE(ecc_tests());
}

TEST(BigNum, ExtAddTimeTest) {
  EXPECT_TRUE(ecc_add_time_test("test_data", ext_ecc_key, 200));
}

TEST(BigNum, EccDoubleTimeTest) {
  EXPECT_TRUE(ecc_double_time_test("test_data", ext_ecc_key, 200));
}

TEST(BigNum, EccMultTimeTest) {
  EXPECT_TRUE(ecc_mult_time_test("test_data", ext_ecc_key, 200));
}

TEST(BigNum, EccProjectiveMultTimeTest) {
  EXPECT_TRUE(ecc_projective_mult_time_test("test_data", ext_ecc_key, 200));
}

TEST(BigNum, EccEmbedTimeTest) {
  EXPECT_TRUE(ecc_embed_time_test("test_data", ext_ecc_key, 200));
}

TEST(BigNum, EccExtractTimeTest) {
  EXPECT_TRUE(ecc_extract_time_test("test_data", ext_ecc_key, 200));
}

TEST(BigNum, EccProjectiveCompareTimeTest) {
  EXPECT_TRUE(ecc_projective_compare_tests(ext_ecc_key, 200));
}

TEST(BigNum, EccSpeedTest) {
  EXPECT_TRUE(ecc_speed_tests(nullptr, "test_data", 0, 200));
}

TEST(BigNum, RsaTest) {
  EXPECT_TRUE(rsa_tests());
}

TEST(BigNum, RsaSpeedTest) {
  EXPECT_TRUE(rsa_speed_tests(nullptr, nullptr, "test_data", 0, 500));
}

TEST(BigNum, SquareRootTest) {
  EXPECT_TRUE(
      square_root_time_test("test_data", 3, *(ext_ecc_key->c_.p_), 200));
}

TEST(BigNum, RsaGen1024Test) {
    // EXPECT_TRUE(rsa1024_gen_time_test("test_data", 20));
}

TEST(BigNum, RsaGen20148Test) {
    // EXPECT_TRUE(rsa2048_gen_time_test("test_data", 20));
}

TEST_F(BigNumTest, RunTestSuite) {
  EXPECT_TRUE(RunTestSuite());
}

int main(int an, char** av) {
  ::testing::InitGoogleTest(&an, av);
#ifdef __linux__
  gflags::ParseCommandLineFlags(&an, &av, true);
#else
  google::ParseCommandLineFlags(&an, &av, true);
#endif
  if (!InitUtilities("bignumtest.log")) {
    printf("InitUtilities() failed\n");
    return 1;
  }
  cycles_per_second = CalibrateRdtsc();
  printf("This computer has %llu cycles per second\n", cycles_per_second);
  int result = RUN_ALL_TESTS();
  printf("\nTESTS ENDED\n");
  CloseUtilities();
  return result;
}
