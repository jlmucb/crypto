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
// File: commontest.cc

#include <stdio.h>
#include <string>
#include "conversions.h"
#include "util.h"

#include <gtest/gtest.h>
#include <gflags/gflags.h>

using namespace std;

class Base64Test : public ::testing::Test {
 protected:
  virtual void SetUp();
  virtual void TearDown();
};

byte mybytes[1024];
void Base64Test::SetUp() {
  for (int i=0;i<1024;i++) {
    mybytes[i]= (byte) i;
  }
}

void Base64Test::TearDown() {
}

byte test1in[5]= { 0x14, 0xfb, 0x9c, 0x03, 0xd9};
byte test1bufout[20];
string test1out("FPucA9k=");
bool simpletest1() {
  string* s= ByteToBase64LeftToRight(sizeof(test1in), test1in);
  int     n= Base64ToByteLeftToRight((char*) s->c_str(), 5, test1bufout);
  cout << "    input: ";
  PrintBytes(5, test1in);
  cout << ", output: " << *s;
  cout << ", ";
  PrintBytes(5, test1bufout);
  cout << "\n";
  if(n==sizeof(test1in) && test1out==*s)
    return true;
  return false;
}
byte test2in[2]={0x0c,0x0d};
bool simpletest2() {
  string* s= ByteToBase64LeftToRight(sizeof(test2in), test2in);
  byte    tmpout[128];
  int     n= Base64ToByteLeftToRight((char*) s->c_str(), 128, tmpout);

  cout << "    input: ";
  PrintBytes(2, test2in);
  cout << ", output: " << *s << ", ";
  PrintBytes(n, tmpout);
  cout << "\n";
  return true;
}

byte test3in[5]= { 
  0xd9,0x03,0x9c,0xfb,0x14};
bool simpletest3() {
  byte    tmpout[128];
  string* s= ByteToBase64RightToLeft(sizeof(test3in), test3in);
  if(s==NULL)
    return false;
  int     n= Base64ToByteRightToLeft((char*) s->c_str(), 5, tmpout);
  cout << "    input: ";
  PrintBytes(5, test1in);
  cout << ", output: " << *s;
  cout << ", ";
  PrintBytes(5, tmpout);
  cout << "\n";
  if(n==sizeof(test1in) && test1out==*s) {
    delete s;
    return true;
  }
  delete s;
  return false;
  cout << "    input: ";
  PrintBytes(5, test1in);
  cout << ", output: " << *s << "\n";
  return true;
}
bool simpletest4() {
  string* s= ByteToBase64RightToLeft(sizeof(test2in), test2in);
  byte    tmpout[128];
  int     n= Base64ToByteRightToLeft((char*) s->c_str(), 128, tmpout);

  cout << "    input: ";
  PrintBytes(2, test2in);
  cout << ", output: " << *s << ", ";
  PrintBytes(n, tmpout);
  cout << "\n";
  delete s;
  return true;
}

string hexout("14fb9c03d9");
bool simpletest5() {
  byte  tmpout[128];
  string* s= ByteToHexLeftToRight(sizeof(test1in), test1in);
  if(s==NULL)
    return false;
  int     n= HexToByteLeftToRight((char*) s->c_str(), 128, tmpout);
  cout << "    input: ";
  PrintBytes(sizeof(test1in), test1in);
  cout << ", hex output: " << *s;
  cout << ", ";
  PrintBytes(5, tmpout);
  cout << ", size: " << n;
  cout << "\n";
  if(sizeof(test1in)==n && hexout==*s) {
    delete s;
    return true;
  }
  delete s;
  return false;
}

bool AreBytesEqual(int n, byte* in1, byte* in2) {
  for(int i=0; i<n;i++)
    if(in1[i]!=in2[i])
      return false;
  return true;
}

bool HexComparisontestLeftToRight(int i, int j) {
  byte    tmpout[256];
  string* s= ByteToHexLeftToRight(j, &mybytes[i]);
  int     n= HexToByteLeftToRight((char*) s->c_str(), 128, tmpout);
  bool    fRet= true;

  if(n!=j) {
    printf("    bytelen1: %d, bytelen2: %d\n", j, n);
    printf("    ");
    PrintBytes(j, &mybytes[i]);
    printf("\n");
    fRet= false;
  }
  else if(!AreBytesEqual(j, &mybytes[i], tmpout)) {
    printf("    Hex Comparison failure i: %d, j: %d\n", i,j);
    printf("    ");
    PrintBytes(j, &mybytes[i]);
    printf(", ");
    PrintBytes(j, tmpout);
    printf("\n");
    fRet= false;
  }
  delete s;
  return fRet;
}

bool HexComparisontestRightToLeft(int i, int j) {
  bool    fRet= true;
  string* s= ByteToHexRightToLeft(j, &mybytes[i]);
  byte    tmpout[256];
  int     n= HexToByteRightToLeft((char*) s->c_str(), 256, tmpout);

  if(n!=j) {
    printf("    bytelen1: %d, bytelen2: %d\n", j, n);
    printf("    ");
    PrintBytes(j, &mybytes[i]);
    printf("\n");
    fRet= false;
  }
  else if(!AreBytesEqual(j, &mybytes[i], tmpout)) {
    printf("    Hex Comparison failure i: %d, j: %d\n", i,j);
    printf("    ");
    PrintBytes(j, &mybytes[i]);
    printf(", ");
    PrintBytes(j, tmpout);
    printf("\n");
    fRet= false;
  }
  delete s;
  return fRet;
}

bool Base64ComparisontestLeftToRight(int i, int j) {
  byte    tmpout[128];
  string* s= ByteToBase64LeftToRight(j, &mybytes[i]);
  int     n= Base64ToByteLeftToRight((char*) s->c_str(), 128, tmpout);
  bool    fRet= true;

  if(n!=j) {
    printf("    bytelen1: %d, bytelen2: %d\n", j, n);
    printf("    ");
    PrintBytes(j, &mybytes[i]);
    printf("\n");
    fRet= false;
  }
  else if(!AreBytesEqual(j, &mybytes[i], tmpout)) {
    printf("    Comparison failure i: %d, j: %d\n", i,j);
    printf("    ");
    PrintBytes(j, &mybytes[i]);
    printf(", ");
    PrintBytes(j, tmpout);
    printf("\n");
    fRet= false;
  }
  delete s;
  return fRet;
}

bool Base64ComparisontestRightToLeft(int i, int j) {
  byte    tmpout[128];
  string* s= ByteToBase64RightToLeft(j, &mybytes[i]);
  int     n= Base64ToByteRightToLeft((char*) s->c_str(), 128, tmpout);
  bool    fRet= true;

  if(n!=j) {
    printf("    bytelen1: %d, bytelen2: %d\n", j, n);
    printf("    ");
    PrintBytes(j, &mybytes[i]);
    printf("\n");
    fRet= false;
  }
  else if(!AreBytesEqual(j, &mybytes[i], tmpout)) {
    printf("    Comparison failure i: %d, j: %d\n", i,j);
    printf("    ");
    PrintBytes(j, &mybytes[i]);
    printf(", ");
    PrintBytes(j, tmpout);
    printf("\n");
    fRet= false;
  }
  delete s;
  return fRet;
}

bool RunTestSuite() {
  for(int i=0; i<256;i++) {
    for(int j=1; j<127; j++) {
      if(!Base64ComparisontestLeftToRight(i, j)) {
        printf("comparison test %d %d failed\n",i,j);
        return false;
      }
      if(!Base64ComparisontestRightToLeft(i, j)) {
        printf("comparison test %d %d failed\n",i,j);
        return false;
      }
      if(!HexComparisontestLeftToRight(i, j)) {
        printf("comparison test %d %d failed\n",i,j);
        return false;
      }
      if(!HexComparisontestRightToLeft(i, j)) {
        printf("comparison test %d %d failed\n",i,j);
        return false;
      }
    }
  }
  return true;
}

bool simpletimetest() {
  TimePoint   time_now;
  TimePoint   time_later;
  TimePoint   time_increment;

  if(!time_now.TimePointNow()) {
    printf("TimePointNow failed\n");
    return false;
  }
  printf("\t");
  time_now.PrintTime();
  printf("\n");
  TimePoint   time_copy;
  time_copy.TimePointCopyFrom(time_now);
  printf("\t");
  time_now.PrintTime();
  printf("\n");

  double  seconds= COMMON_YEAR_SECONDS; 
  int     years_later= 0;
  int     months_later= 0;
  int     days_later= 0;
  int     hours_later= 0;
  int     minutes_later= 0;
  double  seconds_later= 0;
  if(!time_increment. AppxTimeIncrementFromSeconds(seconds, &years_later, 
              &months_later, &days_later, &hours_later, &minutes_later, 
              &seconds_later)) {
    return false;
  }
  printf("\tseconds: %lf, years_later: %d, months_later: %d, days_later: %d" \
          " hours_later: %d, minutes_later: %d, seconds_later: %lf\n",
          seconds, years_later, months_later, days_later, hours_later, 
          minutes_later, seconds_later);
  time_later.TimePointLaterBySeconds(time_now, seconds);
  printf("\tlater: ");
  time_later.PrintTime();
  printf("\n");
  return true;
}

TEST(FirstBase64Case, FirstBase64Test) {
  EXPECT_TRUE(simpletest1());
  EXPECT_TRUE(simpletest2());
  EXPECT_TRUE(simpletest3());
  EXPECT_TRUE(simpletest4());
  printf("\t");
}

TEST(FirstHexCase, FirstHexTest) {
  EXPECT_TRUE(simpletest5());
}

TEST(FirstTimeCase, FirstTimeTest) {
  EXPECT_TRUE(simpletimetest());
}

TEST_F(Base64Test, RunTestSuite) {
  EXPECT_TRUE(RunTestSuite());
}

DEFINE_string(log_file, "commontest.log", "commontest file name");

int main(int an, char** av) {
  byte  buf[20];

  ::testing::InitGoogleTest(&an, av);
  memset(buf, 0, sizeof(buf));
  if(!InitUtilities(FLAGS_log_file.c_str())) {
    printf("InitUtilities() failed\n");
    return 1;
  }
  if(!GetCryptoRand(32, buf)) {
    printf("GetCryptoRand() failed\n");
    return 1;
  }
  PrintBytes(4, buf);
  printf("\n");
  int result= RUN_ALL_TESTS();
  CloseUtilities();
  return result;
}

