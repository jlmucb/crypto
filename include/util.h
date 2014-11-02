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
// File: util.h

#ifndef _CRYPTO_UTIL_H__
#define _CRYPTO_UTIL_H__

#include <iostream>
#include <fstream>
#include "cryptotypes.h"
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
using namespace std;

extern ofstream logging_descriptor;
#define INFO "INFO: "
#define ERROR "ERROR: "
#define LOG(x) (logging_descriptor << x)

#define SECONDS_IN_DAY  86400
#define SECONDS_IN_HOUR  3600.0
#define SECONDS_IN_MINUTE 60.0
#define LEAP_YEAR_SECONDS (366.0*86400)
#define COMMON_YEAR_SECONDS (365.0*86400)
#define GAUSSIAN_YEAR_SECONDS (365.2568983*86400)

class TimePoint {
public:
  int     year_;
  int     month_;           // 1= January
  int     day_in_month_;
  int     hour_;
  int     minutes_;
  double  seconds_;

  TimePoint();
  bool    TimePointNow();
  bool    TimePointCopyFrom(TimePoint& from);
  bool    AppxTimeIncrementFromSeconds(double seconds, int* years_later, 
            int* months_later, int*days_later, int* hours_later, 
            int* minutes_later, double* seconds_later);
  bool    TimePointLaterBy(TimePoint& from, int years_later, int months_later,
                           int days_later, int hours_later, int minutes_later,
                           double seconds_later);
  bool    TimePointLaterBySeconds(TimePoint& from, double seconds_later);
  void    PrintTime();
};
int CompareTimePoints(TimePoint& l, TimePoint& r);

class ReadFile {
public:

  int     fd_;
  int     bytes_in_file_;
  int     bytes_left_;

  ReadFile();
  ~ReadFile();

  bool    Init(const char* filename);
  int     BytesInFile();
  int     BytesLeftInFile();
  void    Close();
  int     Read(int size, byte* buf);
};

class WriteFile {
public:

  int     fd_;
  int     bytes_written_;

  WriteFile();
  ~WriteFile();

  bool    Init(const char* filename);
  int     BytesWrittenToFile();
  void    Close();
  bool    Write(int size, byte* buf);
};
bool    ReadaFile(const char* filename, int* size, byte** out);
bool    WriteaFile(const char* filename, int size, byte* in);

void    LittleEndian32(int size, const uint32_t* in, uint32_t* out);
void    ReverseCpy(int size, byte* in, byte* out);
void    PrintBytes(int n, byte* in);
bool    HaveRdRand();
bool    HaveAesNi();
bool    InitCrypto();
void    CloseCrypto();
bool    GetCryptoRand(int num_bits, byte* buf);
bool    InitLog(const char* log_file);
void    CloseLog();
bool    InitUtilities(const char* log_file);
void    CloseUtilities();
bool    TimeNow(struct tm* time_now);
bool    TimeMonthsAfterRef(struct tm& time_reference, int num_months, 
                          struct tm& new_time);
string* EncodeTime(TimePoint the_time);
bool    DecodeTime(string encoded_time, TimePoint* the_time);
#endif

