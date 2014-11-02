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
// File: util.cc

#include "cryptotypes.h"
#include <string>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "util.h"
using namespace std;

// #define NOREADRAND   // Remove!

ofstream logging_descriptor;

void ReverseCpy(int size, byte* in, byte* out) {
  out+= size-1;
  for(int i=0; i<size; i++)
    *(out--)= *(in++);
}

void PrintBytes(int n, byte* in) {
  for(int i=0; i<n; i++)
    printf("%02x", in[i]);
}

void LittleEndian32(int size, const uint32_t* in, uint32_t* out) {
  byte* p_in= (byte*)in;
  byte* p_out= (byte*)out;

  for(int i=0; i<size; i++) {
    p_out[0]= p_in[3];
    p_out[1]= p_in[2];
    p_out[2]= p_in[1];
    p_out[3]= p_in[0];
    p_in+= 4;
    p_out+= 4;
  }
}

static int          rdrand_enabled= -1;
static int          random_device_desciptor= -1;
static const char*  random_device= "/dev/urandom";
static bool         random_initialized= false;

bool HaveRdRand() {
  uint32_t  arg= 1;
  uint32_t  rd_rand_enabled;

  asm volatile(
    "\tmovl    %[arg], %%eax\n"
    "\tcpuid\n"
    "\tmovl    %%ecx, %[rd_rand_enabled]\n"
    : [rd_rand_enabled] "=m"(rd_rand_enabled)
    : [arg] "m" (arg)
    : "%eax", "%ebx", "%ecx", "%edx");
  if(((rd_rand_enabled>>30)&1)!=0) {
    return true;
  }
  return false;
}

bool HaveAesNi() { 
  uint32_t  arg= 1;
  uint32_t  rd_aesni_enabled;

  asm volatile(
    "\tmovl    %[arg], %%eax\n"
    "\tcpuid\n"
    "\tmovl    %%ecx, %[rd_aesni_enabled]\n"
    : [rd_aesni_enabled] "=m"(rd_aesni_enabled)
    : [arg] "m" (arg)
    : "%eax", "%ebx", "%ecx", "%edx");
  if(((rd_aesni_enabled>>25)&1)!=0) {
    return true;
  }
  return false;
}

#include <sys/stat.h> 
#include <fcntl.h>
#include <unistd.h>

bool InitLog(const char* log_file) {
  logging_descriptor.open(log_file);
  LOG(INFO)<< "Log file " << log_file << " opened.\n";
  return true;
}

void CloseLog() {
  LOG(INFO)<< "Log file closed.\n";
  logging_descriptor.close();
}

bool InitCrypto() {
  if(rdrand_enabled<0) {
    if(HaveRdRand())
      rdrand_enabled= 1;
    else
      rdrand_enabled= 0;
  }
  if(random_device_desciptor<0) {
    random_device_desciptor= open(random_device, O_RDONLY);
    if(random_device_desciptor<0)
      return false;
  }
  random_initialized= true;
  return true;
}

void CloseCrypto() {
  if(random_device_desciptor>0)
    close(random_device_desciptor);
  random_device_desciptor= -1;
  return;
}

bool GetCryptoRand(int num_bits, byte* buf) {
  int       num_bytes= ((num_bits+NBITSINBYTE-1)/NBITSINBYTE);
  uint32_t  out;

  if(rdrand_enabled>0) {
#ifndef NOREADRAND
    while(num_bytes>0) {
      asm volatile(
        "\trdrand %%edx\n"
        "\tmovl   %%edx, %[out]\n"
        : [out] "=m"(out)
        :: "%edx");
      memcpy(buf, (byte*)&out, num_bytes<4?num_bytes:4);
      num_bytes-= 4;
      buf+= 4;
    }
#endif
  } else {
    if(read(random_device_desciptor, buf, num_bytes)<num_bytes)
      return false;
  }
  return true;
}

bool InitUtilities(const char* log_file) {
  if(!InitLog(log_file))
    return false;
  if(!InitCrypto())
    return false;
  return true;
}

void CloseUtilities() {
  CloseCrypto();
  CloseLog();
  return;
}

TimePoint::TimePoint() {
  year_= 0;
  month_= 0;
  day_in_month_= 0;
  hour_= 0;
  minutes_= 0;
  seconds_= 0.0;
}

bool TimePoint::TimePointNow() {
  time_t      now;
  struct tm   current_time; 

  time(&now);
  gmtime_r(&now, &current_time);
  year_= current_time.tm_year+1900;
  month_= current_time.tm_mon+1;
  day_in_month_= current_time.tm_mday;
  hour_= current_time.tm_hour;
  minutes_= current_time.tm_min;
  seconds_= current_time.tm_sec;
  return true;
}

bool TimePoint::TimePointCopyFrom(TimePoint& from) {
  year_= from.year_;
  month_= from.month_;
  day_in_month_= from.day_in_month_;
  hour_= from.hour_;
  minutes_= from.minutes_;
  seconds_= from.seconds_;
  return true;
}

int DaysInMonth(int y, int m) {
  switch(m) {
    case 1:
      return 31;
    case 2:
      if(y%4==0)
        return 29;
      return 28;
    case 3:
      return 31;
    case 4:
      return 30;
    case 5:
      return 31;
    case 6:
      return 30;
    case 7:
      return 31;
    case 8:
      return 31;
    case 9:
      return 30;
    case 10:
      return 31;
    case 11:
      return 30;
    case 12:
      return 31;
  }
  return 0;
}

bool TimePoint::TimePointLaterBy(TimePoint& from, int years_later, int months_later,
                           int days_later, int hours_later, int minutes_later,
                           double seconds_later) {
  if(!this->TimePointCopyFrom(from)) {
    return false;
  }
  year_= from.year_+years_later;
  month_= from.month_+months_later;
  day_in_month_= from.day_in_month_+days_later;
  hour_= from.hour_+hours_later;
  minutes_= from.minutes_+minutes_later;
  seconds_= from.seconds_+seconds_later;

  // normalize
  int t;
  t= (int) seconds_/60.0;
  seconds_-= (double)t*60;
  minutes_+= t;
  t= minutes_/60;
  minutes_-= t*60;
  hour_+= t;
  t= hour_/24;
  hour_-= 24*t;
  day_in_month_+= t;

  while((t= DaysInMonth(year_, month_))<months_later) {
    month_++;
    day_in_month_-= t;
  }
  t= month_/12;
  year_+= t;
  month_-= 12*t;
  return true;
}

bool TimePoint::AppxTimeIncrementFromSeconds(double seconds, int* years_later, 
            int* months_later, int* days_later, int* hours_later, 
            int* minutes_later, double* seconds_later) {
  int32_t t;

  t= (int)(seconds/COMMON_YEAR_SECONDS);
  *years_later= t;
  seconds-= ((double)t)*COMMON_YEAR_SECONDS;
  t= (int)(seconds/((double)SECONDS_IN_DAY));
  *months_later = t/30; // approximate number of months
  seconds-= ((double)*months_later)*((double) 30)*((double)SECONDS_IN_DAY);
  t-= ((double)*months_later)*((double) 30);
  *days_later= t;
  seconds-= ((double)t)*((double)SECONDS_IN_DAY);
  t= (int)(seconds/((double)SECONDS_IN_HOUR));
  *hours_later= t;
  seconds-= ((double)t)*((double)SECONDS_IN_HOUR);
  t= (int)(seconds/SECONDS_IN_MINUTE);
  *minutes_later= t;
  *seconds_later= seconds-SECONDS_IN_MINUTE*((double)t);
  return true; 
}

bool TimePoint::TimePointLaterBySeconds(TimePoint& from, 
                        double total_seconds_later) {
  int     years_later;
  int     months_later;
  int     days_later;
  int     hours_later;
  int     minutes_later;
  double  seconds_later;

  if(!AppxTimeIncrementFromSeconds(total_seconds_later, &years_later, 
            &months_later, &days_later, &hours_later, 
            &minutes_later, &seconds_later)) {
    return false;
  }
  return TimePointLaterBy(from, years_later, months_later,
                           days_later, hours_later, minutes_later,
                           seconds_later);
}

void TimePoint::PrintTime() {
  printf("%04d:%02d:%02d.%02d:%02d:%lfZ", year_, month_, 
         day_in_month_, hour_, minutes_, seconds_);
}

//  1 if l is later than r
int CompareTimePoints(TimePoint& l, TimePoint& r) {
  if(l.year_>r.year_)
    return 1;
  if(l.year_<r.year_)
    return -1;
  if(l.month_>r.month_)
    return 1;
  if(l.month_<r.month_)
    return -1;
  if(l.day_in_month_>r.day_in_month_)
    return 1;
  if(l.day_in_month_<r.day_in_month_)
    return -1;
  if(l.hour_>r.hour_)
    return 1;
  if(l.hour_<r.hour_)
    return -1;
  if(l.minutes_>r.minutes_)
    return 1;
  if(l.minutes_<r.minutes_)
    return -1;
  if(l.seconds_>r.seconds_)
    return 1;
  if(l.seconds_<r.seconds_)
    return -1;
  return 0;
}

string* EncodeTime(TimePoint the_time) {
  char str_time[128];
  sprintf(str_time, "%04d:%02d:%02d.%02d:%02d:%lfZ",
          the_time.year_, the_time.month_, the_time.day_in_month_,
          the_time.hour_, the_time.minutes_, the_time.seconds_);
  return new string((const char*)str_time);
}

bool DecodeTime(string encoded_time, TimePoint* the_time) {
  const char* str_time= encoded_time.c_str();
  sscanf(str_time, "%04d:%02d:%02d.%02d:%02d:%lfZ",
          &the_time->year_, &the_time->month_, &the_time->day_in_month_,
          &the_time->hour_, &the_time->minutes_, &the_time->seconds_);
  return true;
}

ReadFile::ReadFile() {
  fd_= -1;
  bytes_in_file_= 0;
  bytes_left_= 0;
}

ReadFile::~ReadFile() {
}

bool ReadFile::Init(const char* filename) {
  if(filename==NULL) {
    return false;
  }

  struct stat file_info;
  int k= stat(filename, &file_info);
  if(k<0) {
    return false;
  }
  bytes_in_file_= file_info.st_size;
  bytes_left_= file_info.st_size;

  fd_= open(filename, O_RDONLY);
  if(fd_<0) 
    return false;
  return true;
}

int  ReadFile::BytesInFile() {
  return bytes_in_file_;
}

int  ReadFile::BytesLeftInFile() {
  return bytes_left_;
}

void ReadFile::Close() {
  close(fd_);
}

int  ReadFile::Read(int size, byte* buf) {
  int n= read(fd_, buf, size);
  if(n<=0)
    return n;
  bytes_left_-= n;
  return n;
}

WriteFile::WriteFile() {
  fd_= -1;
  bytes_written_= 0;
}

WriteFile::~WriteFile() {
}

bool WriteFile::Init(const char* filename) {
 fd_= creat(filename, S_IRWXU|S_IRWXG);
 if(fd_<=0) 
   return false; 
  return true;
}

int  WriteFile::BytesWrittenToFile() {
  return bytes_written_;
}

void WriteFile::Close() {
  close(fd_);
}

bool WriteFile::Write(int size, byte* buf) {
  int n= write(fd_,buf, size);
  if(n<size)
    return false;
  bytes_written_+= n;
  return true;
}

bool ReadaFile(const char* filename, int* size, byte** out) {
  ReadFile  file_desc;

  *out= NULL;
  if(!file_desc.Init(filename))
    return false;
  int num_bytes= file_desc.BytesInFile();
  byte* buf= new byte[num_bytes];
  if(file_desc.Read(num_bytes, buf)!=num_bytes) {
    delete buf;
    return false;
  }
  *size= num_bytes;
  *out= buf;
  file_desc.Close();
  return true;
}

bool WriteaFile(const char* filename, int size, byte* in) {
  WriteFile  file_desc;

  if(!file_desc.Init(filename))
    return false;
  if(!file_desc.Write(size,in))
    return false;
  file_desc.Close();
  return true;
}

