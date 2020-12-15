//
//  Copyright 2010, John L. Manferdellil
//  feal4.h

#ifndef __FEAL4_H
#define __FEAL4_H

#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
using namespace std;

#ifndef byte
typedef unsigned char byte;
#endif
#ifndef uint32_t 
typedef unsigned uint32_t;
#endif

class FourBytes {
public:
  FourBytes();
  FourBytes(byte a, byte b, byte c, byte d);

  byte rg_[4];
  void CopyFrom(FourBytes& in);
  void FillFromBytes(byte* in);
  void FillFromUint32(uint32_t in);
  void CopyToBytes(byte* out);
  void CopyToUint32(uint32_t* out);
  void CopyToMe(FourBytes& in);
  void XorToMe(FourBytes& in);
  void XorandPut(FourBytes& in1, FourBytes& in2);
  bool Equal(FourBytes& o1);
  bool HiEqual(FourBytes& o1);
  bool LoEqual(FourBytes& o1);
  bool HiBump();
  bool MidBump();
  bool LoBump();
  bool Bump();
  bool BumpUnestimated();
  bool OuterBump();
  void Zero();
  void AntiZero();
  void Print();
};

class FealState {
public:
  FourBytes left_;
  FourBytes right_;
  void FillFromBytes(byte* in);
  void CopyToBytes(byte* out);
  void CopyToMe(FealState& in);
  void XorToMe(FealState& in);
  void XorandPut(FealState& in1, FealState& in2);
  void Swap();
  bool Equal(FealState& in);
  void Print();
};

inline byte G0(byte a, byte b) {
  byte c = a + b;
  return (c<<2) | (c>>6);

}

inline byte G1(byte a, byte b) {
  byte c = a + b + 1;
  return (c<<2) | (c>>6);
}

inline void F(FourBytes& in, FourBytes& out) {
  out.rg_[1]= G1(in.rg_[0]^in.rg_[1],in.rg_[2]^in.rg_[3]);
  out.rg_[0]= G0(in.rg_[0], out.rg_[1]);
  out.rg_[2]= G0(out.rg_[1], in.rg_[2]^in.rg_[3]);
  out.rg_[3]= G1(out.rg_[2], in.rg_[3]);
}

inline void FK(FourBytes& in1, FourBytes& in2, FourBytes& out) {
  byte d1 = in1.rg_[0]^in1.rg_[1];
  byte d2 = in1.rg_[2]^in1.rg_[3];
  out.rg_[1]= G1(d1, in1.rg_[2]^in2.rg_[0]);
  out.rg_[2]= G0(d2, out.rg_[1]^in2.rg_[1]);
  out.rg_[0]= G0(in1.rg_[0], out.rg_[1]^in2.rg_[2]);
  out.rg_[3]= G0(in1.rg_[3], out.rg_[2]^in2.rg_[3]);
}

inline byte InvG0(byte c, byte a) {
    byte rc= ((c>>2)&0x3f) | (c<<6);
    uint32_t t = (256 + ((unsigned)rc) - ((unsigned) a))%256;
    return (byte) t;
}

inline byte InvG1(byte c, byte a) {
    byte rc= ((c>>2)&0x3f) | (c<<6);
    uint32_t t = (256 + ((unsigned)rc) - ((unsigned) 1)- ((unsigned) a))%256;
    return (byte) t;
}

class Feal4 {
public:
  FealState key_;
  FourBytes rk_[8];

  void InitKey(byte* key, bool print=false);
  void EncryptBlock(byte* in, byte* out, bool fPrint = false);
  void DecryptBlock(byte* in, byte* out);
  void CleanKeys();
};

class Feal4Diff {
public:
  FealState     In;
  FealState     Rounds[5];
  FealState     Out;
  FourBytes     XPrime;
  FourBytes     YPrime;
  FourBytes     ZPrime;
  FourBytes     TPrime;
  FourBytes     RPrime;
  FourBytes     SPrime;

  bool      SetIn(FealState& in);
  bool      SetOut(FealState& out);
  bool      GetRound(int iRound, FealState& round);
  bool      SetRound(int iRound, FealState& round);
  bool      GetIn(FealState& in);
  bool      GetOut(FealState& out);
  bool      CalcDiffs(Feal4& o1, Feal4& o2);
  bool      CalcDiffs2(Feal4& o1, Feal4& o2);
  bool      GetXPrime(FourBytes& xP);
  bool      GetYPrime(FourBytes& yP);
  bool      GetZPrime(FourBytes& zP);
  bool      GetTPrime(FourBytes& tP);
  bool      GetSPrime(FourBytes& sP);
  bool      GetRPrime(FourBytes& rP);
};

class ReadFile {
 public:
  int fd_;
  int bytes_in_file_;
  int bytes_left_;

  ReadFile();
  ~ReadFile();

  bool Init(const char* filename);
  int BytesInFile();
  int BytesLeftInFile();
  void Close();
  int Read(int size, byte* buf);
};

class WriteFile {
 public:
  int fd_;
  int bytes_written_;

  WriteFile();
  ~WriteFile();

  bool Init(const char* filename);
  int BytesWrittenToFile();
  void Close();
  bool Write(int size, byte* buf);
};
bool ReadaFile(const char* filename, int* size, byte** out);
bool WriteaFile(const char* filename, int size, byte* in);

#ifndef nullptr
#define nullptr NULL
#endif
#endif

