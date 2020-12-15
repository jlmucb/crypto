#include <stdio.h>
#include <time.h>
#include <string.h>

#include "new_feal4.h"

//  feal4.cpp
//  (c), 2010, John L. Manferdelli

#define MAXPAIRS 512
#define MAXTRIALKEYS 128

// ---------------------------------------------------------------------------------------

FourBytes::FourBytes() {
  rg_[0] = 0;
  rg_[1] = 0;
  rg_[2] = 0;
  rg_[3] = 0;
}

FourBytes::FourBytes(byte a, byte b, byte c, byte d) {
  rg_[0] = a;
  rg_[1] = b;
  rg_[2] = c;
  rg_[3] = d;
}

void FourBytes::Zero() {
  rg_[0]= 0;
  rg_[1]= 0;
  rg_[2]= 0;
  rg_[3]= 0;
}

void FourBytes::AntiZero() {
  rg_[0]= 0xff;
  rg_[1]= 0xff;
  rg_[2]= 0xff;
  rg_[3]= 0xff;
}

void FourBytes::CopyFrom(FourBytes& in) {
  for (int j = 0; j < 4; j++)
    rg_[j] = in.rg_[j];
}

bool FourBytes::HiBump() {
  for(int i = 2; i < 4; i++) {
    if(rg_[i] < 0xff) {
      rg_[i]++;
      return false;
    }
  rg_[i]= 0;
  }
  return true;
}

bool FourBytes::MidBump() {
  for(int i = 1; i < 3; i++) {
    if(rg_[i] < 0xff) {
      rg_[i]++;
      return false;
    }
    rg_[i]= 0;
  }
  return true;
}

bool FourBytes::OuterBump() {
    if(rg_[0] < 0xff) {
      rg_[0]++;
      return false;
    }
    rg_[0] = 0;
    if(rg_[3] < 0xff) {
      rg_[3]++;
      return false;
    }
  return true;
}

bool FourBytes::LoBump() {
  for(int i = 0; i < 2; i++) {
    if(rg_[i] < 0xff) {
      rg_[i]++;
      return false;
    }
  rg_[i]= 0;
  }
  return true;
}

bool FourBytes::Bump() {
  for(int i = 0; i < 4; i++) {
    if(rg_[i]<0xff) {
      rg_[i]++;
      return false;
    }
  rg_[i]= 0;
  }
  return true;
}

bool FourBytes::BumpUnestimated() {
  // exclude bits 7, 15, 23, 31
  for(int i = 0; i < 4; i++) {
    if((rg_[i] & 0xfe) != 0xfe) {
      rg_[i] += 2;
      return false;
    }
  rg_[i] &= 0x1;
  }
  return true;
}

bool FourBytes::Equal(FourBytes& o1) {
  for(int i = 0; i < 4; i++) {
    if(rg_[i]!=o1.rg_[i])
      return false;
  }
  return true;
}

bool FourBytes::HiEqual(FourBytes& o1) {
  for(int i = 2; i < 4; i++) {
    if(rg_[i]!=o1.rg_[i])
      return false;
  }
  return true;
}

bool FourBytes::LoEqual(FourBytes& o1) {
  for(int i = 0; i < 2; i++) {
    if(rg_[i]!=o1.rg_[i])
      return false;
  }
  return true;
}

void FourBytes::CopyToMe(FourBytes& in) {
  for(int j = 0; j < 4; j++) {
    rg_[j]= in.rg_[j];
  }
}

void FourBytes::XorToMe(FourBytes& in) {
  for(int j = 0; j < 4; j++) {
    rg_[j]^= in.rg_[j];
  }
}

void FourBytes::XorandPut(FourBytes& in1, FourBytes& in2) {
  for(int j=0; j < 4; j++) {
    rg_[j]= in1.rg_[j] ^ in2.rg_[j];
  }
}

void FourBytes::FillFromBytes(byte* in) {
  for (int j = 0; j < 4; j++)
    rg_[j] = *(in++);
}

void FourBytes::CopyToBytes(byte* out) {
  for (int j = 0; j < 4; j++)
    *(out++) = rg_[j];
}

void FourBytes::FillFromUint32(uint32_t u) {
  for(int j = 0; j < 4; j++)
      rg_[j] = (u >> (8 * (3 - j))) & 0xff;
}

void FourBytes::CopyToUint32(uint32_t* out) {
}

void FourBytes::Print() {
  for(int j = 0; j < 4; j++)
    printf("%02x", rg_[j]);
}

void FealState::FillFromBytes(byte* in) {
  for (int j = 0; j<4; j++)
    left_.rg_[j] = *(in++);
  for (int j = 0; j < 4; j++)
    right_.rg_[j] = *(in++);
}

void FealState::CopyToBytes(byte* out) {
  for (int j = 0; j < 4; j++)
    *(out++)= left_.rg_[j];
  for (int j = 0; j < 4; j++)
    *(out++)= right_.rg_[j];
}

void FealState::Swap() {
  FourBytes t;

  t.CopyToMe(left_);
  left_.CopyToMe(right_);
  right_.CopyToMe(t);
}

void FealState::CopyToMe(FealState& in) {
  left_.CopyToMe(in.left_);
  right_.CopyToMe(in.right_);
}

void FealState::XorToMe(FealState& in) {
  left_.XorToMe(in.left_);
  right_.XorToMe(in.right_);
}

void FealState::XorandPut(FealState& in1, FealState& in2) {
  left_.XorandPut(in1.left_, in2.left_);
  right_.XorandPut(in1.right_, in2.right_);
}

bool FealState::Equal(FealState& in) {
  return left_.Equal(in.left_) && right_.Equal(in.right_);
}

void FealState::Print() {
  left_.Print();
  printf(" ");
  right_.Print();
}

void Feal4::EncryptBlock(byte* in, byte* out, bool fPrint) {
  FealState t;
  FourBytes f_arg;
  FourBytes f_out;

  t.FillFromBytes(in);
  if (fPrint) {
    printf("Plain    : "); t.Print(); printf("\n");
  }

  // xor in initial whitening keys
  t.left_.XorToMe(rk_[4]);
  t.right_.XorToMe(rk_[5]);
  if (fPrint) {
    printf("\tfirst wht: "); t.Print(); printf("\n");
  }

  // xor plain left into right
  t.right_.XorToMe(t.left_);
  if (fPrint) {
    printf("\tPL+PR    : "); t.Print(); printf("\n");
  }

  // Three regular rounds
  for (int j = 0; j < 3; j++) {
    f_arg.XorandPut(t.right_, rk_[j]);
    F(f_arg, f_out);
    t.left_.XorToMe(f_out);
    t.Swap();
    if (fPrint) {
      printf("\trnd-key  : "); rk_[j].Print();printf("\n");
      printf("\tfarg     : "); f_arg.Print(); printf(", fout      : "); f_out.Print(); printf("\n");
      printf("\trnd(%d)   : ", j + 1); t.Print(); printf("\n");
    }
  }

  // One round without the switch
  f_arg.XorandPut(t.right_, rk_[3]);
  F(f_arg, f_out);
  t.left_.XorToMe(f_out);
  if (fPrint) {
      printf("\trnd(4)   : "); t.Print(); printf("\n");
  }

  // xor left to right
  t.right_.XorToMe(t.left_);
  if (fPrint) {
    printf("\tR4+L4    : "); t.Print(); printf("\n");
  }

  // whitening and xor left to right
  t.left_.XorToMe(rk_[6]);
  t.right_.XorToMe(rk_[7]);
  if (fPrint) {
    printf("Cipher   : "); t.Print(); printf("\n\n");
  }

  t.CopyToBytes(out);
}

void Feal4::DecryptBlock(byte* in, byte* out) {
  FealState t;
  FourBytes f_arg;
  FourBytes f_out;

  t.FillFromBytes(in);

  // xor in initial whitening keys
  t.left_.XorToMe(rk_[6]);
  t.right_.XorToMe(rk_[7]);

  // xor cipher left into right
  t.right_.XorToMe(t.left_);

  // Three regular rounds
  for (int j = 3; j > 0; j--) {
    f_arg.XorandPut(t.right_, rk_[j]);
    F(f_arg, f_out);
    t.left_.XorToMe(f_out);
    t.Swap();
  }

  // One round without the switch
  f_arg.XorandPut(t.right_, rk_[0]);
  F(f_arg, f_out);
  t.left_.XorToMe(f_out);

  // xor left to right
  t.right_.XorToMe(t.left_);

  // whiten
  t.left_.XorToMe(rk_[4]);
  t.right_.XorToMe(rk_[5]);

  t.CopyToBytes(out);
}

void Feal4::CleanKeys() {
}

void Feal4::InitKey(byte* key, bool print) {
  FourBytes x;

  key_.FillFromBytes(key);
  rk_[0].CopyFrom(key_.right_);
  FK(key_.left_, key_.right_, rk_[1]); 
  x.XorandPut(rk_[1], key_.left_);
  FK(rk_[0], x, rk_[2]); 
  for (int j = 3; j < 8; j++) {
    x.XorandPut(rk_[j-1], rk_[j-3]);
    FK(rk_[j-2], x, rk_[j]); 
  }

  if (print) {

    printf("Key schedule\n");
    for (int j = 0; j < 8; j++) {
      printf("  k%d       : ", j); rk_[j].Print(); printf("\n");
    }

    FourBytes t;

    t.XorandPut(rk_[4], rk_[5]);
    t.XorToMe(rk_[0]);
    printf("  k0+k4+k5 : "); t.Print(); printf("\n");

    t.XorandPut(rk_[4], rk_[1]);
    printf("  k1+k4    : "); t.Print(); printf("\n");
  
    t.XorandPut(rk_[6], rk_[2]);
    printf("  k2+k6    : "); t.Print(); printf("\n");

    t.XorandPut(rk_[6], rk_[7]);
    t.XorToMe(rk_[3]);
    printf("  k3+k6+k7 : "); t.Print(); printf("\n");

    t.XorandPut(rk_[4], rk_[5]);
    t.XorToMe(rk_[6]);
    printf("  k4+k5+k6 : "); t.Print(); printf("\n");

    t.XorandPut(rk_[6], rk_[7]);
    t.XorToMe(rk_[4]);
    printf("  k4+k6+k7 : "); t.Print(); printf("\n");
    printf("\n");
  }
}

void switchSides(FourBytes* pL, FourBytes* pR) {
  FourBytes tL;

  tL.CopyToMe(*pL);
  pL->CopyToMe(*pR);
  pR->CopyToMe(tL);
}

void RefactoredFealEncrypt(FourBytes* subKey, FealState& in, FealState* out) {
  FourBytes L, R, s, t;

  // L= left-in, R = L+right-in
  L.CopyToMe(in.left_);
  R.XorandPut(in.left_, in.right_);

  // L+= F(R+K0)
  s.XorandPut(R, subKey[0]);
  F(s, t);
  L.XorToMe(t);
  switchSides(&L, &R);
   
  // L+= F(R+K1)
  s.XorandPut(R, subKey[1]);
  F(s, t);
  L.XorToMe(t);

  // L+= subKeys, R+= subkeys
  L.XorToMe(subKey[4]);
  R.XorToMe(subKey[5]);
  switchSides(&L, &R);

  // L+= F(R+K2)
  s.XorandPut(R, subKey[2]);
  F(s, t);
  L.XorToMe(t);
  switchSides(&L, &R);

  // L+= F(R+K3)
  s.XorandPut(R, subKey[3]);
  F(s, t);
  L.XorToMe(t);

  // left-out= L, right-out = L+R
  out->left_.CopyToMe(L);
  out->right_.XorandPut(L, R);
}

void RefactoredFealDecrypt(FourBytes* subKey, FealState& in, FealState* out) {
}

bool inList(FourBytes& in, int len, FourBytes* list) {
  for (int i = 0; i < len; i++) {
      if (in.Equal(list[i]))
        return true;
  }
  return false;
}

bool addToList(FourBytes& in, int* pLen, FourBytes* list) {
  if (inList(in, *pLen, list))
    return true;
  list[(*pLen)++].CopyToMe(in);
  return true;
}

// ---------------------------------------------------------------------------------------

// Linear Attack helpers

inline int bit5(FourBytes& x) {
  if ((x.rg_[0] >> 2) & 0x1)
    return 1;
  return 0;
}

inline int bit7(FourBytes& x) {
  if (x.rg_[0] & 0x1)
    return 1;
  return 0;
}

inline int bit13(FourBytes& x) {
  if ((x.rg_[1] >> 2) & 0x1)
    return 1;
  return 0;
}

inline int bit15(FourBytes& x) {
  if (x.rg_[1] & 0x1)
    return 1;
  return 0;
}

inline int bit21(FourBytes& x) {
  if ((x.rg_[2] >> 2) & 0x1)
    return 1;
  return 0;
}

inline int bit23(FourBytes& x) {
  if (x.rg_[2] & 0x1)
    return 1;
  return 0;
}

inline int bit29(FourBytes& x) {
  if ((x.rg_[3] >> 2) & 0x1)
    return 1;
  return 0;
}

inline int bit31(FourBytes& x) {
  if (x.rg_[3] & 0x1)
    return 1;
  return 0;
}

inline int biti(int i, FourBytes& x) {
  int j = (i >> 3);
  int k = i & 0x7;
  if (((x.rg_[j] >> (7 - k))) & 0x01)
    return 1;
  return 0;
}

inline void setbit5(byte val, FourBytes& x) {
  byte mask = 0x04;
  x.rg_[0] ^= mask;
  x.rg_[0] |= val << 2;
}

inline void setbit7(byte val, FourBytes& x) {
  byte mask = 0x01;
  x.rg_[0] &= ~mask;
  x.rg_[0] |= val;
}

inline void setbit13(byte val, FourBytes& x) {
  byte mask = 0x04;
  x.rg_[1] &= mask;
  x.rg_[1] |= val << 2;
}

inline void setbit15(byte val, FourBytes& x) {
  byte mask = 0x01;
  x.rg_[1] &= ~mask;
  x.rg_[1] |= val;
}

inline void setbit21(byte val, FourBytes& x) {
  byte mask = 0x04;
  x.rg_[2] ^= mask;
  x.rg_[2] |= val << 2;
}

inline void setbit23(byte val, FourBytes& x) {
  byte mask = 0x01;
  x.rg_[2] &= ~mask;
  x.rg_[2] |= val;
}

inline void setbit29(byte val, FourBytes& x) {
  byte mask = 0x04;
  x.rg_[3] ^= mask;
  x.rg_[3] |= val;
}

inline void setbit31(byte val, FourBytes& x) {
  byte mask = 0x01;
  x.rg_[3] &= ~mask;
  x.rg_[3] |= val;
}

inline void setbiti(int i, byte val, FourBytes& x) {
  int j = (i >> 3);
  int k = i & 0x7;
  byte mask = 0x01 >> (7 - k);

  x.rg_[j] ^= mask;
  x.rg_[j] |= val >> (7 - k);
}

// -----------------------------------------------------------------------------------------

//      Round 1

//  Test: b= (PL+CL)[5, 13, 21] + (PL+CL+CR)[15] + (F(PL+PR+tK))[15] for xored key
bool Round1AdjustedTestCorrectE(FourBytes tK, int numPairs, FealState* inBlks, FealState* outBlks) {
  int j;
  FourBytes R0, R4;
  FourBytes R0X;

  int d[2];
  FourBytes r, t, PL, PR, CL, CR;
  d[0] = 0; d[1] = 0;
  for (int k = 0; k < numPairs; k++) {

      PL.CopyFrom(inBlks[k].left_);
      PR.CopyFrom(inBlks[k].right_);
      CL.CopyFrom(outBlks[k].left_);
      CR.CopyFrom(outBlks[k].right_);

      R0.XorandPut(PL, PR);
      R4.XorandPut(CL, CR);
      R0X.Zero();
      R0X.rg_[1] = R0.rg_[0] ^ R0.rg_[1];
      R0X.rg_[2] = R0.rg_[3] ^ R0.rg_[2];
      r.XorandPut(R0X, tK);
      F(r, t);

      j = bit5(CL) ^ bit5(R0) ^ bit13(CL) ^ bit13(R0) ^ bit21(CL) ^ bit21(R0) ^ 
          bit15(PL) ^ bit15(R4) ^ bit15(t);

      d[j]++;
      if ((d[0] * d[1]) !=0) {
        return false;
      }
  }
  return true;
}

//  Test: a= (CL+PL+PR)[23,29] + (PL+CL+CR)[31] + (F(PL+PR+tK))[31]
bool Round1TestCorrect(FourBytes tK, int numPairs, FealState* inBlks, FealState* outBlks) {
  int j;
  int a[2];
  int b[2];
  int c[2];
  int d[2];
  FourBytes r, t, PL, PR, CL, CR;
  FourBytes R0, R4;

  a[0] = 0; a[1] = 0;
  b[0] = 0; b[1] = 0;
  c[0] = 0; c[1] = 0;
  d[0] = 0; d[1] = 0;
  for (int k = 0; k < numPairs; k++) {

      PL.CopyFrom(inBlks[k].left_);
      PR.CopyFrom(inBlks[k].right_);
      CL.CopyFrom(outBlks[k].left_);
      CR.CopyFrom(outBlks[k].right_);

      R0.XorandPut(PL, PR);
      R4.XorandPut(CL, CR);

      r.XorandPut(R0, tK);
      F(r, t);

      // hA(P,C)=(CL+PL+PR)[23,29]+PL[31]+ (CL+CR)[31]+F(PL+PR+K0)[31]
      j = bit23(CL) ^ bit29(CL) ^ bit23(R0) ^ bit29(R0) ^ 
          bit31(PL) ^ bit31(R4) ^ bit31(t);

      a[j]++;
      if ((a[0] * a[1]) !=0)
        return false;
      j = bit13(CL) ^ bit13(R0) ^ 
          bit7(PL) ^ bit7(R4) ^ bit7(t) ^
          bit15(PL) ^ bit15(R4) ^ bit15(t) ^
          bit23(PL) ^ bit23(R4) ^ bit23(t) ^
          bit31(PL) ^ bit31(R4) ^ bit31(t);

      b[j]++;
      if ((b[0] * b[1]) !=0)
        return false;

      j = bit5(CL) ^ bit5(R0) ^ bit15(CL) ^ bit15(R0) ^
          bit7(PL) ^ bit7(R4) ^ bit7(t);

      c[j]++;
      if ((c[0] * c[1]) !=0)
        return false;

      j = bit21(CL) ^ bit21(R0) ^ bit15(CL) ^ bit15(R0) ^ 
          bit23(PL) ^ bit23(R4) ^ bit23(t) ^
          bit31(PL) ^ bit31(R4) ^ bit31(t);

      d[j]++;
      if ((d[0] * d[1]) !=0)
        return false;
  }
  return true;
}

//      Round 2

// If X = PL+F(PL+PR+K0), Y = F(CL+CR+K3) and Z= PL+PR+CL
// (Z+Y)[13]+X[7,15,23,31]+1= K1[7,15,23,31]
// (Z+Y)[5,15]+X[7]= K1[7]
// (Z+Y)[15,21]+X[23,31]= K1[23,31]
// (Z+Y)[23,29]+X[31]+1= K1[31]
bool EstimateK1(FourBytes K0, FourBytes K3, int numPairs,
                FealState* inBlks, FealState* outBlks, FourBytes* out) {
  int j;
  FourBytes r, s, t, PL, PR, CL, CR;
  FourBytes X, Y, Z;
  byte val31, val23, val7, val15;
  byte t_val31, t_val23, t_val7, t_val15;

  out->Zero();
  for (int k = 0; k < numPairs; k++) {

      PL.CopyFrom(inBlks[k].left_);
      PR.CopyFrom(inBlks[k].right_);
      CL.CopyFrom(outBlks[k].left_);
      CR.CopyFrom(outBlks[k].right_);

      r.XorandPut(PL, PR);
      r.XorToMe(K0);
      F(r, s);
      X.XorandPut(PL, s);
      // s = F(PL+PR+K0)
      // X = PL+F(PL+PR+K0)

      r.XorandPut(CL, CR);
      r.XorToMe(K3);
      F(r, Y);
      // Y= F(CL+CR+K3)

      Z.XorandPut(PL, PR);
      Z.XorToMe(CL);
      // Z= PL+PR+CL

      val31 = bit23(Z) ^ bit23(Y) ^ bit29(Z) ^ bit29(Y) ^ bit31(X) ^ 1;
      val23 = bit15(Z) ^ bit15(Y) ^ bit21(Z) ^ bit21(Y) ^ bit23(X) ^ bit31(X) ^ val31;
      val7 = bit15(Z) ^ bit15(Y) ^ bit5(Z) ^ bit5(Y) ^ bit7(X);
      val15 = bit13(Z) ^ bit13(Y) ^ bit7(X)^ bit15(X)^ bit23(X) ^ bit31(X) ^ val7 ^ val23 ^ val31 ^ 1;

      if (k == 0) {
        t_val31 = val31;
        t_val23 = val23;
        t_val15 = val15;
        t_val7 = val7;
      }

      if (t_val31 != val31 ) { // || t_val23 != val23 || t_val15 != val15 || t_val7 != val7) {
        return false;
      }
  }
  return true;
}

// If X = CL+F(CL+CR+K3), Y = F(PL+PR+K0) and Z= CL+CR+PL
// (Z+Y)[13]+X[7,15,23,31]+1= K2[7,15,23,31]
// (Z+Y)[5,15]+X[7]= K2[7]
// (Z+Y)[15,21]+X[23,31]= K2[23,31]
// (Z+Y)[23,29]+X[31]+1= K2[31]
bool EstimateK2(FourBytes K0, FourBytes K3, int numPairs,
                FealState* inBlks, FealState* outBlks, FourBytes* out) {
  int j;
  FourBytes r, s, t, PL, PR, CL, CR;
  FourBytes X, Y, Z;
  byte val31, val23, val7, val15;
  byte t_val31, t_val23, t_val7, t_val15;

  for (int k = 0; k < numPairs; k++) {

      PL.CopyFrom(inBlks[k].left_);
      PR.CopyFrom(inBlks[k].right_);
      CL.CopyFrom(outBlks[k].left_);
      CR.CopyFrom(outBlks[k].right_);

      r.XorandPut(CL, CR);
      r.XorToMe(K3);
      // r = CL+CR+K3
      F(r, t);
      // t = F(r)
      X.XorandPut(CL, t);
      // X = CL+F(CL+CR+K3)

      r.XorandPut(PL, PR);
      r.XorToMe(K0);
      F(r,Y);
      // Y = F(PL+PR+K0)

      Z.XorandPut(CL, CR);
      Z.XorToMe(PL);
      // Z = CL+CR+PL

      val31 = bit23(Z) ^ bit23(Y) ^ bit29(Z) ^ bit29(Y) ^ bit31(X) ^ 1;
      val23 = bit15(Z) ^ bit15(Y) ^ bit21(Z) ^ bit21(Y) ^ bit23(X) ^ bit31(X) ^ val31;
      val7 = bit15(Z) ^ bit15(Y) ^ bit5(Z) ^ bit5(Y) ^ bit7(X);
      val15 = bit13(Z) ^ bit13(Y) ^ bit7(X)^ bit15(X)^ bit23(X) ^ bit31(X) ^ val7 ^ val23 ^ val31 ^ 1;

      if (k == 0) {
        t_val31 = val31;
        t_val23 = val23;
        t_val15 = val15;
        t_val7 = val7;
      }

      if (t_val31 != val31 ) //|| t_val23 != val23 || t_val15 != val15 || t_val7 != val7)
        return false;
  }
  return true;
}

bool Round2MidEstimate(FourBytes tK, FourBytes K0, FourBytes K3, int numPairs,
                                FealState* inBlks, FealState* outBlks) {
  FourBytes r, s, t, PL, PR, CL, CR;
  FourBytes X, Y, Z, midX;
  byte y1, y1t;

  for (int k = 0; k < numPairs; k++) {

      PL.CopyFrom(inBlks[k].left_);
      PR.CopyFrom(inBlks[k].right_);
      CL.CopyFrom(outBlks[k].left_);
      CR.CopyFrom(outBlks[k].right_);

      r.XorandPut(PL, PR);
      r.XorToMe(K0);
      F(r, s);
      X.XorandPut(PL, s);
      // s = F(PL+PR+K0)
      // X = PL+F(PL+PR+K0)

      r.XorandPut(CL, CR);
      r.XorToMe(K3);
      F(r, Y);
      // Y= F(CL+CR+K3)

      Z.XorandPut(PL, PR);
      Z.XorToMe(CL);
      // Z= PL+PR+CL

      midX.rg_[1] = X.rg_[0] ^ X.rg_[1];
      midX.rg_[2] = X.rg_[2] ^ X.rg_[3];
      midX.rg_[0] = 0; midX.rg_[3] = 0;
      midX.XorToMe(tK);
      F(midX, t);

      y1 = t.rg_[1] ^ Z.rg_[1] ^ Y.rg_[1];
      if (k == 0)
        y1t = y1;
      if (y1t != y1)
        return false;
  }
  return true;
}

bool Round2TestCorrect(FourBytes tK, FourBytes K0, FourBytes K3, int numPairs,
       FealState* inBlks, FealState* outBlks) {

  FourBytes r, t, PL, PR, CL, CR;
  FourBytes X, Y, Z;
  FourBytes K, Kt;

  for (int k = 0; k < numPairs; k++) {

      PL.CopyFrom(inBlks[k].left_);
      PR.CopyFrom(inBlks[k].right_);
      CL.CopyFrom(outBlks[k].left_);
      CR.CopyFrom(outBlks[k].right_);

      r.XorandPut(PL, PR);
      r.XorToMe(K0);
      // r = PL+PR+K0
      F(r, t);
      // t = F(r)
      X.XorandPut(PL, t);
      // X = PL+F(PL+PR+K0)

      r.XorandPut(CL, CR);
      r.XorToMe(K3);
      F(r,Y);
      // Y = F(CL+CR+K3)

      Z.XorandPut(PL, PR);
      Z.XorToMe(CL);
      // Z = PL+PR+CL

      r.XorandPut(X, tK);
      F(r, t);
      // t= F(PL+F(PL+PR+K0)+tK)

      Kt.XorandPut(Y, Z);
      Kt.XorToMe(t);
      // Kt = Y+Z+F(PL+F(PL+PR+K0)+tK)

      if (k == 0) {
        K.CopyToMe(Kt);
        continue;
      }
      if (!K.Equal(Kt))
        return false;
  }
  return true;
}

//      Round 3

bool Round3MidEstimate(FourBytes tK, FourBytes K0, FourBytes K3, int numPairs,
                                FealState* inBlks, FealState* outBlks) {
  FourBytes R0, R4;
  FourBytes r, t, PL, PR, CL, CR;
  FourBytes X, Y, Z, midX;
  byte y1, y1t;

  for (int k = 0; k < numPairs; k++) {

      PL.CopyFrom(inBlks[k].left_);
      PR.CopyFrom(inBlks[k].right_);
      CL.CopyFrom(outBlks[k].left_);
      CR.CopyFrom(outBlks[k].right_);

      R0.XorandPut(PL, PR);
      R4.XorandPut(CL, CR);

      r.XorandPut(CL, CR);
      r.XorToMe(K3);
      F(r,t);
      X.XorandPut(CL,t);

      r.XorandPut(PL, PR);
      r.XorToMe(K0);
      F(r,Y);

      Z.XorandPut(CL, CR);
      Z.XorToMe(PL);

      midX.rg_[1] = X.rg_[0] ^ X.rg_[1];
      midX.rg_[2] = X.rg_[2] ^ X.rg_[3];
      midX.rg_[0] = 0; midX.rg_[3] = 0;
      midX.XorToMe(tK);
      F(midX, t);

      y1 = t.rg_[1] ^ Z.rg_[1] ^ Y.rg_[1];
      if (k == 0)
        y1t = y1;
      if (y1t != y1)
        return false;
  }
  return true;
}

bool Round3TestCorrect(FourBytes tK,  FourBytes K0, FourBytes K3, int numPairs,
        FealState* inBlks, FealState* outBlks) {
  FourBytes r, t, PL, PR, CL, CR;
  FourBytes R0, R4;
  FourBytes X, Y, Z;
  FourBytes K, Kt;

  for (int k = 0; k < numPairs; k++) {

      PL.CopyFrom(inBlks[k].left_);
      PR.CopyFrom(inBlks[k].right_);
      CL.CopyFrom(outBlks[k].left_);
      CR.CopyFrom(outBlks[k].right_);

      R0.XorandPut(PL, PR);
      R4.XorandPut(CL, CR);

      r.XorandPut(CL, CR);
      r.XorToMe(K3);
      // r= CL+CR+K3
      F(r,t);
      X.XorandPut(CL,t);
      // X= CL+F(CL+CR+K3)

      r.XorandPut(PL, PR);
      r.XorToMe(K0);
      F(r,Y);
      // Y= F(PL+PR+K0)

      Z.XorandPut(CL, CR);
      Z.XorToMe(PL);
      // Z= CL+CR+PL

      r.XorandPut(X, tK);
      F(r, t);
      // t= F(CL+F(CL+CR+K3)+tK)
      Kt.XorandPut(Y,Z);
      Kt.XorToMe(t);

      if (k == 0) {
        K.CopyToMe(Kt);
        continue;
      }
      if (!K.Equal(Kt))
        return false;
  }
  return true;
}

//      Round 4

bool Round4AdjustedTestCorrectE(FourBytes tK, int numPairs, FealState* inBlks, FealState* outBlks) {
  int j;
  FourBytes R0, R4;
  FourBytes R4X;
  int d[2];
  FourBytes r, t, PL, PR, CL, CR;

  d[0] = 0; d[1] = 0;
  for (int k = 0; k < numPairs; k++) {

      PL.CopyFrom(inBlks[k].left_);
      PR.CopyFrom(inBlks[k].right_);
      CL.CopyFrom(outBlks[k].left_);
      CR.CopyFrom(outBlks[k].right_);

      R0.XorandPut(PL, PR);
      R4.XorandPut(CL, CR);
      R4X.Zero();
      R4X.rg_[1] = R4.rg_[0] ^ R4.rg_[1];
      R4X.rg_[2] = R4.rg_[3] ^ R4.rg_[2];

      r.XorandPut(R4X, tK);
      F(r, t);

      j = bit5(PL) ^ bit5(R4) ^
          bit13(PL) ^ bit13(R4) ^
          bit21(PL) ^ bit21(R4) ^ 
          bit15(CL) ^ bit15(R0) ^ bit15(t);

      d[j]++;
      if ((d[0] * d[1]) !=0) {
        return false;
      }
  }
  return true;
}

bool Round4TestCorrect(FourBytes tK, int numPairs, FealState* inBlks, FealState* outBlks) {
  int j;
  int a[2];
  int b[2];
  int c[2];
  int d[2];
  FourBytes r, t, PL, PR, CL, CR;
  FourBytes R0, R4;

  a[0] = 0; a[1] = 0;
  b[0] = 0; b[1] = 0;
  c[0] = 0; c[1] = 0;
  d[0] = 0; d[1] = 0;
  for (int k = 0; k < numPairs; k++) {

    PL.CopyFrom(inBlks[k].left_);
    PR.CopyFrom(inBlks[k].right_);
    CL.CopyFrom(outBlks[k].left_);
    CR.CopyFrom(outBlks[k].right_);

    R0.XorandPut(PL, PR);
    R4.XorandPut(CL, CR);

    r.XorandPut(R4, tK);
    F(r, t);

    j = bit23(PL) ^ bit29(PL) ^ bit23(R4) ^ bit29(R4) ^ 
        bit31(CL) ^ bit31(R0) ^ bit31(t);

    a[j]++;
    if ((a[0] * a[1]) !=0)
      return false;

    j = bit13(PL) ^ bit13(R4) ^ 
        bit7(CL) ^ bit7(R0) ^ bit7(t) ^
        bit15(CL) ^ bit15(R0) ^ bit15(t) ^
        bit23(CL) ^ bit23(R0) ^ bit23(t) ^
        bit31(CL) ^ bit31(R0) ^ bit31(t);

    b[j]++;
    if ((b[0] * b[1]) !=0)
      return false;

    j = bit5(PL) ^ bit5(R4) ^ bit15(PL) ^ bit15(R4) ^
        bit7(CL) ^ bit7(R0) ^ bit7(t);

    c[j]++;
    if ((c[0] * c[1]) !=0)
      return false;

    j = bit21(PL) ^ bit21(R4) ^ 
        bit15(PL) ^ bit15(R4) ^ 
        bit23(CL) ^ bit23(R0) ^ bit23(t) ^
        bit31(CL) ^ bit31(R0) ^ bit31(t);

    d[j]++;
    if ((d[0] * d[1]) !=0)
      return false;
  }
  return true;
}

bool TestRefactored(int numBlks, FealState* plainBlks, FealState* cipherBlks, FourBytes* subKeys) {
  FealState tOut;

  for (int i = 0; i< numBlks; i++) {
    RefactoredFealEncrypt(subKeys, plainBlks[i], &tOut);
    if (!tOut.Equal(cipherBlks[i])) {
      return false;
    }
  }
  return true;
}

bool GetOuterRoundCandidates(int numPairs, FealState* inBlks, FealState* outBlks,
               int* pNumRound1, int* pNumRound4, FourBytes* candidatesRound1,
               FourBytes* candidatesRound4, int maxResults = 2) {
  FourBytes tK;
  byte a, b;
  FourBytes fullKey;

  int nMidRound1 = 0;
  FourBytes midRangeRound1[MAXTRIALKEYS];
  int nMidRound4 = 0;
  FourBytes midRangeRound4[MAXTRIALKEYS];

  // Round 1

  tK.Zero();
  nMidRound1 = 0;
  while(!tK.MidBump()) {
      if (Round1AdjustedTestCorrectE(tK, numPairs, inBlks, outBlks)) {
          if (nMidRound1 >= MAXTRIALKEYS)
            break;
          midRangeRound1[nMidRound1++].CopyToMe(tK);
      }
  }

  printf("%d mid candidates, round 1\n", nMidRound1);

  //  Find candidates for K0
  *pNumRound1 = 0;
  for (int i = 0; i < nMidRound1; i++) {
    tK.Zero();
    while(!tK.OuterBump()) {
      fullKey.rg_[0] = tK.rg_[0];
      fullKey.rg_[1] = tK.rg_[0] ^ midRangeRound1[i].rg_[1];
      fullKey.rg_[2] = tK.rg_[3] ^ midRangeRound1[i].rg_[2];
      fullKey.rg_[3] = tK.rg_[3];
      if (Round1TestCorrect(fullKey, numPairs, inBlks, outBlks)) {
        if(*pNumRound1 < maxResults) {
          candidatesRound1[(*pNumRound1)++].CopyToMe(fullKey);
          if (*pNumRound1 >= maxResults)
            break;
        }
      }
    }
  }

  // Round 4

  *pNumRound4 = 0;
  tK.Zero();
  nMidRound4 = 0;
  while(!tK.MidBump()) {
      if (Round4AdjustedTestCorrectE(tK, numPairs, inBlks, outBlks)) {
          if (nMidRound4 >= MAXTRIALKEYS)
            break;
          midRangeRound4[nMidRound4++].CopyToMe(tK);
      }
  }

  printf("%d mid candidates, round 4\n", nMidRound4);

  //  Find candidates for K3
  for (int i = 0; i < nMidRound4; i++) {
    tK.Zero();
    while(!tK.OuterBump()) {
      fullKey.rg_[0] = tK.rg_[0];
      fullKey.rg_[1] = tK.rg_[0] ^ midRangeRound4[i].rg_[1];
      fullKey.rg_[2] = tK.rg_[3] ^ midRangeRound4[i].rg_[2];
      fullKey.rg_[3] = tK.rg_[3];
      if (Round4TestCorrect(fullKey, numPairs, inBlks, outBlks)) {
        if(*pNumRound4 < maxResults) {
          candidatesRound4[(*pNumRound4)++].CopyToMe(fullKey);
          if ((*pNumRound4) >= maxResults)
            break;
        }
      }
    }
  }
  return true;
}

bool GetInnerRoundCandidates(int numPairs, FealState* inBlks, FealState* outBlks,
               FourBytes& K0, FourBytes& K3,
               int* pNumRound2, int* pNumRound3, FourBytes* candidatesRound2,
               FourBytes* candidatesRound3, FourBytes* k4k5k6, FourBytes* k4k6k7,
               int maxResults = 2) {
  FourBytes tK;
  byte a, b;
  FourBytes fullKey;

  int nMidRound2 = 0;
  FourBytes midRangeRound2[MAXTRIALKEYS];
  int nMidRound3 = 0;
  FourBytes midRangeRound3[MAXTRIALKEYS];

  printf("K0: "); K0.Print();
  printf(", K3: "); K3.Print(); printf("\n");

  tK.Zero();
  nMidRound2 = 0;
  while(!tK.MidBump()) {
    if (Round2MidEstimate(tK, K0, K3, numPairs, inBlks, outBlks)) {
        if (nMidRound2 >= MAXTRIALKEYS)
          break;
        midRangeRound2[nMidRound2++].CopyToMe(tK);
    }
  }

  printf("%d mid candidates, round 2\n", nMidRound2);

  //  Find candidates for K1
  *pNumRound2 = 0;

  for (int i = 0; i < nMidRound2; i++) {
    tK.Zero();
    while(!tK.OuterBump()) {
      fullKey.rg_[0] = tK.rg_[0];
      fullKey.rg_[1] = tK.rg_[0] ^ midRangeRound2[i].rg_[1];
      fullKey.rg_[2] = tK.rg_[3] ^ midRangeRound2[i].rg_[2];
      fullKey.rg_[3] = tK.rg_[3];
      if (Round2TestCorrect(fullKey, K0, K3, numPairs, inBlks, outBlks)) {
        if(*pNumRound2 < maxResults) {
          FourBytes r, t, PL, PR, CL, CR;
          FourBytes X, Y, Z, K4K5K6;

          PL.CopyFrom(inBlks[0].left_);
          PR.CopyFrom(inBlks[0].right_);
          CL.CopyFrom(outBlks[0].left_);
          CR.CopyFrom(outBlks[0].right_);

          r.XorandPut(PL, PR);
          r.XorToMe(K0);
          // r = PL+PR+K0
          F(r, t);
          // t = F(r)
          X.XorandPut(PL, t);
          // X = PL+F(PL+PR+K0)

          r.XorandPut(CL, CR);
          r.XorToMe(K3);
          F(r,Y);
          // Y = F(CL+CR+K3)

          Z.XorandPut(PL, PR);
          Z.XorToMe(CL);
          // Z = PL+PR+CL

          r.XorandPut(X, fullKey);
          F(r, t);
          // t= F(PL+F(PL+PR+K0)+fullKey)

          K4K5K6.XorandPut(Y, Z);
          K4K5K6.XorToMe(t);

          k4k5k6[*pNumRound2].CopyToMe(K4K5K6);
          candidatesRound2[(*pNumRound2)++].CopyToMe(fullKey);
          if (*pNumRound2 >= maxResults)
            break;
        }
      }
    }
  }

  tK.Zero();
  nMidRound3 = 0;
  while(!tK.MidBump()) {
    if (Round3MidEstimate(tK, K0, K3, numPairs, inBlks, outBlks)) {
        if (nMidRound3 >= MAXTRIALKEYS)
          break;
        midRangeRound3[nMidRound3++].CopyToMe(tK);
    }
  }
  printf("%d mid candidates, round 3\n", nMidRound3);

  //  Find candidates for K2
  *pNumRound3 = 0;
  for (int i = 0; i < nMidRound3; i++) {
    tK.Zero();
    while(!tK.OuterBump()) {
      fullKey.rg_[0] = tK.rg_[0];
      fullKey.rg_[1] = tK.rg_[0] ^ midRangeRound3[i].rg_[1];
      fullKey.rg_[2] = tK.rg_[3] ^ midRangeRound3[i].rg_[2];
      fullKey.rg_[3] = tK.rg_[3];
      if (Round3TestCorrect(fullKey, K0, K3, numPairs, inBlks, outBlks)) {
        if(*pNumRound3 < maxResults) {
          FourBytes r, t, PL, PR, CL, CR;
          FourBytes X, Y, Z, K4K6K7;

          PL.CopyFrom(inBlks[0].left_);
          PR.CopyFrom(inBlks[0].right_);
          CL.CopyFrom(outBlks[0].left_);
          CR.CopyFrom(outBlks[0].right_);

          r.XorandPut(CL, CR);
          r.XorToMe(K3);
          // r = CL+CR+K3
          F(r, t);
          // t = F(r)
          X.XorandPut(CL, t);
          // X = CL+F(CL+CR+K3)

          r.XorandPut(PL, PR);
          r.XorToMe(K0);
          F(r,Y);
          // Y = F(PL+PR+K0)

          Z.XorandPut(CL, CR);
          Z.XorToMe(PL);
          // Z = CL+CR+PL
  
          r.XorandPut(X, fullKey);
          F(r, t);
          // t= F(CL+F(CL+CR+K3)+fullKey)
  
          K4K6K7.XorandPut(Y, Z);
          K4K6K7.XorToMe(t);
          k4k6k7[*pNumRound3].CopyToMe(K4K6K7);
          candidatesRound3[(*pNumRound3)++].CopyToMe(fullKey);
          k4k6k7[*pNumRound3].CopyToMe(K4K6K7);
          if (*pNumRound3 >= maxResults)
            break;
        }
      }
    }
  }
 
  return true;
}

bool RunLinearAttack(int numPairs, FealState* inBlks, FealState* outBlks, FourBytes* subKeys) {

  int numCandRound1 = 0;
  int numCandRound2 = 0;
  int numCandRound3 = 0;
  int numCandRound4 = 0;
  FourBytes candidatesRound1[MAXTRIALKEYS];
  FourBytes candidatesRound2[MAXTRIALKEYS];
  FourBytes candidatesRound3[MAXTRIALKEYS];
  FourBytes candidatesRound4[MAXTRIALKEYS];
  FourBytes k4k5k6[MAXTRIALKEYS];
  FourBytes k4k6k7[MAXTRIALKEYS];

  FourBytes tK;
  byte a, b;
  FourBytes fullKey;
  bool fReturn = false;
  int nSucceeded = 0;

  printf("RunLinearAttack: %d corresponding plain/cipher pairs\n\n", numPairs); 

  int nMidRound1 = 0;
  FourBytes midRangeRound1[MAXTRIALKEYS];
  int nMidRound2 = 0;
  FourBytes midRangeRound2[MAXTRIALKEYS];
  int nMidRound3 = 0;
  FourBytes midRangeRound3[MAXTRIALKEYS];
  int nMidRound4 = 0;
  FourBytes midRangeRound4[MAXTRIALKEYS];

  if (!GetOuterRoundCandidates(numPairs, inBlks, outBlks,
               &numCandRound1, &numCandRound4, candidatesRound1,
               candidatesRound4, MAXTRIALKEYS)) {
    printf("Can't get outer keys\n");
  }

  for (int n = (numCandRound1 - 1); n >= 0; n--) {
    for (int m = (numCandRound4 - 1); m >= 0; m--) {
      printf("K0: "); candidatesRound1[n].Print();
      printf(", K3: "); candidatesRound4[m].Print(); printf("\n");
      if (!GetInnerRoundCandidates(numPairs, inBlks, outBlks,
               candidatesRound1[n], candidatesRound4[m],
               &numCandRound2, &numCandRound3, candidatesRound2,
               candidatesRound3, k4k5k6, k4k6k7, MAXTRIALKEYS)) {
        printf("Can't get inner keys\n");
      }
      for (int i = (numCandRound2 - 1); i >= 0; i--) {
        for (int j = (numCandRound3 - 1); j >= 0; j--) {
          printf("\nFinal check\n");
          printf("  Round 1 trial key: "); candidatesRound1[n].Print();printf("\n");
          printf("  Round 2 trial key: "); candidatesRound2[i].Print();printf("\n");
          printf("  Round 3 trial key: "); candidatesRound3[j].Print();printf("\n");
          printf("  Round 4 trial key: "); candidatesRound4[m].Print();printf("\n");
          printf("  k4k5k6  trial key: "); k4k5k6[i].Print();printf("\n");
          printf("  k4k6k7  trial key: "); k4k6k7[j].Print();printf("\n");
          subKeys[0].CopyToMe(candidatesRound1[n]);
          subKeys[1].CopyToMe(candidatesRound2[i]);
          subKeys[2].CopyToMe(candidatesRound3[j]);
          subKeys[3].CopyToMe(candidatesRound4[m]);
          subKeys[4].CopyToMe(k4k5k6[i]);
          subKeys[5].CopyToMe(k4k6k7[j]);
         if (TestRefactored(numPairs, inBlks, outBlks, subKeys)) {
            printf("  succeeded\n\n");
            fReturn = true;
            nSucceeded++;
          } else {
            printf("  failed\n\n");
          }
        }
      }
    }
  }
  printf("%d succeeded\n", nSucceeded);
  return fReturn;
}

bool LinearAttack(int numBlocks, FealState* plainBlocks, FealState* cipherBlocks) {

  if (numBlocks > MAXPAIRS)
    numBlocks = MAXPAIRS;

  FourBytes subKeys[6];

  if (RunLinearAttack(numBlocks, plainBlocks, cipherBlocks, subKeys)) {
    printf("\nLinear attack succeeded\n");
    printf("  K0    : "); subKeys[0].Print();printf("\n");
    printf("  K1    : "); subKeys[1].Print();printf("\n");
    printf("  K2    : "); subKeys[2].Print();printf("\n");
    printf("  K3    : "); subKeys[3].Print();printf("\n");
    printf("  k4k5k6: "); subKeys[4].Print();printf("\n");
    printf("  k4k6k7: "); subKeys[5].Print();printf("\n");
    return true;
  } else {
    printf("\nLinear attack failed\n");
    return false;
  }
}

// ---------------------------------------------------------------------------------------

bool TestOuterRoundDiff(FourBytes& key, FourBytes& in1, FourBytes& in2, FourBytes& outDiff) {
  FourBytes out1;
  FourBytes out2;
  FourBytes arg1, arg2;
  FourBytes outd;

  arg1.XorandPut(in1, key);
  arg2.XorandPut(in2, key);
  F(arg1, out1);
  F(arg2, out2);
  outd.XorandPut(out1, out2);
  return outDiff.Equal(outd);
}

bool TestInnerRoundDiff(FourBytes& key, FourBytes& in1, FourBytes& in2, FourBytes& outDiff) {
  FourBytes out1, out2;
  FourBytes arg1, arg2;
  FourBytes outd;

  arg1.rg_[1] = in1.rg_[0] ^ in1.rg_[1];
  arg1.rg_[2] = in1.rg_[2] ^ in1.rg_[3];
  arg1.XorToMe(key);

  arg2.rg_[1] = in2.rg_[0] ^ in2.rg_[1];
  arg2.rg_[2] = in2.rg_[2] ^ in2.rg_[3];
  arg2.XorToMe(key);

  F(arg1, out1);
  F(arg2, out2);

  outd.XorandPut(out1, out2);
  if ((outd.rg_[1] == outDiff.rg_[1]) && (outd.rg_[2] == outDiff.rg_[2])) {
    return true;
  }
  return false;
}

bool EstimateInnerKeys(int numBlocks, FourBytes* in1, FourBytes* in2,
                             FourBytes* expected_out_xor, double thresh, int maxKeys,
                             int* numCands, FourBytes* keyCand) {
  FourBytes tK;

  while(!tK.MidBump()) {
    int numSuccess = 0;

    for (int i = 0; i < numBlocks; i++) {
      if (TestInnerRoundDiff(tK, in1[i], in2[i], expected_out_xor[i])) {
        numSuccess++;
      }
    }
    if ((((double)numSuccess)/((double)numBlocks)) >= thresh) {
      addToList(tK, numCands, keyCand);
    }
    if (*numCands >= maxKeys)
      break;
  }
  return *numCands > 0;
}

bool EstimateOuterKeys(int numBlocks, FourBytes* in1, FourBytes* in2,
                       FourBytes& innerKey, FourBytes* expected_out_xor,
                       double thresh, int maxKeys, int* numCands, FourBytes* keyCand) {
  FourBytes tK;
  FourBytes fullKey;

  while(!tK.OuterBump()) {
    fullKey.rg_[0] = tK.rg_[0];
    fullKey.rg_[1] = tK.rg_[0] ^ innerKey.rg_[1];
    fullKey.rg_[2] = tK.rg_[3] ^ innerKey.rg_[2];
    fullKey.rg_[3] = tK.rg_[3];
    
    int numSuccess = 0;

    for (int i = 0; i < numBlocks; i++) {
      if (TestOuterRoundDiff(fullKey, in1[i], in2[i], expected_out_xor[i])) {
        numSuccess++;
      }
    }
    if ((((double)numSuccess)/((double)numBlocks)) >= thresh) {
      addToList(fullKey, numCands, keyCand);
    }
    if (*numCands >= maxKeys)
      break;
  }
  return *numCands > 0;
}

bool RunDifferentialAttack(int numBlocks, FealState* plainBlocks1, FealState* plainBlocks2,
                            FealState* cipherBlocks1, FealState* cipherBlocks2, 
                            FealState* plainBlocks3, FealState* plainBlocks4, 
                            FealState* cipherBlocks3, FealState* cipherBlocks4,
                            FourBytes* subKeys) {

  // a2008000 2280 8000
  FourBytes diff1(0x80, 0x80, 0x00, 0x00);
  FourBytes diff2(0x02, 0x00, 0x00, 0x00);
  FourBytes diff3(0xa2, 0x00, 0x80, 0x00);
  FourBytes diff4(0x22, 0x80, 0x80, 0x00);

  FourBytes expected_out_xor[MAXPAIRS];

  int numK3= 0;
  FourBytes r4_in1[MAXPAIRS];
  FourBytes r4_in2[MAXPAIRS];
  FourBytes candK3[MAXPAIRS];

  int numK2 = 0;
  FourBytes r3_in1[MAXPAIRS];
  FourBytes r3_in2[MAXPAIRS];
  FourBytes candK2[MAXPAIRS];

  int numK1 = 0;
  FourBytes r2_in1[MAXPAIRS];
  FourBytes r2_in2[MAXPAIRS];
  FourBytes candK1[MAXPAIRS];

  int numK0 = 0;
  FourBytes r1_in1[MAXPAIRS];
  FourBytes r1_in2[MAXPAIRS];
  FourBytes candK0[MAXPAIRS];

  int numInner= 0;
  FourBytes candInner[MAXPAIRS];
  double thresh = 1.00;

  bool fRet = false;
  int nSucceeded = 0;

  // Round 4
  for (int i = 0; i < numBlocks; i++) {
    FourBytes L4Diff;

    L4Diff.XorandPut(cipherBlocks1[i].left_, cipherBlocks2[i].left_);
    expected_out_xor[i].XorandPut(L4Diff, diff2);

    r4_in1[i].XorandPut(cipherBlocks1[i].left_, cipherBlocks1[i].right_);
    r4_in2[i].XorandPut(cipherBlocks2[i].left_, cipherBlocks2[i].right_);
  }

  numInner = 0;
  if (!EstimateInnerKeys(numBlocks, r4_in1, r4_in2, expected_out_xor, thresh, MAXPAIRS,
                           &numInner, candInner)) {
    printf("Inner round 4 estimate failed\n");
    return false;
  }

  printf("%d inner round 4 keys\n", numInner);
  for (int j = 0; j < numInner; j++) {
    printf("  ");
    candInner[j].Print();
    printf("\n");
  }

  for (int j = 0; j < numInner; j++) {
    if (!EstimateOuterKeys(numBlocks, r4_in1, r4_in2, candInner[j], expected_out_xor,
                            thresh, MAXPAIRS, &numK3, candK3)) {
      continue;
    }
  }
  printf("%d round 4 candidates\n", numK3);

  // Round 3
  // Compute inputs to round 3 (z1, z2) based on previous key estimate
  // expected xor is y1+y2+80800000

  for (int k3 = 0; k3 < numK3; k3++) {

    printf("\nK3 candidate: ");
    printf("  "); candK3[k3].Print(); printf("\n");

    for (int i = 0; i < numBlocks; i++) {
      expected_out_xor[i].XorandPut(r4_in1[i], r4_in2[i]);
      expected_out_xor[i].XorToMe(diff1);
      FourBytes out1, out2;
      FourBytes arg1, arg2;

      arg1.XorandPut(r4_in1[i], candK3[k3]);
      F(arg1, out1);

      arg2.XorandPut(r4_in2[i], candK3[k3]);
      F(arg2, out2);

      r3_in1[i].XorandPut(cipherBlocks1[i].left_, out1);
      r3_in2[i].XorandPut(cipherBlocks2[i].left_, out2);
    }

    numInner = 0;
    if (!EstimateInnerKeys(numBlocks, r3_in1, r3_in2, expected_out_xor, thresh, MAXPAIRS,
                            &numInner, candInner)) {
      printf("Inner round 3 estimate failed, K3 %d\n", k3);
    }

    printf("%d inner round 3 keys\n", numInner);
    candK3[k3].Print(); printf("\n");
    for (int k = 0; k < numInner; k++) {
      printf("  ");
      candInner[k].Print();
      printf("\n");
    }

    for (int k = 0; k < numInner; k++) {
      if (!EstimateOuterKeys(numBlocks, r3_in1, r3_in2, candInner[k], expected_out_xor,
                             thresh, MAXPAIRS, &numK2, candK2)) {
        continue;
      }
    }
    printf("%d round 3 candidates\n", numK2);
    if (numK2 > 0)
      printf("K2 candidates:\n");
    for (int k = 0; k < numK2; k++) {
      printf("  "); candK2[k].Print(); printf("\n");
    }
  }

  // Now do the same thing with the decryption cipher
  // to get K0 and K1

  // Round 1
  for (int i = 0; i < numBlocks; i++) {
    FourBytes L0Diff;

    L0Diff.XorandPut(plainBlocks3[i].left_, plainBlocks4[i].left_);
    expected_out_xor[i].XorandPut(L0Diff, diff2);

    r1_in1[i].XorandPut(plainBlocks3[i].left_, plainBlocks3[i].right_);
    r1_in2[i].XorandPut(plainBlocks4[i].left_, plainBlocks4[i].right_);
  }

  numInner = 0;
  if (!EstimateInnerKeys(numBlocks, r1_in1, r1_in2, expected_out_xor, thresh, MAXPAIRS,
                           &numInner, candInner)) {
    printf("Inner round 1 estimate failed\n");
    return false;
  }

  printf("%d inner round 1 keys\n", numInner);
  for (int j = 0; j < numInner; j++) {
    printf("  ");
    candInner[j].Print();
    printf("\n");
  }

  for (int j = 0; j < numInner; j++) {
    if (!EstimateOuterKeys(numBlocks, r1_in1, r1_in2, candInner[j], expected_out_xor,
                            thresh, MAXPAIRS, &numK0, candK0)) {
      continue;
    }
  }
  printf("%d round 1 candidates\n", numK0);

  // Round 2
  // Compute inputs to round 2 (z1, z2) based on previous key estimate
  // expected xor is y1+y2+80800000

  for (int k0 = 0; k0 < numK0; k0++) {

    printf("\nK0 candidate: ");
    printf("  "); candK0[k0].Print(); printf("\n");

    for (int i = 0; i < numBlocks; i++) {
      expected_out_xor[i].XorandPut(r1_in1[i], r1_in2[i]);
      expected_out_xor[i].XorToMe(diff1);
      FourBytes out1, out2;
      FourBytes arg1, arg2;

      arg1.XorandPut(r1_in1[i], candK0[k0]);
      F(arg1, out1);

      arg2.XorandPut(r1_in2[i], candK0[k0]);
      F(arg2, out2);

      r2_in1[i].XorandPut(plainBlocks3[i].left_, out1);
      r2_in2[i].XorandPut(plainBlocks4[i].left_, out2);
    }

    numInner = 0;
    if (!EstimateInnerKeys(numBlocks, r2_in1, r2_in2, expected_out_xor, thresh, MAXPAIRS,
                            &numInner, candInner)) {
      printf("Inner round 2 estimate failed, K0 %d\n", k0);
    }

    printf("%d inner round 2 keys\n", numInner);
    for (int k = 0; k < numInner; k++) {
      printf("  ");
      candInner[k].Print();
      printf("\n");
    }

    for (int k = 0; k < numInner; k++) {
      if (!EstimateOuterKeys(numBlocks, r2_in1, r2_in2, candInner[k], expected_out_xor,
                             thresh, MAXPAIRS, &numK1, candK1)) {
        continue;
      }
    }
    printf("%d round 2 candidates\n", numK1);
    if (numK1 > 0)
      printf("K1 candidates:\n");
    for (int k = 0; k < numK1; k++) {
      printf("  "); candK1[k].Print(); printf("\n");
    }
  }

  // Calculate intermediate constants and verify
  // L0+F(K0+R0)=t1, R0+F(K1+R1)=t2
  // L4+F(R4+K3)=r1, R4+F(R2+K2)=r2
  // t1+r2=k6+k7+k4, t2+r1=k4+k5+k6

  FourBytes L0, R0, L4, R4;
  FourBytes t1, t2, r1, r2;
  FourBytes K4K5K6, K4K6K7;
  FourBytes out1, out2;
  FourBytes arg1, arg2;

  L0.CopyToMe(plainBlocks1[0].left_);
  R0.XorandPut(L0, plainBlocks1[0].right_);
  L4.CopyToMe(cipherBlocks1[0].left_);
  R4.XorandPut(L4, cipherBlocks1[0].right_);

  int numTests = 0;
  for (int k3 = 0; k3 < numK3; k3++) {

    arg1.XorandPut(R4, candK3[k3]);
    F(arg1, out1);
    r1.XorandPut(L4, out1);
    subKeys[3].CopyToMe(candK3[k3]);

    for (int k2 = 0; k2 < numK2; k2++) {

      arg2.XorandPut(r1, candK2[k2]);
      F(arg2, out2);
      r2.XorandPut(R4, out2);
      subKeys[2].CopyToMe(candK2[k2]);

      for (int k0 = 0; k0 < numK0; k0++) {

        arg1.XorandPut(R0, candK0[k0]);
        F(arg1, out1);
        t1.XorandPut(L0, out1);
        subKeys[0].CopyToMe(candK0[k0]);

        for (int k1 = 1; k1 < numK1; k1++) {

          arg2.XorandPut(t1, candK1[k1]);
          F(arg2, out2);
          t2.XorandPut(R0, out2);
          subKeys[1].CopyToMe(candK1[k1]);

          K4K5K6.XorandPut(t2, r1); 
          K4K6K7.XorandPut(t1, r2);

          subKeys[4].CopyToMe(K4K5K6);
          subKeys[5].CopyToMe(K4K6K7);

          printf("Subkeys: \n");
          for (int j = 0; j < 6; j++) {
            printf("  subKey[%d]: ", j); subKeys[j].Print(); printf("\n");
          }
          printf("\n");
          numTests++;
          if (TestRefactored(numBlocks, plainBlocks1, cipherBlocks1, subKeys)) {
            fRet= true;
            nSucceeded++;
          }
        }
      }
    }
  }
  printf("\nnumTests: %d, succeeded: %d\n", numTests, nSucceeded);
  return fRet;
}

bool DifferentialAttack(int numBlocks, FealState* plainBlocks1, FealState* cipherBlocks1, 
                        FealState* plainBlocks2, FealState* cipherBlocks2,
                        FealState* plainBlocks3, FealState* cipherBlocks3,
                        FealState* plainBlocks4, FealState* cipherBlocks4) {
  if (numBlocks > MAXPAIRS)
    numBlocks = MAXPAIRS;
  FourBytes subKeys[6];

  if (RunDifferentialAttack(numBlocks, plainBlocks1, plainBlocks2,
                            cipherBlocks1, cipherBlocks2, 
                            plainBlocks3, plainBlocks4,
                            cipherBlocks3, cipherBlocks4, subKeys)) {
    printf("\nDifferential attack succeeded\n");
    printf("  K0    : "); subKeys[0].Print();printf("\n");
    printf("  K1    : "); subKeys[1].Print();printf("\n");
    printf("  K2    : "); subKeys[2].Print();printf("\n");
    printf("  K3    : "); subKeys[3].Print();printf("\n");
    printf("  k4k5k6: "); subKeys[4].Print();printf("\n");
    printf("  k4k6k7: "); subKeys[5].Print();printf("\n");
    return true;
  } else {
    printf("\nDifferential attack failed\n");
    return false;
  }
}

// ---------------------------------------------------------------------------------------

byte HexDigit(char a) {
  if (a >= '0' && a <= '9')
    return a - '0';
  if (a >= 'a' && a <= 'f')
    return a - 'a' + 10;
  return 0;
}

bool Get64(const char* str, byte* out) {
  if ((strlen(str) & 1) != 0)
    return false;
  byte c, d;
  while (*str != 0) {
    c= HexDigit(*(str++));
    d= HexDigit(*(str++));
    *(out++) = (c<<4)|d;
  }
  return true;
}

void PrintBytes(int l, byte* b) {
  for (int j = 0; j < l; j++)
    printf("%02x", b[j]);
}

ReadFile::ReadFile() {
  fd_ = -1;
  bytes_in_file_ = 0;
  bytes_left_ = 0;
}

ReadFile::~ReadFile() {}

bool ReadFile::Init(const char* filename) {
  if (filename == nullptr) {
    return false;
  }

  struct stat file_info;
  int k = stat(filename, &file_info);
  if (k < 0) {
    return false;
  }
  bytes_in_file_ = file_info.st_size;
  bytes_left_ = file_info.st_size;

  fd_ = open(filename, O_RDONLY);
  if (fd_ < 0)
    return false;
  return true;
}

int ReadFile::BytesInFile() { return bytes_in_file_; }

int ReadFile::BytesLeftInFile() { return bytes_left_; }

void ReadFile::Close() { close(fd_); }

int ReadFile::Read(int size, byte* buf) {
  int n = read(fd_, buf, size);
  if (n <= 0)
    return n;
  bytes_left_ -= n;
  return n;
}

WriteFile::WriteFile() {
  fd_ = -1;
  bytes_written_ = 0;
}

WriteFile::~WriteFile() {}

bool WriteFile::Init(const char* filename) {
  fd_ = creat(filename, S_IRWXU | S_IRWXG);
  if (fd_ <= 0)
    return false;
  return true;
}

int WriteFile::BytesWrittenToFile() { return bytes_written_; }

void WriteFile::Close() { close(fd_); }

bool WriteFile::Write(int size, byte* buf) {
  int n = write(fd_, buf, size);
  if (n < size)
    return false;
  bytes_written_ += n;
  return true;
}

bool ReadaFile(const char* filename, int* size, byte** out) {
  ReadFile file_desc;

  *out = nullptr;
  if (!file_desc.Init(filename))
    return false;
  int num_bytes = file_desc.BytesInFile();
  byte* buf = new byte[num_bytes];
  memset(buf, 0, num_bytes);
  if (file_desc.Read(num_bytes, buf) != num_bytes) {
    delete []buf;
    return false;
  }
  *size = num_bytes;
  *out = buf;
  file_desc.Close();
  return true;
}

bool WriteaFile(const char* filename, int size, byte* in) {
  WriteFile file_desc;

  if (!file_desc.Init(filename))
    return false;
  if (!file_desc.Write(size, in))
    return false;
  file_desc.Close();
  return true;
}

// ---------------------------------------------------------------------------------------

bool EncryptBuffer(Feal4& oF, int size, byte* plain, byte* cipher) {
    int i = size;

    while (i >= 8) {
      oF.EncryptBlock(plain, cipher);
      plain += 8;
      cipher += 8;
      i -= 8;
    }
  return true;
}

bool DecryptBuffer(Feal4& oF, int size, byte* cipher, byte* plain) {
    int i = size;

    while (i >= 8) {
      oF.DecryptBlock(cipher, plain);
      plain += 8;
      cipher += 8;
      i -= 8;
    }
  return true;
}

bool FillRandomText(byte* seed, int size, byte* buf) {
  int s = size;
  Feal4 oF;
  byte mask[8] = {
   0x44, 0x88, 0x99, 0xbb,
   0x66, 0xff, 0xdd, 0x22
  };

  oF.InitKey(seed);

  while (s >= 8) {
    oF.EncryptBlock(mask, buf);
    for (int i = 0; i < 8; i++) {
      mask[i] ^= buf[i];
    }
    s -= 8;
    buf += 8;
  }
  return true;
}

int main(int an, char** av) {

  if (an < 2) {
      printf("Use:\n");
      printf("  new_feal4.exe -test key(16 hexbytes) in(16 hexbytes)\n");
      printf("  new_feal4.exe -encrypt key(16 hexbytes) in(16 hexbytes)\n");
      printf("  new_feal4.exe -decrypt key(16 hexbytes) in(16 hexbytes)\n");
      printf("  new_feal4.exe -encryptfile key(16 hexbytes) filename\n");
      printf("  new_feal4.exe -decryptfile key(16 hexbytes) filename\n");
      printf("  new_feal4.exe -preparecorrespondingtext key(16 hexbytes) seed(16 hexbytes) size file1 file2\n");
      printf("  new_feal4.exe -preparedifferentialpairs key(16 hex) seed(16 hex) differential(hex) size file1 file2 file3 file4\n");
      printf("  new_feal4.exe -linearattackdemo\n");
      printf("  new_feal4.exe -differentialattackdemo\n");
      printf("  new_feal4.exe -differentialattack file1 file2 file3 file4\n");
      printf("  new_feal4.exe -linearattack file1 file2\n");
      return 1;
  }

  if(strcmp(av[1], "-test")==0) {
    byte key[8];
    byte in[8];
    byte out[8];
    byte check[8];
    Feal4 o;
    const char* keys[4] = {
      "0000000000000000",
      "0000000000000000",
      "000000aaaaa00000",
      "000000aaaaa00000"
    };
    const char* inputs[4] = {
      "0000000000000001",
      "0f0f0f0f0f0f0f0f",
      "0000000000000001",
      "0f0f0f0f0f0f0f0f"
    };

    printf("Feal-4 test\n");
    for (int k = 0; k < 4; k++) {
      if (!Get64(keys[k], key)) {
        printf("Get64 failed\n");
      }
      if (!Get64(inputs[k], in)) {
        printf("Get64 failed\n");
      }
      printf("key  : "); PrintBytes(8, key); printf("\n");
      o.InitKey(key, true);
      for (int j = 0; j < 8; j++) {
        printf("\tK[%d]: ", j); o.rk_[j].Print(); printf("\n");
      }

      printf("in   : "); PrintBytes(8, in); printf("\n");
      o.EncryptBlock(in, out);
      printf("out  : "); PrintBytes(8, out); printf("\n");
      o.DecryptBlock(out, check);
      printf("check: "); PrintBytes(8, check); printf("\n");
      if (memcmp(in, check, 8)!=0) {
        printf("input and decrypted DONT match\n");
      } else {
        printf("input and decrypted match\n");
      }
    }

    return 0;
  } else if(strcmp(av[1], "-encrypt")==0) {
    byte plain[8], cipher[8];
    byte key[8];

    if (an < 4) {
      printf("Wrong number af arguments\n");
      return 1;
    }
    if (!Get64(av[2], key)) {
      printf("Bad key\n");
      return 1;
    }
    if (!Get64(av[3], plain)) {
      printf("Bad plaintext\n");
      return 1;
    }

    Feal4 oF;

    oF.InitKey(key, true);
    oF.EncryptBlock(plain, cipher, true);

    printf("plain : "); PrintBytes(8, plain); printf("\n");
    printf("cipher: "); PrintBytes(8, cipher); printf("\n");
  } else if(strcmp(av[1], "-decrypt")==0) {
    byte plain[8], cipher[8];
    byte key[8];

    if (an < 5) {
      printf("Wrong number af arguments\n");
      return 1;
    }
    if (!Get64(av[2], key)) {
      printf("Bad key\n");
      return 1;
    }
    if (!Get64(av[3], cipher)) {
      printf("Bad ciphertext\n");
      return 1;
    }

    Feal4 oF;

    oF.InitKey(key, true);
    oF.DecryptBlock(cipher, plain);

    printf("cipher: "); PrintBytes(8, cipher); printf("\n");
    printf("plain : "); PrintBytes(8, plain); printf("\n");
  } else if(strcmp(av[1], "-encryptfile")==0) {
    byte key[8];

    if (an < 4) {
      printf("Wrong number af arguments\n");
      return 1;
    }
    if (!Get64(av[2], key)) {
      printf("Bad key\n");
      return 1;
    }

    Feal4 oF;

    int inSize = 0;
    byte* input = nullptr;
    if (!ReadaFile(av[3], &inSize, &input)) {
      printf("Can't read %s\n", av[3]);
      return 1;
    }
    inSize &= ~0x3;
    byte* output = (byte*)malloc(inSize);

    EncryptBuffer(oF, inSize, input, output);
    WriteaFile(av[4], inSize, output);

    free(input);
    free(output);
  } else if(strcmp(av[1], "-decryptfile")==0) {
    byte key[8];

    if (an < 4) {
      printf("Wrong number af arguments\n");
      return 1;
    }
    if (!Get64(av[2], key)) {
      printf("Bad key\n");
      return 1;
    }

    Feal4 oF;
    oF.InitKey(key, true);

    int inSize = 0;
    byte* input = nullptr;
    if (!ReadaFile(av[3], &inSize, &input)) {
      printf("Can't read %s\n", av[3]);
      return 1;
    }
    inSize &= ~0x3;
    byte* output = (byte*)malloc(inSize);

    DecryptBuffer(oF, inSize, input, output);
    WriteaFile(av[4], inSize, output);

    free(input);
    free(output);
  } else if(strcmp(av[1], "-preparecorrespondingtext")==0) {
      // -preparecorrespondingtext key(8 hexbytes) seed(8 hexbytes) size file1 file2
    byte key[8];
    byte seed[8];
    int size;

    if (an < 7) {
      printf("Wrong number af arguments\n");
      return 1;
    }
    if (!Get64(av[2], key)) {
      printf("Bad key\n");
      return 1;
    }
    if (!Get64(av[3], seed)) {
      printf("Bad seed\n");
      return 1;
    }
    size = atoi(av[4]);
    size &= ~0x3;

    Feal4 oF;
    oF.InitKey(key, true);

    printf("preparecorrespondingtext, key: ");
    PrintBytes(8, key);
    printf(", seed: ");
    PrintBytes(8, seed);
    printf(", size: %d\n", size);

    byte* plain = (byte*) malloc(size);
    byte* cipher = (byte*) malloc(size);

    // Make up plaintext based on seed then encrypt it
    FillRandomText(seed, size, plain);
    EncryptBuffer(oF, size, plain, cipher);

    printf("Files out: %s %s\n\n", av[5], av[6]);

    printf("Plain  : "); PrintBytes(size, plain); printf("\n");
    printf("Cipher : "); PrintBytes(size, cipher); printf("\n");
    printf("\n");

    WriteaFile(av[5], size, plain);
    WriteaFile(av[6], size, cipher);

    free(plain);
    free(cipher);
  } else if(strcmp(av[1], "-preparedifferentialpairs")==0) {
      // -preparedifferentialpairs key(8 hex) seed(8 hex) differential(hex) size file1 file2 file3 file4
  } else if(strcmp(av[1], "-differentialattack")==0) {
      // -differentialattack file1 file2 file3 file4
  } else if(strcmp(av[1], "-linearattack")==0) {

    if (an < 4) {
      printf("Wrong number af arguments\n");
      return 1;
    }

    // -linearattack file1 file2
    int plainSize = 0;
    int cipherSize = 0;
    byte* plain = nullptr;
    byte* cipher = nullptr;

    if (!ReadaFile(av[2], &plainSize, &plain)) {
      printf("Cant read plaintext file %s\n", av[3]);
      return 1;
    }

    if (!ReadaFile(av[3], &cipherSize, &cipher)) {
      printf("Cant read ciphertext file %s\n", av[4]);
      return 1;
    }

    FealState plainBlocks[MAXPAIRS];
    FealState cipherBlocks[MAXPAIRS];
    int iNum = plainSize/8;

    byte* p = plain;
    byte* q = cipher;
    for (int i = 0; i < iNum; i++) {
      plainBlocks[i].FillFromBytes(p);
      cipherBlocks[i].FillFromBytes(q);
      p += 8;
      q += 8;
    }

    printf("%d pairs examined\n", iNum);
    for (int k = 0; k < iNum; k++) {
      printf("Plain: "); plainBlocks[k].Print();
      printf(", Cipher: "); cipherBlocks[k].Print(); printf("\n");
    }
    printf("\n");
    LinearAttack(iNum, plainBlocks, cipherBlocks);

    free(plain);
    free(cipher);
  } else if(strcmp(av[1], "-differentialattackdemo")==0) {

    // For now, use synthetic data.
    byte plain[8], cipher[8];
    byte newplain[8];
    byte plain2[8];
    byte cipher2[8];
    byte key[8];

    FealState plainBlocks1[16];
    FealState cipherBlocks1[16];
    FealState plainBlocks2[16];
    FealState cipherBlocks2[16];
    FealState plainBlocks3[16];
    FealState cipherBlocks3[16];
    FealState plainBlocks4[16];
    FealState cipherBlocks4[16];

    FourBytes candidates[MAXPAIRS];
    FourBytes oKeyStart, oKeyEnd;

    int iNum = 16;

    if (!Get64("0123456789abcdef", key)) {
      printf("Can't get key\n");
    }

    printf("Feal-4 differential attack");
    printf("Key: "); PrintBytes(8, key); printf("\n\n");

    Feal4 o;
    o.InitKey(key, true);

    for (int k = 0; k < iNum; k++) {
      if (k < 64) {
        plain[0] = (byte)k;
        plain[1] = (byte)(k*k);
        plain[2] = (byte)k;
        plain[3] = (byte)k;
        plain[4] = (byte)(0x88 - k);
        plain[5] = (byte)k;
        plain[6] = (byte)(4+k);
        plain[7] = (byte)k;
      } else {
        plain[0] = (byte)(k*k);
        plain[1] = (byte)k;
        plain[2] = (byte)k;
        plain[3] = (byte)(0x88 - k);
        plain[4] = (byte)3;
        plain[5] = (byte)7;
        plain[7] = (byte)0;
        plain[6] = (byte)0;
      }

#ifdef T0
      o.EncryptBlock(plain, newplain, true);
      o.EncryptBlock(newplain, cipher, true);
#else
      o.EncryptBlock(plain, newplain);
      o.EncryptBlock(newplain, cipher);
#endif
      plainBlocks1[k].FillFromBytes(newplain);
      cipherBlocks1[k].FillFromBytes(cipher);

      newplain[0] ^= 0x80;
      newplain[1] ^= 0x80;
      newplain[4] ^= 0x80;
      newplain[5] ^= 0x80;

#ifdef T0
      o.EncryptBlock(newplain, cipher, true);
#else
      o.EncryptBlock(newplain, cipher);
#endif
      plainBlocks2[k].FillFromBytes(newplain);
      cipherBlocks2[k].FillFromBytes(cipher);

      memcpy(cipher2, cipher, 8);

      cipher2[0] ^= 0x80;
      cipher2[1] ^= 0x80;
      cipher2[4] ^= 0x80;
      cipher2[5] ^= 0x80;

      cipherBlocks3[k].FillFromBytes(cipher);
      cipherBlocks4[k].FillFromBytes(cipher);
      plainBlocks3[k].FillFromBytes(newplain);
      o.DecryptBlock(cipher2, plain2);
      plainBlocks4[k].FillFromBytes(plain2);
    }

    printf("Input differential: ");
    FealState d;
    d.XorandPut(plainBlocks1[0], plainBlocks2[0]);
    d.Print(); printf("\n\n");

    for (int k = 0; k < iNum; k++) {
      printf("P1: "); plainBlocks1[k].Print();
      printf(", C1: "); cipherBlocks1[k].Print();
      printf(", P2: "); plainBlocks2[k].Print();
      printf(", C2: "); cipherBlocks2[k].Print();
      printf("\n");
    }
    printf("\n");

    for (int k = 0; k < iNum; k++) {
      printf("C3: "); cipherBlocks3[k].Print();
      printf(", P3: "); plainBlocks3[k].Print();
      printf("C4: "); cipherBlocks4[k].Print();
      printf(", P4: "); plainBlocks4[k].Print();
      printf("\n");
    }
    printf("\n");

    DifferentialAttack(iNum, plainBlocks1, cipherBlocks1, plainBlocks2, cipherBlocks2,
                       plainBlocks3, cipherBlocks3, plainBlocks4, cipherBlocks4);
  } else if(strcmp(av[1], "-linearattackdemo")==0) {

    // For now, use synthetic data.
    byte plain[8], cipher[8];
    byte newplain[8];
    byte key[8];

    FealState plainBlocks[MAXPAIRS];
    FealState cipherBlocks[MAXPAIRS];

    FourBytes candidates[MAXPAIRS];
    FourBytes oKeyStart, oKeyEnd;

    int iNum = 128;

    if (!Get64("0123456789abcdef", key)) {
      printf("Can't get key\n");
    }

    printf("Feal-4 linear attack");
    printf("Key: "); PrintBytes(8, key); printf("\n\n");

    Feal4 o;
    o.InitKey(key, true);

    for (int k = 0; k < iNum; k++) {
      if (k < 64) {
        plain[0] = (byte)k;
        plain[1] = (byte)(k*k);
        plain[2] = (byte)k;
        plain[3] = (byte)k;
        plain[4] = (byte)(0x88 - k);
        plain[5] = (byte)k;
        plain[6] = (byte)(4+k);
        plain[7] = (byte)k;
      } else {
        plain[0] = (byte)(k*k);
        plain[1] = (byte)k;
        plain[2] = (byte)k;
        plain[3] = (byte)(0x88 - k);
        plain[4] = (byte)3;
        plain[5] = (byte)7;
        plain[7] = (byte)0;
        plain[6] = (byte)0;
      }

#ifdef T0
      o.EncryptBlock(plain, newplain, true);
      o.EncryptBlock(newplain, cipher, true);
#else
      o.EncryptBlock(plain, newplain);
      o.EncryptBlock(newplain, cipher);
#endif
      plainBlocks[k].FillFromBytes(newplain);
      cipherBlocks[k].FillFromBytes(cipher);
    }
#ifdef T0
    for (int k = 0; k < iNum; k++) {
      printf("Plain: "); plainBlocks[k].Print();
      printf(", Cipher: "); cipherBlocks[k].Print(); printf("\n");
    }
#endif
    LinearAttack(iNum, plainBlocks, cipherBlocks);
  } else {
    printf("Unknown option\n");
    return 1;
  }
  return 0;
}

// ---------------------------------------------------------------------------------------

