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
// File: rsa.cc


#include "cryptotypes.h"
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include "bignum.h"
#include "conversions.h"
#include "intel64_arith.h"
#include "keys.pb.h"
#include "keys.h"


RsaKey::RsaKey() {
  bit_size_modulus_= 0;
  m_= NULL;
  e_= NULL;
  d_= NULL;
  p_= NULL;
  q_= NULL;
  dp_= NULL;
  dq_= NULL;
  m_prime_= NULL;
  p_prime_= NULL;
  q_prime_= NULL;
}

RsaKey::~RsaKey() {
  bit_size_modulus_= 0;
  if(m_!=NULL) {
    m_->ZeroNum();
    delete m_;
    m_= NULL;
  }
  if(e_!=NULL) {
    e_->ZeroNum();
    delete e_;
    e_= NULL;
  }
  if(d_!=NULL) {
    d_->ZeroNum();
    delete d_;
    d_= NULL;
  }
  if(p_!=NULL) {
    p_->ZeroNum();
    delete p_;
    p_= NULL;
  }
  if(q_!=NULL) {
    q_->ZeroNum();
    delete q_;
    q_= NULL;
  }
  if(dp_!=NULL) {
    dp_->ZeroNum();
    delete dp_;
    dp_= NULL;
  }
  if(dq_!=NULL) {
    dq_->ZeroNum();
    delete dq_;
    dq_= NULL;
  }
  if(q_prime_!=NULL) {
    q_prime_->ZeroNum();
    delete q_prime_;
    q_prime_= NULL;
  }
  if(m_prime_!=NULL) {
    m_prime_->ZeroNum();
    delete m_prime_;
    m_prime_= NULL;
  }
  if(p_prime_!=NULL) {
    p_prime_->ZeroNum();
    delete p_prime_;
    p_prime_= NULL;
  }
}

bool  RsaKey::ComputeFastDecryptParameters() {
  if(m_==NULL) {
    LOG(ERROR)<<"RsaKey::ComputeFastDecryptParameters: empty modulus\n";
    return false;
  }
  BigNum  t(2*m_->capacity_+1);
  BigNum  y(2*m_->capacity_+1);
  BigNum  g(2*m_->capacity_+1);
  BigNum  p_minus_1(2*p_->capacity_+1);
  BigNum  q_minus_1(2*q_->capacity_+1);
  
  if(!BigSub(*p_, Big_One, p_minus_1)) {
    LOG(ERROR)<<"RsaKey::ComputeFastDecryptParameters: bad sub 1\n";
    return false;
  }
  if(!BigSub(*q_, Big_One, q_minus_1)) {
    LOG(ERROR)<<"RsaKey::ComputeFastDecryptParameters: bad sub 2\n";
    return false;
  }
  if(!BigMult(p_minus_1, q_minus_1, t)) {
    LOG(ERROR)<<"RsaKey::ComputeFastDecryptParameters: bad mult\n";
    return false;
  }
  if(!BigExtendedGCD(t, *e_, y, *d_, g)) {
    LOG(ERROR)<<"RsaKey::ComputeFastDecryptParameters: GCD 1\n";
    return false;
  }
  if(!BigModNormalize(*d_,t)) {
    LOG(ERROR)<<"RsaKey::ComputeFastDecryptParameters: normalized decryption exponent\n";
    return false;
  }
  t.ZeroNum();
  y.ZeroNum();
  if(!BigExtendedGCD(p_minus_1, *e_, y, *dp_, g)) {
    LOG(ERROR)<<"RsaKey::ComputeFastDecryptParameters: GCD 2\n";
    return false;
  }
  if(!BigModNormalize(*dp_,p_minus_1)) {
    LOG(ERROR)<<"RsaKey::ComputeFastDecryptParameters: normalized decryption exponent\n";
    return false;
  }
  t.ZeroNum();
  y.ZeroNum();
  if(!BigExtendedGCD(q_minus_1, *e_, y, *dq_, g)) {
    LOG(ERROR)<<"RsaKey::ComputeFastDecryptParameters: GCD 3\n";
    return false;
  }
  if(!BigModNormalize(*dq_,q_minus_1)) {
    LOG(ERROR)<<"RsaKey::ComputeFastDecryptParameters: normalized decryption exponent\n";
    return false;
  }
  r_= BigHighBit(*m_);
  if(!BigMontParams(*m_, r_, *m_prime_)) {
    LOG(ERROR)<<"RsaKey::ComputeFastDecryptParameters: cant compute BigMontParams\n";
    return false;
  }
  return true;
}

bool RsaKey::SerializeKeyToMessage(crypto_rsa_key_message& msg) {

  msg.set_key_bit_size(bit_size_modulus_);

  char  buf[256];
  sprintf(buf, "rsa-%d", bit_size_modulus_);
  string  key_type(buf);

  msg.set_key_type(key_type.c_str());

  if(m_!=NULL) {
    string* s= ByteToBase64RightToLeft(
                  m_->size_*sizeof(uint64_t), (byte*)m_->value_);
    msg.set_modulus(s->c_str());
    delete s;
  }
  if(e_!=NULL) {
    string* s= ByteToBase64RightToLeft(
                  e_->size_*sizeof(uint64_t), (byte*)e_->value_);
    msg.set_public_exponent(s->c_str());
    delete s;
  }
  if(d_!=NULL) {
    string* s= ByteToBase64RightToLeft(
                  d_->size_*sizeof(uint64_t), (byte*)d_->value_);
    msg.set_private_exponent(s->c_str());
    delete s;
  }
  if(p_!=NULL) {
    string* s= ByteToBase64RightToLeft(
                  p_->size_*sizeof(uint64_t), (byte*)p_->value_);
    msg.set_p(s->c_str());
    delete s;
  }
  if(q_!=NULL) {
    string* s= ByteToBase64RightToLeft(
                  q_->size_*sizeof(uint64_t), (byte*)q_->value_);
    msg.set_q(s->c_str());
    delete s;
  }
  if(dp_!=NULL) {
    string* s= ByteToBase64RightToLeft(
                  dp_->size_*sizeof(uint64_t), (byte*)dp_->value_);
    msg.set_dp(s->c_str());
    delete s;
  }
  if(dq_!=NULL) {
    string* s= ByteToBase64RightToLeft(
                  dq_->size_*sizeof(uint64_t), (byte*)dq_->value_);
    msg.set_dq(s->c_str());
    delete s;
  }
  if(m_prime_!=NULL) {
    string* s= ByteToBase64RightToLeft(
                  m_prime_->size_*sizeof(uint64_t), (byte*)m_prime_->value_);
    msg.set_m_prime(s->c_str());
    delete s;
  }
  return true;
}

bool RsaKey::DeserializeKeyFromMessage(crypto_rsa_key_message& msg) {
  int k;

  if(msg.has_key_bit_size())
        bit_size_modulus_= msg.key_bit_size();
  else
        bit_size_modulus_= 3072;
  int bignum_size= (bit_size_modulus_+NBITSINUINT64-1)/NBITSINUINT64;

  if(msg.has_modulus()) {
    if(m_==NULL) {
      m_= new BigNum(bignum_size);
    }
    k= Base64ToByteRightToLeft((char*)(msg.modulus().c_str()),
            bignum_size*sizeof(uint64_t),
            (byte*)m_->value_);
    if(k<0) {
      LOG(ERROR)<<"RsaKey::DeserializeKeyFromMessage: cant encode\n";
    }
    m_->Normalize();
  }
  if(msg.has_public_exponent()) {
    if(e_==NULL) {
      e_= new BigNum(bignum_size);
    }
    k= Base64ToByteRightToLeft((char*)(msg.public_exponent().c_str()),
            bignum_size*sizeof(uint64_t),
            (byte*)e_->value_);
    if(k<0) {
      LOG(ERROR)<<"RsaKey::DeserializeKeyFromMessage: cant encode\n";
    }
    e_->Normalize();
  }
  if(msg.has_private_exponent()) {
    if(d_==NULL) {
      d_= new BigNum(bignum_size);
    }
    k= Base64ToByteRightToLeft((char*)(msg.private_exponent().c_str()),
            bignum_size*sizeof(uint64_t),
            (byte*)d_->value_);
    if(k<0) {
      LOG(ERROR)<<"RsaKey::DeserializeKeyFromMessage: cant encode\n";
    }
    d_->Normalize();
  }
  if(msg.has_p()) {
    if(p_==NULL) {
      p_= new BigNum(bignum_size);
    }
    k= Base64ToByteRightToLeft((char*)(msg.p().c_str()),
            bignum_size*sizeof(uint64_t),
            (byte*)p_->value_);
    if(k<0) {
      LOG(ERROR)<<"RsaKey::DeserializeKeyFromMessage: cant encode\n";
    }
    p_->Normalize();
  }
  if(msg.has_q()) {
    if(q_==NULL) {
      q_= new BigNum(bignum_size);
    }
    k= Base64ToByteRightToLeft((char*)(msg.q().c_str()),
            bignum_size*sizeof(uint64_t),
            (byte*)q_->value_);
    if(k<0) {
      LOG(ERROR)<<"RsaKey::DeserializeKeyFromMessage: cant encode\n";
    }
    q_->Normalize();
  }
  if(msg.has_dp()) {
    if(dp_==NULL) {
      dp_= new BigNum(bignum_size);
    }
    k= Base64ToByteRightToLeft((char*)(msg.dp().c_str()),
            bignum_size*sizeof(uint64_t),
            (byte*)dp_->value_);
    if(k<0) {
      LOG(ERROR)<<"RsaKey::DeserializeKeyFromMessage: cant encode\n";
    }
    dp_->Normalize();
  }
  if(msg.has_dq()) {
    if(dq_==NULL) {
      dq_= new BigNum(bignum_size);
    }
    k= Base64ToByteRightToLeft((char*)(msg.dq().c_str()),
            bignum_size*sizeof(uint64_t),
            (byte*)dq_->value_);
    if(k<0) {
      LOG(ERROR)<<"RsaKey::DeserializeKeyFromMessage: cant encode\n";
    }
    dq_->Normalize();
  }
  if(msg.has_m_prime()) {
    if(m_prime_==NULL) {
      m_prime_= new BigNum(bignum_size);
    }
    k= Base64ToByteRightToLeft((char*)(msg.m_prime().c_str()),
            bignum_size*sizeof(uint64_t),
            (byte*)m_prime_->value_);
    if(k<0) {
      LOG(ERROR)<<"RsaKey::DeserializeKeyFromMessage: cant encode\n";
    }
    m_prime_->Normalize();
  }
  return true;
}


bool RsaKey::GenerateRsaKey(const char* name, const char* usage,
                         const char* owner, int num_bits,
                         double seconds_to_live) {
  BigNum m(1+2*num_bits/NBITSINUINT64);
  BigNum p(1+num_bits/NBITSINUINT64);
  BigNum q(1+num_bits/NBITSINUINT64);
  BigNum e(1,0x010001ULL);

  if(!BigGenPrime(p, num_bits/2)) {
    LOG(ERROR)<<"RsaKey::GenerateRsaKey: can't generate p\n";
    return false;
  }
  if(!BigGenPrime(q, num_bits/2)) {
    LOG(ERROR)<<"RsaKey::GenerateRsaKey: can't generate q\n";
    return false;
  }
  if(!BigMult(p,q,m)) {
    LOG(ERROR)<<"RsaKey::GenerateRsaKey: can't multiply p and q\n";
    return false;
  }
  return MakeRsaKey(name, usage, owner, num_bits, seconds_to_live,
                     m, e, p, q);
}

bool RsaKey::MakeRsaKey(const char* name, const char* usage,
                     const char* owner, int num_bits, double secondstolive,
                     BigNum& m, BigNum& e, BigNum& p, BigNum& q) {
  char  mod_len[256];

  sprintf(mod_len,"rsa-%d", num_bits);
  bit_size_modulus_= num_bits;
  key_valid_= true;
  key_type_= new string(mod_len);
  key_name_= new string(name);
  key_usage_= new string(usage);
  key_owner_= new string(owner);
  not_before_= new TimePoint();
  not_after_= new TimePoint();
  not_before_->TimePointNow();
  not_after_->TimePointLaterBySeconds(*not_before_, secondstolive);
  m_= new BigNum(m);
  e_= new BigNum(e);
  p_= new BigNum(p);
  q_= new BigNum(q);
  d_= new BigNum(1+2*num_bits/NBITSINUINT64);
  dp_= new BigNum(1+2*num_bits/(NBITSINUINT64));
  dq_= new BigNum(1+2*num_bits/(NBITSINUINT64));
  m_prime_= new BigNum(1+2*num_bits/(NBITSINUINT64));
  if(!ComputeFastDecryptParameters()) {
    LOG(ERROR) << "RsaKey::MakeRsaKey: cant compute ComputeFastDecryptParameters\n";
    return false;
  }
  return true;
}

void RsaKey::PrintKey() {
  printf("bit_size_modulus_: %d\n", bit_size_modulus_);
  if(m_!=NULL) {
    printf("m: "); PrintNumToConsole(*m_, 10ULL); printf("\n");
  } else {
    printf("RSAKey: m is empty\n");
  }
  if(e_!=NULL) {
    printf("e: "); PrintNumToConsole(*e_, 10ULL); printf("\n");
  }
  if(d_!=NULL) {
    printf("d: "); PrintNumToConsole(*d_, 10ULL); printf("\n");
  }
  if(p_!=NULL) {
    printf("p: "); PrintNumToConsole(*p_, 10ULL); printf("\n");
  }
  if(q_!=NULL) {
    printf("q: "); PrintNumToConsole(*q_, 10ULL); printf("\n");
  }
  if(dp_!=NULL) {
    printf("dp: "); PrintNumToConsole(*dp_, 10ULL); printf("\n");
  }
  if(dq_!=NULL) {
    printf("dq: "); PrintNumToConsole(*dq_, 10ULL); printf("\n");
  }
}

bool RsaKey::Encrypt(int size_in, byte* in, int* size_out, byte* out,
                      int speed) {
  int bytes_in_block= bit_size_modulus_/NBITSINBYTE;

  if(size_in>bytes_in_block)
    return false;

  int     new_byte_size= (size_in+bytes_in_block-1)/bytes_in_block;
  new_byte_size*= bytes_in_block;
  BigNum  int_in(1+4*new_byte_size/sizeof(uint64_t));
  BigNum  int_out(1+4*new_byte_size/sizeof(uint64_t));
  ReverseCpy(new_byte_size, in, (byte*)int_in.value_);
  int_in.Normalize();
  if(speed==0) {
    if(!BigModExp(int_in, *e_, *m_, int_out)) {
      LOG(ERROR)<< "BigModExp failed in RSAKey::Encrypt\n";
      return false;
    }
  } else if(speed==1) {
    if(!BigMontExp(int_in, *e_, r_, *m_, *m_prime_, int_out)) {
      LOG(ERROR)<< "BigMontExp failed in RSAKey::Encrypt\n";
      return false;
    }
  } else if (speed==2) {
      // implement CRT
      LOG(ERROR)<< "RsaKey::Decrypt, bad speed parameter " << speed << "\n";
  } else if (speed==3) {
      // implement CRT and MonMult
      LOG(ERROR)<< "RsaKey::Decrypt, bad speed parameter " << speed << "\n";
  } else {
      LOG(ERROR)<< "RsaKey::Encrypt, bad speed parameter " << speed << "\n";
      return false;
  }
  ReverseCpy(new_byte_size, (byte*)int_out.value_, out);
  *size_out= new_byte_size;
  return true;
}

bool RsaKey::Decrypt(int size_in, byte* in, int* size_out, byte* out,
                      int speed) {
  int bytes_in_block= bit_size_modulus_/NBITSINBYTE;

  if(size_in>bytes_in_block)
    return false;
  int     new_byte_size= (size_in+bytes_in_block-1)/bytes_in_block;
  new_byte_size*= bytes_in_block;

  BigNum  int_in(2*new_byte_size/sizeof(uint64_t));
  BigNum  int_out(2*new_byte_size/sizeof(uint64_t));
  ReverseCpy(new_byte_size, in, (byte*)int_in.value_);
  int_in.Normalize();
  if(speed==0) {
    if(!BigModExp(int_in, *d_, *m_, int_out)) {
      LOG(ERROR)<< "BigModExp failed in RSAKey::Decrypt\n";
      return false;
    }
  } else if(speed==1) {
    if(!BigMontExp(int_in, *d_, r_, *m_, *m_prime_, int_out)) {
      LOG(ERROR)<< "BigMontExp failed in RSAKey::Encrypt\n";
      return false;
    }
  } else if (speed==2) {
      // implement CRT
      LOG(ERROR)<< "RsaKey::Decrypt, bad speed parameter " << speed << "\n";
  } else if (speed==3) {
      // implement CRT and MonMult
      LOG(ERROR)<< "RsaKey::Decrypt, bad speed parameter " << speed << "\n";
  } else {
      LOG(ERROR)<< "RsaKey::Decrypt, bad speed parameter " << speed << "\n";
      return false;
  }
  ReverseCpy(new_byte_size, (byte*)int_out.value_, (byte*)out);
  *size_out= new_byte_size;
  return true;
}


