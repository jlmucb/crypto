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
// File: keys.cc

#include <string>
#include <iostream> 
#include <type_traits>
#include <fstream>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "cryptotypes.h"
#include "conversions.h"
#include "util.h"
#include "ecc.h"
#include "keys.h"
#include "keys.pb.h"

using namespace std;

const int num_cryptoalgs= 9;
string cryptoalgs[]= {
  "undefined",
  "aes128",
  "aes256",
  "aesni128",
  "aesni256",
  "rsa1024",
  "rsa2048",
  "twofish128",
  "twofish256",
};

const int num_cryptoschemes= 5;
string cryptoschemes[]= {
  "undefined",
  "aes128-ebc-standard-symmetric-pad"
  "aes128-cbc-standard-symmetric-pad"
  "aes256-ebc-standard-symmetric-pad"
  "aes256-cbc-standard-symmetric-pad"
};

const int num_paddingalgs= 3;
string paddingalgs[]= {
  "undefined",
  "none-symmetric-pad"
  "standard-symmetric-pad"
};

const int num_modes= 3;
string modes[]= {
  "undefined",
  "ecb",
  "cbc"
};

const int num_hashalgs= 5;
string hashalgs[]= {
  "undefined",
  "sha1",
  "sha2-256",
  "sha2-512",
  "sha3-1024",
};

void printcryptoalgs() {
  cout << "crypto algs\n";
  for (int i = 0; i < num_cryptoalgs; i++) {
    cout << "\t" << cryptoalgs[i] << "\n";
  }
}

void printcryptoschemes() {
  cout << "crypto schemes\n";
  for (int i = 0; i < num_cryptoschemes; i++) {
    cout << "\t" << cryptoschemes[i] << "\n";
  }
}

void printpaddingalgs() {
  cout << "padding algs\n";
  for (int i = 0; i < num_paddingalgs; i++) {
    cout << "\t" << paddingalgs[i] << "\n";
  }
}

void printmodes() {
  cout << "encryption modes\n";
  for (int i = 0; i < num_modes; i++) {
    cout << "\t" << modes[i] << "\n";
  }
}

void printhashalgs() {
  cout << "hash algs\n";
  for (int i = 0; i < num_hashalgs; i++) {
    cout << "\t" << hashalgs[i] << "\n";
  }
}

CryptoKey::CryptoKey() {
  key_valid_= false;
  key_name_= NULL;
  key_type_= NULL;
  key_usage_= NULL;
  key_owner_= NULL;
  not_before_= NULL;
  not_after_= NULL;
}

CryptoKey::~CryptoKey() {
  if(key_name_!=NULL) {
    delete key_name_;
    key_name_= NULL;
  }
  if(key_type_!=NULL) {
    delete key_type_;
    key_type_= NULL;
  }
  if(key_usage_!=NULL) {
    delete key_usage_;
    key_usage_= NULL;
  }
  if(key_owner_!=NULL) {
    delete key_owner_;
    key_owner_= NULL;
  }
  if(not_before_!=NULL) {
    delete not_before_;
    not_before_= NULL;
  }
  if(not_after_!=NULL) {
    delete not_after_;
    not_after_= NULL;
  }
}

bool CryptoKey::SerializeKeyToMessage(crypto_key_message& message) {

  // key_message:
  if(!key_valid_) {
    LOG(ERROR) << "CryptoKey::SerializeKeyToMessage: key invalid\n";
    return false;
  }
  if(key_type_==NULL) {
    LOG(ERROR) << "CryptoKey::SerializeKeyToMessage: no key type\n";
    return false;
  }
  message.set_key_type(key_type_->c_str());
  if(key_name_!=NULL) {
    message.set_key_name(key_name_->c_str());
  }
  message.set_key_usage(key_usage_->c_str());
  if(key_usage_!=NULL) {
    message.set_key_usage(key_usage_->c_str());
  }
  if(key_owner_!=NULL) {
    message.set_key_owner(key_owner_->c_str());
  }
  if(not_before_!=NULL) {
    string* s= EncodeTime(*not_before_);
    if(s==NULL)
      return false;
    message.set_not_before(*s);
  }
  if(not_after_!=NULL) {
    string* s= EncodeTime(*not_after_);
    if(s==NULL)
      return false;
    message.set_not_after(*s);
  }
  if(strcmp(key_type_->c_str(),"symmetric-cipher")==0) {
    crypto_symmetric_key_message* symmetric_key_message=
      message.mutable_symkey();
    ((SymmetricKey*)this)->SerializeKeyToMessage(*symmetric_key_message);
  }
  else if(strcmp(key_type_->c_str(),"rsa")==0 || strcmp(key_type_->c_str(),"rsa-128")==0 ||
     strcmp(key_type_->c_str(),"rsa-256")==0 || strcmp(key_type_->c_str(),"rsa-512")==0 ||
     strcmp(key_type_->c_str(),"rsa-1024")==0 || strcmp(key_type_->c_str(),"rsa-2048")==0 ||
     strcmp(key_type_->c_str(),"rsa3072")==0) {
    crypto_rsa_key_message* rsa_key_message= message.mutable_rsakey();
    ((RsaKey*)this)->SerializeKeyToMessage(*rsa_key_message);
  }
  else if(strcmp(key_type_->c_str(),"ecc")==0 || strcmp(key_type_->c_str(),"ecc-256")==0) {
    crypto_ecc_key_message* ecc_key_message= message.mutable_ecckey();
    ((EccKey*)this)->SerializeKeyToMessage(*ecc_key_message);
  }
  message.set_crypto_context("jlm-crypto-key-message");
  return true;
}

bool CryptoKey::DeserializeKeyFromMessage(crypto_key_message& message) {
  if(!message.has_key_type()) {
    LOG(ERROR) << "CryptoKey::DeserializeKeyFromMessage: no key type\n";
    return false;
  }
  if(message.has_key_name()) {
    const char* p= message.key_name().c_str();
    key_name_= new string(p);
  }

  if(message.has_key_type()) {
    key_type_= new string(message.key_type().c_str());
  } else {
    return false;
  }
  if(message.has_key_owner()) {
    key_owner_= new string(message.key_owner().c_str());
  }
  if(message.has_key_usage()) {
    key_usage_= new string(message.key_usage().c_str());
  }
  if(message.has_not_before()) {
    not_before_= new TimePoint();
    if(!DecodeTime(message.not_before(), not_before_)) {
        LOG(ERROR) << "CryptoKey::DeserializeKeyFromMessage: cant decode DecodeTime, not_before_\n";
      return false;
    }
  }
  if(message.has_not_before()) {
    not_after_= new TimePoint();
    if(!DecodeTime(message.not_after(), not_after_)) {
      LOG(ERROR) << "CryptoKey::DeserializeKeyFromMessage: cant decode DecodeTime, not_after_\n";
      return false;
    }
  }
  if(message.has_symkey()) {
    crypto_symmetric_key_message* sc= (crypto_symmetric_key_message*)&message.symkey();
    if(!((SymmetricKey*)this)->DeserializeKeyFromMessage(*sc)) {
      return false;
    }
  }
  if(message.has_rsakey()) {
    crypto_rsa_key_message* sc= (crypto_rsa_key_message*)&message.rsakey();
    if(!((RsaKey*)this)->DeserializeKeyFromMessage(*sc)) {
      return false;
    }
  }
  if(message.has_ecckey()) {
    crypto_ecc_key_message* sc= (crypto_ecc_key_message*)&message.ecckey();
    if(!((EccKey*)this)->DeserializeKeyFromMessage(*sc)) {
      return false;
    }
  }
  if(!message.has_crypto_context() ||
      strcmp(message.crypto_context().c_str(),"jlm-crypto-key-message")!=0) {
    printf("crypto-context is wrong\n");
  }
  key_valid_= true;
  return true;
}

bool CryptoKey::ReadKey(string& filename) {
  crypto_key_message message;

  fstream input(filename, ios::in | ios::binary);
  if (!message.ParseFromIstream(&input)) {
    LOG(ERROR) << "ReadKey cant read message file\n";
    return false;
  }
  if(!DeserializeKeyFromMessage(message)) {
    LOG(ERROR) << "ReadKey cant DeserializeKeyFromBuffer\n";
    return false;
  }
  return true;
}

bool CryptoKey::SaveKey(string& filename) {
  crypto_key_message message;

  if(!SerializeKeyToMessage(message)) {
    return false;
  }
  fstream output(filename, ios::out | ios::trunc | ios::binary);
  if (!message.SerializeToOstream(&output)) {
    LOG(ERROR) << "SymmetricKey::SaveKey can't SerializeToOstream\n";
    return false;
  }
  output.close();
  return true;
}

void CryptoKey::PrintKey() {
  if(key_valid_)
    printf("Key valid\n");
  else
    printf("Key invalid\n");

  if(key_name_==NULL)
    printf("\tno key name\n");
  else
    printf("\tkey name: %s\n", key_name_->c_str());;

  if(key_type_==NULL)
    printf("\tno key type\n");
  else
    printf("\tkey type: %s\n", key_type_->c_str());
  if(key_usage_==NULL)
    printf("\tno key usage\n");
  else
    printf("\tkey usage: %s\n", key_usage_->c_str());

  if(not_before_==NULL) {
    printf("\tno not before\n");
  } else {
    printf("\tnot before: ");
    not_before_->PrintTime();
    printf("\n");
  }
  if(not_after_==NULL) {
    printf("\tno not after\n");
  } else {
    printf("\tnot after: ");
    not_after_->PrintTime();
    printf("\n");
  }
  if(key_type_==NULL)
    return;
  if(strcmp(key_type_->c_str(), "symmetric-cipher")==0) {
    ((SymmetricKey*)this)->PrintKey();
  } else if(strcmp(key_type_->c_str(), "rsa-1024")==0 || 
            strcmp(key_type_->c_str(), "rsa-2048")==0 ||
            strcmp(key_type_->c_str(), "rsa-3072")==0 ||
            strcmp(key_type_->c_str(), "rsa-512")==0 ||
            strcmp(key_type_->c_str(), "rsa-256")==0 ||
            strcmp(key_type_->c_str(), "rsa-128")==0) {
    ((RsaKey*)this)->PrintKey();
  } else if(strcmp(key_type_->c_str(), "ecc-256")==0) {
    ((EccKey*)this)->PrintKey();
  } else {
    return;
  }
}

SymmetricKey::SymmetricKey() {
  symmetric_key_bytes_= NULL;
  symmetric_algorithm_type_= NULL;
}

SymmetricKey::~SymmetricKey() {
  if(symmetric_key_bytes_!=NULL) {
    memset(symmetric_key_bytes_, 0, symmetric_key_bit_size_/NBITSINBYTE);
    delete symmetric_key_bytes_;
    symmetric_key_bytes_= NULL;
  }
  if(symmetric_algorithm_type_!=NULL) {
    delete symmetric_algorithm_type_;
    symmetric_algorithm_type_= NULL;
  }
}

bool SymmetricKey::GenerateAesKey(const char* name, const char* usage, 
                    const char* owner, int num_bits, double secondstolive) {
  byte  my_key[32];

  if(num_bits!=128 && num_bits!=256) {
    LOG(ERROR) << "SymmetricKey::GenerateAesKey: unsupported key size "<< num_bits<<"\n";
    return false;
  }
  if(!GetCryptoRand(num_bits, my_key)) {
    LOG(ERROR) << "SymmetricKey::GenerateAesKey: can't get key bits\n";
    return false;
  }
  return MakeAesKey(name, usage, owner, num_bits, secondstolive, my_key);
}

bool SymmetricKey::MakeAesKey(const char* name, const char* usage, 
            const char* owner, int num_bits, double secondstolive , byte* key) {
  key_type_= new string("symmetric-cipher");
  key_name_= new string(name);
  key_usage_= new string(usage);
  key_owner_= new string(owner);
  not_before_= new TimePoint();
  not_after_= new TimePoint();
  not_before_->TimePointNow();
  not_after_->TimePointLaterBySeconds(*not_before_, secondstolive);
  if(num_bits!=128) {
    LOG(ERROR) << "SymmetricKey::MakeAesKey: only 128 bit keys supported\n";
    return false;
  }
  symmetric_key_bit_size_= num_bits;
  symmetric_key_bytes_= new byte[32];
  symmetric_algorithm_type_= new string("aes-128");
  memcpy(symmetric_key_bytes_, key, num_bits/NBITSINBYTE);
  key_valid_= true;
  return true;
}

bool SymmetricKey::GenerateTwofishKey(const char* name, const char* usage, 
                    const char* owner, int num_bits, double secondstolive) {
  byte  my_key[32];

  if(num_bits!=128 && num_bits!=192 && num_bits!=256) {
    LOG(ERROR) << "SymmetricKey::GenerateTwofishKey: unsupported key size\n";
    return false;
  }
  if(!GetCryptoRand(num_bits, my_key)) {
    LOG(ERROR) << "SymmetricKey::GenerateTwofishKey: can't get key bits\n";
    return false;
  }
  return MakeTwofishKey(name, usage, owner, num_bits, secondstolive, my_key);
}

bool SymmetricKey::MakeTwofishKey(const char* name, const char* usage, 
            const char* owner, int num_bits, double secondstolive , byte* key) {
  key_type_= new string("symmetric-cipher");
  key_name_= new string(name);
  key_usage_= new string(usage);
  key_owner_= new string(owner);
  not_before_= new TimePoint();
  not_after_= new TimePoint();
  not_before_->TimePointNow();
  not_after_->TimePointLaterBySeconds(*not_before_, secondstolive);
  if(num_bits!=128 && num_bits!=192 && num_bits!=256) {
    LOG(ERROR) << "SymmetricKey::MakeTwofishKey: unsupported key size\n";
    return false;
  }
  symmetric_key_bit_size_= num_bits;
  symmetric_key_bytes_= new byte[32];
  char  tmp_name[32];
  sprintf(tmp_name,"twofish-%d", num_bits);
  symmetric_algorithm_type_= new string(tmp_name);
  memcpy(symmetric_key_bytes_, key, num_bits/NBITSINBYTE);
  key_valid_= true;
  return true;
}

bool SymmetricKey::SerializeKeyToMessage(
            crypto_symmetric_key_message& message) {
  if(symmetric_algorithm_type_!=NULL) {
    message.set_key_type(symmetric_algorithm_type_->c_str());
  }
  message.set_key_bit_size(symmetric_key_bit_size_);
  if(symmetric_key_bytes_==NULL) {
    return false;
  }
  string* s= ByteToBase64LeftToRight(
                  symmetric_key_bit_size_/NBITSINBYTE,
                  symmetric_key_bytes_);
  if(s==NULL) {
    return false;
  }
  message.set_value(*s);
  return true;
}

bool SymmetricKey::DeserializeKeyFromMessage(
            crypto_symmetric_key_message& message) {
  symmetric_algorithm_type_= 
        new string(message.key_type().c_str());
  symmetric_key_bit_size_= message.key_bit_size();
  if(!message.has_value()) {
    LOG(ERROR) << "SymmetricKey::DeserializeKeyFromMessage no key value\n";
    return false;
  }
  const char* base64_key= message.value().c_str();
  symmetric_key_bytes_= new byte [2*symmetric_key_bit_size_/NBITSINBYTE];
  int k= Base64ToByteLeftToRight((char*)base64_key,
          2*symmetric_key_bit_size_/NBITSINBYTE,
          symmetric_key_bytes_);
  if(k<0) {
    return false;
  }
  return true;
}

void SymmetricKey::PrintKey() {

  if(symmetric_algorithm_type_==NULL) {
    printf("\tno symmetric algorithm\n");
  } else {
    printf("\tcrypto alg: %s\n", symmetric_algorithm_type_->c_str());
  }

  if(symmetric_key_bytes_==NULL) {
    printf("\tno key bytes\n");
  } else {
    printf("\t%d key bits: ", symmetric_key_bit_size_);
    PrintBytes(symmetric_key_bit_size_/NBITSINBYTE, symmetric_key_bytes_);
    printf("\n");
  }
}

KeyStore::KeyStore() {
  filename_= NULL;
  num_keys_= -1;
}

KeyStore::~KeyStore() {
  if(filename_!=NULL) {
    delete filename_;
    filename_= NULL;
  }
}

bool KeyStore::FindKey(const char* keyname, string** the_key_type, 
                       CryptoKey** p_key) {
  const char*  entry_name;

  if(num_keys_<0)
    return false;

  CryptoKey* found_key= NULL;
  for (int i= 0; i<num_keys_; i++) {
    const crypto_key_message entry= store_.key_entry(i);
    if(entry.has_key_name()) {
      entry_name= entry.key_name().c_str();
      if(strcmp(entry_name, keyname)==0) {
        if(strcmp(entry.key_type().c_str(), "symmetric-cipher")==0) {
          *the_key_type= new string(entry.key_type().c_str());
          found_key= (CryptoKey*)new SymmetricKey();
          if(!found_key->DeserializeKeyFromMessage(
                  *(crypto_key_message*)&entry)) {
            LOG(ERROR) << "cant deserialize key in FindKey\n";
            return false;
          }
          *p_key= found_key;
          return true;
        } else if(strcmp(entry.key_type().c_str(),"rsa")==0 || 
                  strcmp(entry.key_type().c_str(),"rsa-128")==0 ||
                  strcmp(entry.key_type().c_str(),"rsa-256")==0 || 
                  strcmp(entry.key_type().c_str(),"rsa-512")==0 ||
                  strcmp(entry.key_type().c_str(),"rsa-1024")==0 || 
                  strcmp(entry.key_type().c_str(),"rsa-2048")==0 ||
                  strcmp(entry.key_type().c_str(),"rsa3072")==0) {
          *the_key_type= new string(entry.key_type().c_str());
          found_key= (CryptoKey*)new RsaKey();
          if(!found_key->DeserializeKeyFromMessage(
                  *(crypto_key_message*)&entry)) {
            LOG(ERROR) << "cant deserialize key in FindKey\n";
            return false;
          }
          *p_key= found_key;
          return true;
        } else if(strcmp(entry.key_type().c_str(),"ecc")==0 || 
                  strcmp(entry.key_type().c_str(),"ecc-256")==0) {
          *the_key_type= new string(entry.key_type().c_str());
          found_key= (CryptoKey*)new EccKey();
          if(!found_key->DeserializeKeyFromMessage(
                  *(crypto_key_message*)&entry)) {
            LOG(ERROR) << "cant deserialize key in FindKey\n";
            return false;
          }
          *p_key= found_key;
      } else {
        LOG(ERROR) << "Unsupported key type in FindKey\n";
        return false;
      } 
     }
    }
  }
  return false;
}

bool KeyStore::AddKey(CryptoKey* key) {
  crypto_key_message* message= store_.add_key_entry();
  if(!key->SerializeKeyToMessage(*message)) {
    return false;
  }
  num_keys_++;
  return true;
}

bool KeyStore::DeleteKey(const char* keyname) {
  return true;
}

int  KeyStore::NumKeys() {
  return num_keys_;
}

bool KeyStore::ReadStore(const char* filename) {
    filename_= new string(filename);
    fstream input(filename, ios::in | ios::binary);
    if(!input) {
      cout << filename << ": File not found.  Creating a new file.\n";
    } else if (!store_.ParseFromIstream(&input)) {
      cerr << "Failed to parse address book.\n";
      return false;
    }
  num_keys_= store_.key_entry_size();
  return true; 
}

bool KeyStore::SaveStore(const char* filename) {
  // Write the new address book back to disk.
  fstream output(filename, ios::out | ios::trunc | ios::binary);
  if (!store_.SerializeToOstream(&output)) {
    cerr << "Failed to write address book.\n";
    return false;
  }
  return true; 
}

Signature::Signature() {
  encryption_alg_= NULL;
  size_serialized_= 0;
  serialized_statement_= NULL;
  size_signature_= 0;
  signature_= NULL;
  signer_name_= NULL;
}

Signature::~Signature() {
  if(encryption_alg_!=NULL) {
    delete encryption_alg_;
    encryption_alg_= NULL;
  }
  size_serialized_= 0;
  if(serialized_statement_!=NULL) {
    delete serialized_statement_;
    serialized_statement_= NULL;
  }
  size_signature_= 0;
  if(signature_!=NULL) {
    delete signature_;
    signature_= NULL;
  }
  if(signer_name_!=NULL) {
    delete signer_name_;
    signer_name_= NULL;
  }
}

bool Signature::Serialize(crypto_signature& sig) {
  sig.set_encryption_algorithm_name(encryption_alg_);
  if(size_serialized_>0 && serialized_statement_!=NULL) {
    string* s= ByteToBase64LeftToRight(size_serialized_,
                                     serialized_statement_);
    if(s==NULL) 
      return false;
    sig.set_serialized_statement(s->c_str());
  }
  if(size_signature_>0 && signature_!=NULL) {
    string* s= ByteToBase64LeftToRight(size_signature_,
                                     signature_);
    if(s==NULL) 
      return false;
    sig.set_signature(s->c_str());
    sig.set_serialized_statement("");
  }
  sig.set_signer_name(signer_name_);
  return true;
}

bool Signature::Deserialize(crypto_signature& sig) {
  int   n;

  encryption_alg_= strdup(sig.encryption_algorithm_name().c_str());
  serialized_statement_= new byte[512];
  n= Base64ToByteLeftToRight((char*)sig.serialized_statement().c_str(),
                             512, serialized_statement_);
  size_serialized_= n;

  signature_= new byte[512];
  n= Base64ToByteLeftToRight((char*)sig.signature().c_str(),
                             512, signature_);
  size_signature_= n;
  signer_name_= strdup(sig.signer_name().c_str());
  return true;
}

void Signature::PrintSignature() {
  if(encryption_alg_!=NULL) {
    printf("Encryption algorithm: %s\n", encryption_alg_);
  } else {
    printf("No Encryption algorithm\n");
  }
  if(size_serialized_>0 && serialized_statement_!=NULL) {
    printf("Serialized statement: ");
    PrintBytes(size_serialized_, serialized_statement_); printf("\n");
  } else {
    printf("No serialized statement\n");
  }
  if(size_signature_>0 && signature_!=NULL) {
    printf("Signature: ");
    PrintBytes(size_signature_, signature_); printf("\n");
  } else {
    printf("No signature\n");
  }
  if(signer_name_!=NULL) {
    printf("Signer: %s\n", signer_name_);
  } else {
    printf("No signer\n");
  }
}

