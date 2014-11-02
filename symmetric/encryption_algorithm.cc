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
// File: encryption_algorithm.cc

#include <string>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include "cryptotypes.h"
#include "util.h"
#include "conversions.h"
#include "symmetric_cipher.h"
#include "encryption_algorithm.h"
#include "aescbchmac256sympad.h"
#include "keys.h"

using namespace std;

EncryptionAlgorithm::EncryptionAlgorithm() {
  alg_name_= NULL;
  message_id_= NULL;
  input_bytes_processed_= 0;
  output_bytes_produced_= 0;
  initialized_= false;
}

EncryptionAlgorithm::~EncryptionAlgorithm() {
  if(alg_name_!= NULL) {
    delete alg_name_;
    alg_name_= NULL;
  }
  if(message_id_!= NULL) {
    delete message_id_;
    message_id_= NULL;
  }
  initialized_= false;
}

bool EncryptionAlgorithm::ReadEncryptionAlgorithm(string& filename) {
  crypto_encryption_algorithm_message message;

  fstream input(filename, ios::in | ios::binary);
  if (!message.ParseFromIstream(&input)) {
    LOG(ERROR) << "ReadEncryptionAlgorithm cant read message file\n";
    return false;
  }
  if(!DeserializeEncryptionAlgorithmFromMessage(message)) {
    LOG(ERROR) << "ReadEncryptionAlgorithm cant DeserializeEncryptionAlgorithmFromBuffer\n";
    return false;
  }
  return true;
}

bool EncryptionAlgorithm::SaveEncryptionAlgorithm(string& filename) {
  crypto_encryption_algorithm_message message;

  if(!SerializeEncryptionAlgorithmToMessage(message)) {
    LOG(ERROR) << "SaveEncryptionAlgorithm cant DeserializeEncryptionAlgorithmFromMessage\n";
    return false;
  }
  fstream output(filename, ios::out | ios::trunc | ios::binary);
  if (!message.SerializeToOstream(&output)) {
    LOG(ERROR) << "SymmetricEncryptionAlgorithm::SaveEncryptionAlgorithm can't SerializeEncryptionAlgorithmToMessage\n";
    return false;
  }
  output.close();
  return true;
}

bool EncryptionAlgorithm::SerializeEncryptionAlgorithmToMessage(
                crypto_encryption_algorithm_message& message) {
  crypto_symmetric_key_message* key_message= new crypto_symmetric_key_message();

  message.set_allocated_key_msg(key_message);
  SymmetricCipher* sc= NULL;
  if(((AesCbcHmac256Sympad*)this)->use_aesni_) {
    sc= (SymmetricCipher*)&((((AesCbcHmac256Sympad*)this)->aesni_obj_));
  } else {
    sc= (SymmetricCipher*)&((((AesCbcHmac256Sympad*)this)->aes_obj_));
  }
  if(!sc->SerializeSymmetricCipherToMessage(*key_message)) {
    LOG(ERROR) << "SymmetricEncryptionAlgorithm::SerializeEncryptionAlgorithmToMessage can't SerializeKeyToMessage\n";
    return false;
  }
  if(alg_name_==NULL) {
    LOG(ERROR) << "no algorithm name\n";
    return false;
  }
  if(!initialized_) {
    LOG(ERROR) << "encryption_algorithm not initialized\n";
    return false;
  }
  if(strcmp(alg_name_->c_str(), "aes128-cbc-hmacsha256-sympad")==0) {
    message.set_encryption_algorithm_name("aes128-cbc-hmacsha256-sympad");
    message.set_encryption_algorithm_mode("cbc");
  } else if(strcmp(alg_name_->c_str(), "aes128-ctr-hmacsha256-sympad")==0) {
    message.set_encryption_algorithm_name("aes128-ctr-hmacsha256-sympad");
    message.set_encryption_algorithm_mode("ctr");
  } else {
    LOG(ERROR) << alg_name_->c_str() << " - unimplemented encryption_algorithm name\n";
    return false;
  }
  message.set_encryption_algorithm_pad("sympad");
  if(message_id_!=NULL) {
    message.set_message_id(message_id_->c_str());
  }
  string* s= ByteToBase64LeftToRight(HmacSha256::BLOCKBYTESIZE,
              ((AesCbcHmac256Sympad*)this)->hmac_.key_);
  if(s==NULL) {
    LOG(ERROR) << "EncryptionAlgorithm::SerializeEncryptionAlgorithmToMessage can't  ByteToBase64LeftToRight\n";
    return false;
  }
  message.set_encryption_algorithm_hmac_key(s->c_str());
  delete s;
  string* t= ByteToBase64LeftToRight(Aes::BLOCKBYTESIZE,
                ((AesCbcHmac256Sympad*)this)->iv_);
  if(t==NULL) {
    LOG(ERROR) << "EncryptionAlgorithm::SerializeEncryptionAlgorithmToMessage can't  ByteToBase64LeftToRight\n";
    return false;
  }
  message.set_encryption_algorithm_iv(t->c_str());
  delete t;
  initialized_= true;
  return true;
}

bool EncryptionAlgorithm::DeserializeEncryptionAlgorithmFromMessage(
                            crypto_encryption_algorithm_message& message) {
  int n;

  if(!message.has_encryption_algorithm_name()) {
    LOG(ERROR) << "EncryptionAlgorithm::DeserializeEncryptionAlgorithmFromMessage no alg name\n";
    return false;
  }
  if(strcmp(message.encryption_algorithm_name().c_str(),
            "aes128-cbc-hmacsha256-sympad")==0) {
    alg_name_= new string("aes128-cbc-hmacsha256-sympad");
  } else if(strcmp(message.encryption_algorithm_name().c_str(),
            "aes128-ctr-hmacsha256-sympad")==0) {
    alg_name_= new string("aes128-ctr-hmacsha256-sympad");
  } else {
    LOG(ERROR) << "EncryptionAlgorithm::DeserializeEncryptionAlgorithmFromMessage incorrect alg name\n";
    return false;
  }
  ((AesCbcHmac256Sympad*)this)->use_aesni_= true;
  if(message.has_message_id()) {
    message_id_= new string(message.message_id().c_str());
  } else {
    message_id_= NULL;
  }
  if(!message.has_encryption_algorithm_hmac_key()) {
    LOG(ERROR) << "EncryptionAlgorithm::DeserializeEncryptionAlgorithmFromMessage no mac key\n";
    return false;
  }
  n= Base64ToByteLeftToRight((char*)message.encryption_algorithm_hmac_key().c_str(), 
                     HmacSha256::BLOCKBYTESIZE, ((AesCbcHmac256Sympad*)this)->hmac_.key_);

  if(!message.has_encryption_algorithm_iv()) {
    LOG(ERROR) << "EncryptionAlgorithm::DeserializeEncryptionAlgorithmFromMessage no iv\n";
    return false;
  }
  n= Base64ToByteLeftToRight((char*)message.encryption_algorithm_iv().c_str(), 
                     Aes::BLOCKBYTESIZE, ((AesCbcHmac256Sympad*)this)->iv_);
  if(n<0) {
    LOG(ERROR) << "EncryptionAlgorithm::DeserializeEncryptionAlgorithmFromMessage iv base64 failed\n";
    return false;
  }
  crypto_symmetric_key_message* key_message= message.mutable_key_msg();
  SymmetricCipher* sc= (SymmetricCipher*)&((((AesCbcHmac256Sympad*)this)->aesni_obj_));
  if(!sc->DeserializeSymmetricCipherFromMessage(*key_message)) {
    LOG(ERROR) << "EncryptionAlgorithm::DeserializeEncryptionAlgorithmFromMessage cant deserialize cipher form message\n";
    return false;
  }
  initialized_= true;
  return true;
}

