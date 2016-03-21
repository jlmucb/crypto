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
// File: cert.h

#include <stdio.h>
#include <string.h>
#include <time.h>

#include <string>
#include <iostream>
#include <type_traits>
#include <fstream>

#include "cryptotypes.h"
#include "conversions.h"
#include "keys.h"
#include "keys.pb.h"
#include "cert.pb.h"


#ifndef _CRYPTO_AES_H__
#define _CRYPTO_AES_H__

using std::string;

class name {
public:
  string type_;
  string value_;
}

class property {
public:
  string property_name_;
  string property_value_;
}

class proto_cert {
private:
public:
  proto_cert();
  virtual ~proto_cert();

  string version_;
  name subject_name_[]; 
  string signature_algorithm_;
  string purpose_;
  property properties_[];
  string not_before_;
  string not_after_;
  string nonce_;
  string canonical_;
  string revocation_address_;
  string date_signed_;
  name issuer_name_[]; 
  string signature_;

  bool FillProto(certificate_message* cert);
  bool FillSignerParameter();
  bool FillSignature();

  string& getVersion();
  string& getPurpose();
  string& getNotBefore();
  string& getNotAfter();
  string& getSignature();
  string& getNonce();
  string& getCanonical();
  string& getDateSigned();

  void putVersion();
  void putPurpose();
  void putNotBefore();
  void putNotAfter();
  void putSignature();
  void putNonce();
  void putCanonical();
  void putDateSigned();

}

void PrintProto(certificate_message& cert);

#endif
