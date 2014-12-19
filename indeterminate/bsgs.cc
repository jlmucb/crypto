//
//  File: bsgs.cc
//  Description: Baby step, giant step point counting in ECC
//
//  Copyright (c) 2014, John Manferdelli.  All rights reserved.
//
// Use, duplication and disclosure of this file and derived works of
// this file are subject to and licensed under the Apache License dated
// January, 2004, (the "License").  This License is contained in the
// top level directory originally provided with the CloudProxy Project.
// Your right to use or distribute this file, or derived works thereof,
// is subject to your being bound by those terms and your use indicates
// consent to those terms.
//
// If you distribute this file (or portions derived therefrom), you must
// include License in or with the file and, in the event you do not include
// the entire License in the file, the file must contain a reference
// to the location of the License.

#include "bignum.h"
#include "stdio.h"

// ----------------------------------------------------------------------------

 * 1. Q= (q+1)P
 * 2. Choose m>q^(1/4)
 * 3. Compute Q+jP, j= 0, 1, ..., m and store
 * 4. Compute Q+k(2mP), k= -m, -m+1, ... 0, 1, ..., m
 *      until Q+k(2mP)= Q+jP or Q-jP
 * 5. (q+1+2mk+j)P= O or (q+1+2mk-j)P= O.  Let M be coefficient of P
 * 6. Factor M into p[0]^e[0] ... p[l]^e[l]
 * 7. Repeat until failure if (M/p[i]]P=0, replace M with /p[i] 
 * 8. Conclude |P|= M
 * If we're looking for the order of the group, do the above with
 *    random points until LCM divides one N with q+1-2(q^1/2)<=N<=q+1+2(q^1/2).
 *    Conclude N is the order
 */

bool eccbsgspointorder(EccCurve& curve, CurvePoint& P, BigNum& order)
{
#ifdef JLMDEBUG
  printf("eccbsgspointorder\n");
#endif
}

// ----------------------------------------------------------------------------
