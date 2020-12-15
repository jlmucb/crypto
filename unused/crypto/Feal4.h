//
//  Module Name: feal4.h
//
//  Copyright 2010, John L. Manferdellil
//


// ------------------------------------------------------------------------


#ifndef __FEAL4_H
#define __FEAL4_H


#ifndef byte
typedef unsigned char byte;
#endif


class FourBytes {
public:
    byte            rg[4];
    void            CopyToMe(FourBytes& in);
    void            XorToMe(FourBytes& in);
    void            XorandPut(FourBytes& in1, FourBytes& in2);
    bool            Equal(FourBytes& o1);
    bool            Bump();
    bool            MidBump();
    void            Zero();
    void            AntiZero();
};


class FealState {
public:
    FourBytes       Left;
    FourBytes       Right;
    void            CopyToMe(FealState& in);
    void            XorToMe(FealState& in);
    void            XorandPut(FealState& in1, FealState& in2);
    void            Swap();
};


class Feal4 {
public:
    byte            G0(byte a, byte b);
    byte            G1(byte a, byte b);
    byte            InvG0(byte c, byte a);
    byte            InvG1(byte c, byte a);
    FealState       Key;
    FourBytes       roundKeys[8];
    FealState       In;
    FealState       Rounds[5];
    FealState       Out;

    bool            SetIn(FealState& in);
    bool            SetOut(FealState& out);
    bool            GetRound(int iRound, FealState& round);
    bool            GetIn(FealState& in);
    bool            GetOut(FealState& out);
    bool            GetKey(FealState& key);
    bool            GetRoundKey(int r, FourBytes& rK);
    bool            doRound(int i, FourBytes& rK);
    bool            TestRound(FourBytes& out, FourBytes& in, FourBytes& rK);
    bool            Encrypt();
    bool            Decrypt();
    bool            CleanKeys();
    bool            KeyInit(FealState& gKey);
    bool            F(FourBytes& out, FourBytes& in, FourBytes& rKey);
    bool            FK(FourBytes& out, FourBytes& in1, FourBytes& in2);
};


class Feal4Diff {
public:
    FealState       In;
    FealState       Rounds[5];
    FealState       Out;
    FourBytes       XPrime;
    FourBytes       YPrime;
    FourBytes       ZPrime;
    FourBytes       TPrime;
    FourBytes       RPrime;
    FourBytes       SPrime;

    bool            SetIn(FealState& in);
    bool            SetOut(FealState& out);
    bool            GetRound(int iRound, FealState& round);
    bool            SetRound(int iRound, FealState& round);
    bool            GetIn(FealState& in);
    bool            GetOut(FealState& out);
    bool            CalcDiffs(Feal4& o1, Feal4& o2);
    bool            CalcDiffs2(Feal4& o1, Feal4& o2);
    bool            GetXPrime(FourBytes& xP);
    bool            GetYPrime(FourBytes& yP);
    bool            GetZPrime(FourBytes& zP);
    bool            GetTPrime(FourBytes& tP);
    bool            GetSPrime(FourBytes& sP);
    bool            GetRPrime(FourBytes& rP);
};


#endif


// ------------------------------------------------------------------------

