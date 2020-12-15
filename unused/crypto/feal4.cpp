#include <stdio.h>
#ifndef JLMUNIX
#include <io.h>
#endif
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>

#include "Feal4.h"

//  Feal4.cpp
//  (c), 2010, John L. Manferdelli

// ---------------------------------------------------------------------------------------


FourBytes g_oPattern1;
FourBytes g_oPattern2;
FourBytes g_oPattern3;


void FourBytes::Zero()
{
    rg[0]= 0;
    rg[1]= 0;
    rg[2]= 0;
    rg[3]= 0;
}


void FourBytes::AntiZero()
{
    rg[0]= 0xff;
    rg[1]= 0xff;
    rg[2]= 0xff;
    rg[3]= 0xff;
}


bool FourBytes::Bump()
{
    for(int i=0; i<4; i++) {
        if(rg[i]<0xff) {
            rg[i]++;
            return false;
        }
        rg[i]= 0;
    }
    return true;
}


bool FourBytes::MidBump()
{
    int i;

    for(i=1; i<3; i++) {
        if(rg[i]<0xff) {
            rg[i]++;
            return false;
        }
        rg[i]= 0;
    }
    return true;
}


bool FourBytes::Equal(FourBytes& o1)
{
    int i;

    for(i=0; i<4; i++) {
        if(rg[i]!=o1.rg[i])
            return false;
    }
    return true;
}


void FourBytes::CopyToMe(FourBytes& in)
{
    for(int j=0; j<4; j++) {
        rg[j]= in.rg[j];
    }
}


void FourBytes::XorToMe(FourBytes& in)
{
    for(int j= 0; j<4; j++) {
        rg[j]^= in.rg[j];
    }
}


void FourBytes::XorandPut(FourBytes& in1, FourBytes& in2)
{
    for(int j=0; j<4; j++) {
        rg[j]= in1.rg[j]^in2.rg[j];
    }
}


void FealState::Swap()
{
    FourBytes   t;

    t.CopyToMe(Left);
    Left.CopyToMe(Right);
    Right.CopyToMe(t);
}


void FealState::CopyToMe(FealState& in)
{
    Left.CopyToMe(in.Left);
    Right.CopyToMe(in.Right);
}


void FealState::XorToMe(FealState& in)
{
    Left.XorToMe(in.Left);
    Right.XorToMe(in.Right);
}


void FealState::XorandPut(FealState& in1, FealState& in2)
{
    Left.XorandPut(in1.Left, in2.Left);
    Right.XorandPut(in1.Right, in2.Right);
}


void fillFromWord(FourBytes& out, unsigned u)
{
    for(int j=0; j<4; j++)
        out.rg[j]= (u>>(8*(3-j)))&0xff;
}


void printFour(const char* sz, FourBytes& in)
{
    if(sz!=NULL)
        printf("%s",sz);
    for(int j=0;j<4;j++)
        printf("%02x ", in.rg[j]);
}


void printState(const char* sz, FealState& in)
{
    if(sz!=NULL)
        printf("%s",sz);
    printFour(NULL, in.Left);
    printf("  ");
    printFour(NULL, in.Right);
    printf("\n");
}


bool Feal4::doRound(int r, FourBytes& rK)
{
    F(Rounds[r].Right, Rounds[r-1].Right, rK);
    Rounds[r].Right.XorToMe(Rounds[r-1].Left);
    Rounds[r].Left.CopyToMe(Rounds[r-1].Right);
    return true;
}


bool Feal4::Encrypt()
{
    Rounds[0].Left.XorandPut(In.Left, roundKeys[6]);
    Rounds[0].Right.XorandPut(In.Right, Rounds[0].Left);
    Rounds[0].Right.XorToMe(roundKeys[7]);

    for(int i=1; i<5; i++)
        doRound(i, roundKeys[i+1]);

    // There was an extra switch
    Out.Left.CopyToMe(Rounds[4].Right);
    Out.Right.XorandPut(Rounds[4].Left, Rounds[4].Right);
    return true;
}


bool Feal4::Decrypt()
{
    Rounds[0].Left.CopyToMe(In.Left);
    Rounds[0].Right.XorandPut(In.Right, In.Left);

    for(int i= 1; i<5; i++)
        doRound(i, roundKeys[6-i]);

    Out.Left.XorandPut(Rounds[4].Right, roundKeys[6]);
    Out.Right.XorandPut(Rounds[4].Left, Rounds[4].Right);
    Out.Right.XorToMe(roundKeys[7]);
    return true;
}


bool Feal4::CleanKeys()
{
    for(int j=0; j<8; j++) 
        memset((void*)roundKeys, 0, 4);
    memset((void*)(&Key), 0, 8);
    for(int j=0; j<5; j++) 
        memset((void*)(&Rounds[j]), 0, 8);
    return true;
}


bool Feal4::KeyInit(FealState& gKey)
{
    int         i;
    FourBytes   t;

    for(i=0;i<4; i++) {
        roundKeys[0].rg[i]= 0;
    }

    roundKeys[1].CopyToMe(gKey.Left);
    roundKeys[2].CopyToMe(gKey.Right);

    for(i=3; i<8;i++) {
        t.XorandPut(roundKeys[i-1], roundKeys[i-3]);
        FK(roundKeys[i], roundKeys[i-2], t);
    }

    return true;
}


bool Feal4::F(FourBytes& out, FourBytes& in, FourBytes& rKey)
{
    byte x0= in.rg[0]^rKey.rg[0];
    byte x1= in.rg[1]^rKey.rg[1];
    byte x2= in.rg[2]^rKey.rg[2];
    byte x3= in.rg[3]^rKey.rg[3];

    out.rg[1]= G1(x0^x1,x2^x3);
    out.rg[0]= G0(x0, out.rg[1]);
    out.rg[2]= G0(out.rg[1], x2^x3);
    out.rg[3]= G1(out.rg[2], x3);

    return true;
}


bool Feal4::FK(FourBytes& out, FourBytes& in1, FourBytes& in2)
{
    byte d1= in1.rg[0]^in1.rg[1];
    byte d2= in1.rg[2]^in1.rg[3];
    
    out.rg[1]= G1(d1, in1.rg[2]^in2.rg[0]);
    out.rg[2]= G0(d2, out.rg[1]^in2.rg[1]);
    out.rg[0]= G0(in1.rg[0], out.rg[1]^in2.rg[2]);
    out.rg[3]= G1(in1.rg[3], out.rg[2]^in2.rg[3]);

    return true;
}


bool Feal4::SetIn(FealState& in)
{
    In.CopyToMe(in);
    return true;
}


bool Feal4::SetOut(FealState& out)
{
    Out.CopyToMe(out);
    return true;
}


bool Feal4::GetRound(int iRound, FealState& round)
{
    round.CopyToMe(Rounds[iRound]);
    return true;
}


bool Feal4::GetIn(FealState& in)
{
    in.CopyToMe(In);
    return true;
}


bool Feal4::GetOut(FealState& out)
{
    out.CopyToMe(Out);
    return true;
}


bool Feal4::GetKey(FealState& key)
{
    key.CopyToMe(Key);
    return true;
}


bool Feal4::GetRoundKey(int r, FourBytes& rK)
{
    rK.CopyToMe(roundKeys[r+1]);
    return true;
}


byte Feal4::G0(byte a, byte b)
{
    byte c= a+b;

    return (c<<2) | (c>>6);
}


byte Feal4::G1(byte a, byte b)
{
    byte c= a+b+1;

    return (c<<2) | (c>>6);
}


byte  Feal4::InvG0(byte c, byte a)
{
    byte rc= ((c>>2)&0x3f) | (c<<6);
    unsigned t;

    t= (256 + ((unsigned)rc) - ((unsigned) a))%256;
    return (byte) t;
}


byte  Feal4::InvG1(byte c, byte a)
{
    byte rc= ((c>>2)&0x3f) | (c<<6);
    unsigned t;

    t= (256 + ((unsigned)rc) - ((unsigned) 1)- ((unsigned) a))%256;
    return (byte) t;
}


bool Feal4::TestRound(FourBytes& out, FourBytes& in, FourBytes& rK)
{
    F(out, in, rK);
    return true;
}


bool Feal4Diff::SetIn(FealState& in)
{
    In.CopyToMe(in);
    return true;
}


bool Feal4Diff::SetOut(FealState& out)
{
    Out.CopyToMe(out);
    return true;
}


bool Feal4Diff::GetRound(int iRound, FealState& round)
{
    round.CopyToMe(Rounds[iRound]);
    return true;
}


bool Feal4Diff::SetRound(int iRound, FealState& round)
{
    Rounds[iRound].CopyToMe(round);
    return true;
}


bool Feal4Diff::GetIn(FealState& in)
{
    in.CopyToMe(In);
    return true;
}


bool Feal4Diff::GetOut(FealState& out)
{
    out.CopyToMe(Out);
    return true;
}


bool Feal4Diff::CalcDiffs2(Feal4& o1, Feal4& o2)
{
    In.XorandPut(o1.In, o2.In);
    Out.XorandPut(o1.Out, o2.Out);
    for(int i=0; i<5; i++) {
        Rounds[i].XorandPut(o1.Rounds[i], o2.Rounds[i]);
    }

    return true;
}


bool Feal4Diff::CalcDiffs(Feal4& o1, Feal4& o2)
{
    int         i;

    In.XorandPut(o1.In, o2.In);
    Out.XorandPut(o1.Out, o2.Out);
    for(int i=0; i<5; i++) {
        Rounds[i].XorandPut(o1.Rounds[i], o2.Rounds[i]);
    }

    ZPrime.XorandPut(Out.Left, g_oPattern2);
    YPrime.XorandPut(Out.Left, Out.Right);
    XPrime.XorandPut(YPrime, g_oPattern1);
    TPrime.CopyToMe(g_oPattern2);
    SPrime.CopyToMe(g_oPattern1);
    RPrime.CopyToMe(g_oPattern2);
    return true;
}


bool Feal4Diff::GetTPrime(FourBytes& tP)
{
    tP.CopyToMe(TPrime);
    return true;
}
   

bool Feal4Diff::GetSPrime(FourBytes& sP)
{
    sP.CopyToMe(SPrime);
    return true;
}


bool Feal4Diff::GetRPrime(FourBytes& rP)
{
    rP.CopyToMe(RPrime);
    return true;
}


bool Feal4Diff::GetXPrime(FourBytes& xP)
{
    xP.CopyToMe(XPrime);
    return true;
}


bool Feal4Diff::GetYPrime(FourBytes& yP)
{
    yP.CopyToMe(YPrime);
    return true;
}


bool Feal4Diff::GetZPrime(FourBytes& zP)
{
    zP.CopyToMe(ZPrime);
    return true;
}


// ---------------------------------------------------------------------------------------


void EncryptPair(FealState key, FealState in, FealState out, bool fPrint= false) {
    Feal4       oFeal;
    FourBytes   t;
    char        szLabel[128];

    oFeal.KeyInit(key);
    oFeal.SetIn(in);
    oFeal.Encrypt();
    out.CopyToMe(oFeal.Out);

    if (fPrint) {
        printf("RoundKeys:\n");
        for(int j=1; j<7; j++) {
            sprintf(szLabel, "    Round %d: ", j);
            oFeal.GetRoundKey(j, t);
            printFour(szLabel, t);
            printf("\n");
        }
        printf("\n");

        sprintf(szLabel, "\nInput             : "); 
        printState(szLabel, oFeal.In);
        sprintf(szLabel, "Output            : "); 
        printState(szLabel, oFeal.Out);
        for(int i=0; i<5; i++) {
            sprintf(szLabel, "Round %d           : ", i);
            printState(szLabel, oFeal.Rounds[i]); 
        }
        printf("\n");
    }
}

// ---------------------------------------------------------------------------------------


bool SolveBackForKeys(FourBytes& k0, FourBytes& k1, FourBytes& k2, FourBytes& k3)
{
    Feal4  ot;

    // K[i]
    byte c0= k3.rg[0];
    byte c1= k3.rg[1];
    byte c2= k3.rg[2];
    byte c3= k3.rg[3];

    // K[i-2]
    byte a0= k1.rg[0];
    byte a1= k1.rg[1];
    byte a2= k1.rg[2];
    byte a3= k1.rg[3];

    // K[i-1]
    byte b0= k2.rg[0];
    byte b1= k2.rg[1];
    byte b2= k2.rg[2];
    byte b3= k2.rg[3];

    byte d1= a0^a1;
    byte d2= a2^a3;

    // K[i-3]
    k0.rg[0]= ot.InvG1(c1,d1)^a2^b0;
    k0.rg[2]= ot.InvG0(c0, a0)^c1^b2;
    k0.rg[1]= ot.InvG0(c2, d2)^c1^b1;
    k0.rg[3]= ot.InvG1(c3,a3)^c2^b3;

#ifdef DEBUGSOLVE
#define DEBUGSOLVE
    char szLabel[32];

    sprintf(szLabel, "    K[i]        : "); 
    printFour(szLabel, k3); printf("\n");
    sprintf(szLabel, "    K[i-1]      : "); 
    printFour(szLabel, k2); printf("\n");
    sprintf(szLabel, "    K[i-2]      : "); 
    printFour(szLabel, k1); printf("\n");
    sprintf(szLabel, "    K[i-3]      : "); 
    printFour(szLabel, k0); printf("\n");
#endif
    return true;
}


// ---------------------------------------------------------------------------------------


//              Differential Cryptanalysis

#define MAXPAIRS    128
#define MAXROUND3  1024


void M(FourBytes& in, FourBytes& out)
{
    out.Zero();
    out.rg[1]= in.rg[0]^in.rg[1];
    out.rg[2]= in.rg[2]^in.rg[3];
}


int FastTestKeys(int iNumInputs, FourBytes* rgIn0, FourBytes* rgIn1,
                 int iMaxOutputs, FourBytes* rgCandidates,
                 FourBytes* rgYDiff, FourBytes* rgZDiff)
// returns number of keys that pass test
{
    FourBytes   oq0, oq1, oqPrime, ob0, ob1, oa, oc, od, oz0, oz1;
    FourBytes   zPrime;
    int         i, k;
    FourBytes   rgPhase1Cand[MAXPAIRS];
    int         iNumOut1= 0;
    int         iNumOut2= 0;
    Feal4       oF;
    bool        fSuccess;
    
    //  Primary Phase

    oa.Zero();
    printf("\n");
    while(!oa.MidBump()) {
        fSuccess= true;
        for(k=0; k<iNumInputs; k++) {
            oq0.CopyToMe(rgIn0[k]); oq1.CopyToMe(rgIn1[k]); 
            M(rgIn0[k], ob0);
            M(rgIn1[k], ob1);
            oF.F(oq0, ob0, oa);
            oF.F(oq1, ob1, oa);
            oqPrime.XorandPut(oq0, oq1);
            if(!(oqPrime.rg[1]==rgZDiff[k].rg[1]) ||
               !(oqPrime.rg[2]==rgZDiff[k].rg[2])) {
                fSuccess= false;
                break;
            }
        }
        if(fSuccess) {
            if(iNumOut1<iMaxOutputs) {
                rgPhase1Cand[iNumOut1++].CopyToMe(oa);
            }
#ifdef PRINTPRIMARY
             printFour((char*)"Primary phase key candidate: ", oa); printf("\n");
#endif
        }
    }
    printf("\n");

    // Secondary Phase
    // Phase 1 candidates are of the form M(K[3])
    oc.Zero();
    for(k=0; k<iNumOut1; k++) {
        while(!oc.MidBump()) {
            od.rg[0]= oc.rg[1];
            od.rg[1]= oc.rg[1]^rgPhase1Cand[k].rg[1];
            od.rg[2]= oc.rg[2]^rgPhase1Cand[k].rg[2];
            od.rg[3]= oc.rg[2];
            fSuccess= true;
            for(i=0; i<iNumInputs; i++) {
                oF.F(oz0, rgIn0[i], od);
                oF.F(oz1, rgIn1[i], od);
                zPrime.XorandPut(oz0, oz1);
#ifdef PRINTSECONDARY
                printFour((char*)"Secondary key, od: ", od);  printf("\n");
                printFour((char*)"Primary key candidate: ", rgPhase1Cand[k]);  printf("\n");
                printFour((char*)"Secondary, oc: ", oc);  printf("\n");
                printFour((char*)"Secondary, y0: ", rgIn0[0]);  printf("\n");
                printFour((char*)"Secondary, y1: ", rgIn1[0]);  printf("\n");
                printFour((char*)"Secondary, oz0: ", oz0);  printf("\n");
                printFour((char*)"Secondary, oz1: ", oz1);  printf("\n");
                printFour((char*)"Secondary, z': ", zPrime);  printf("\n");
                printFour((char*)"Secondary, ZPrime: ", rgZDiff[0]);  printf("\n\n");
#endif 
            if(!zPrime.Equal(rgZDiff[i])) {
                fSuccess= false;
                break;
                }
            }
            if(fSuccess) {
                if(iNumOut2<iMaxOutputs) {
                    rgCandidates[iNumOut2++].CopyToMe(od);
                }
            }
        }
    }

    return(iNumOut2);
}


int TestKeys(int iNumInputs, FourBytes* rgIn0, FourBytes* rgIn1,
                             int iMaxOutputs, FourBytes* rgCandidates,
                             FourBytes* rgRightDiff, 
                             FourBytes& oKeyStart, FourBytes& oKeyEnd,
                             int iMaxResults=2)
// returns number of keys that pass test
{
    bool        fSuccess;
    FourBytes   oPrime;
    FourBytes   tK;
    int         k;
    FourBytes   rgOut0[MAXPAIRS];
    FourBytes   rgOut1[MAXPAIRS];
    int         iNumOut= 0;
    Feal4       oF;
    
    //  Find candidates
    tK.CopyToMe(oKeyStart);
    while(!tK.Bump()) {
        fSuccess= true;
        for(k=0; k<iNumInputs; k++) {
            oF.TestRound(rgOut0[k], rgIn0[k], tK);
            oF.TestRound(rgOut1[k], rgIn1[k], tK);
            oPrime.XorandPut(rgOut0[k], rgOut1[k]);
            if(!oPrime.Equal(rgRightDiff[k])) {
                fSuccess= false;
                break;
            }
        }
        if(fSuccess) {
            if(iNumOut<iMaxOutputs) {
                rgCandidates[iNumOut++].CopyToMe(tK);
                if(iNumOut>=iMaxResults)
                    break;
            }
            printFour((char*)"Key Candidate: ", tK); printf((char*)"\n");
        }
        if(tK.Equal(oKeyEnd))
            break;
    }

    return(iNumOut);
}


int Round2TestKeys(int iNumInputs, FourBytes* rgInLeft, FourBytes* rgInRight,
                   FourBytes* rgOutLeft, FourBytes* rgOutRight, int iMaxOutputs, 
                   FourBytes* rgCandidates, FourBytes& oKeyStart, FourBytes& oKeyEnd,
                   int iMaxCmp=32, int iMaxResults=1)
// returns number of keys that pass test
{
    FourBytes   tK;
    int         i, j, n, m;
    int         iNumOut= 0;
    Feal4       oF;
    FourBytes   b, c1, c2, c3;
    FourBytes   PLd, PRd, CLd;
    
    //  Find candidates
    tK.CopyToMe(oKeyStart);
    while(!tK.Bump()) {
        // CL= PR+PL+k4+k5+F(CR+k1), CL*= PR*+PL*+k4+k5+F(CR*+k1), so
        // CL'= PL' + PR' + F(CR+k1)+F(CR*+k1), CL= t, CR= s
        n= 0;
        m= 0;
        for(i=0; i<iNumInputs; i++) {
            oF.F(c1, rgOutRight[i], tK);
            for(j=i+1; j<iNumInputs; j++) {
                PRd.XorandPut(rgInRight[i], rgInRight[j]);
                PLd.XorandPut(rgInLeft[i], rgInLeft[j]);
                CLd.XorandPut(rgOutLeft[i], rgOutLeft[j]);
                oF.F(c2, rgOutRight[j], tK);
                c3.XorandPut(c1, c2);
                b.XorandPut(PLd,PRd);
                b.XorToMe(CLd);
                n++;
                if(b.Equal(c3)) {
                    m++;
                }
            if(n>iMaxCmp)
                break;      
            }
        }

        if(m>(n/2)) {
            printf("Key candidates %d/%d: ", m, n);
            printFour(NULL, tK); printf("\n");
            if(iNumOut<iMaxOutputs) {
                rgCandidates[iNumOut++].CopyToMe(tK);
                if(iNumOut>=iMaxResults)
                    break;
            }
        }
        if(tK.Equal(oKeyEnd))
            break;
    }

    return(iNumOut);
}


int Round2TestKeys2(int iNumInputs, FourBytes* rgIn0, FourBytes* rgIn1, 
                    FourBytes* rgRDiff2, /* s0, s2 */ int iMaxOutputs, 
                    FourBytes* rgCandidates, FourBytes& oKeyStart, FourBytes& oKeyEnd)
// returns number of keys that pass test
{
    FourBytes   or0, or1, ob0, ob1, oa, oc, od, os0, os1;
    FourBytes   rPrime;
    FourBytes   RPrime;
    int         i, k;
    FourBytes   rgPhase1Cand[MAXPAIRS];
    int         iNumOut1= 0;
    int         iNumOut2= 0;
    Feal4       oF;
    bool        fSuccess;
    
    //  Primary Phase

    oa.Zero();
    printf("\n");

#define OLD1
#ifdef   OLD1
    while(!oa.MidBump()) {
        fSuccess= true;
        for(k=0; k<iNumInputs; k++) {
            os0.CopyToMe(rgIn0[k]);
            os1.CopyToMe(rgIn1[k]);
            M(os0, ob0);
            M(os1, ob1);
            oF.F(or0, ob0, oa);
            oF.F(or1, ob1, oa);
            rPrime.XorandPut(or0, or1);
            oc.Zero();
            oc.rg[1]= rgRDiff2[k].rg[1];
            oc.rg[2]= rgRDiff2[k].rg[2];
            if(oc.rg[1]!=rPrime.rg[1] || oc.rg[2]!=rPrime.rg[2]) {
                fSuccess= false;
                break;
            }
        }
        if(fSuccess) {
            if(iNumOut1<iMaxOutputs) {
                rgPhase1Cand[iNumOut1++].CopyToMe(oa);
            }
#ifdef PRINTPRIMARY
            printFour((char*)"Primary phase key candidate: ", oa); printf("\n");
#endif
        }
    }
    printf("\n");

    // Secondary Phase
    // Phase 1 candidates are of the form M(K[3])
    oc.Zero();
    for(k=0; k<iNumOut1; k++) {
        while(!oc.MidBump()) {
            od.rg[0]= oc.rg[1];
            od.rg[1]= oc.rg[1]^rgPhase1Cand[k].rg[1];
            od.rg[2]= oc.rg[2]^rgPhase1Cand[k].rg[2];
            od.rg[3]= oc.rg[2];
            fSuccess= true;
            for(i=0; i<iNumInputs; i++) {
                oF.F(or0, rgIn0[i], od);
                oF.F(or1, rgIn1[i], od);
                rPrime.XorandPut(or0, or1);
            if(!rPrime.Equal(rgRDiff2[i])) {
                fSuccess= false;
                break;
                }
            }
            if(fSuccess) {
                if(iNumOut2<iMaxOutputs) {
                    rgCandidates[iNumOut2++].CopyToMe(od);
                }
#ifdef PRINTSECONDARY
                printFour((char*)"Secondary phase key candidate: ", od); printf("\n");
#endif
            }
        }
    }
    return(iNumOut2);

#else  // OLD

    oa.CopyToMe(oKeyStart);
    while(!oa.Bump()) {
        fSuccess= true;
        for(k=0; k<iNumInputs; k++) {
            os0.CopyToMe(rgIn0[k]);
            os1.CopyToMe(rgIn1[k]);
            oF.F(or0, os0, oa);
            oF.F(or1, os1, oa);
            oc.CopyToMe(rgRDiff2[k]);
            rPrime.XorandPut(or0, or1);
#ifdef PRINTTHIS
            printFour((char*)"s0: ", os0);  printFour((char*)",  s1: ", os1);  
            printFour((char*)"    r0: ", or0);  printFour((char*)",  r1: ", or1);  
            printFour((char*)",  key: ", oa);  printf("\n"); 
            printFour((char*)"   rPrime: ", rPrime);  
            printFour((char*)",  RPrime: ", oc);  printf("\n");
#endif
            if(!oc.Equal(rPrime)) {
                fSuccess= false;
                break;
            }
        }
        if(fSuccess) {
            if(iNumOut1<iMaxOutputs) {
                rgCandidates[iNumOut1++].CopyToMe(oa);
            }
        }
        if(oKeyEnd.Equal(oa))
            break;
    }
    printf("\n");
    return iNumOut1;

#endif // OLD
}


inline int bit23(FourBytes& x)
{
    return (int) (x.rg[2]&0x01);
}


inline int bit15(FourBytes& x)
{
    return (int) (x.rg[1]&0x01);
}


inline int bit29(FourBytes& x)
{
    return (int) ((x.rg[3]>>2)&0x01);
}


inline int bit31(FourBytes& x)
{
    return (int) (x.rg[3]&0x01);
}


inline int biti(int i, FourBytes& x)
{
    int j= (i>>3);
    int k= i&0x7;

    return (int) ((x.rg[j]>>(7-k))&0x01);
}


void TestBitPositions(int iNumInputs, unsigned* rgIn)
{
    FourBytes   o29, o23, o15, o31;
    int         i, j, k;
    FourBytes   t, s, r;
    Feal4       oF;

    o29.Zero(); o23.Zero(); o15.Zero(); o31.Zero();
    o15.rg[1]= 0x1; o23.rg[2]= 0x1; o29.rg[3]= 0x4; o31.rg[3]= 0x1;

    printf("o15: Bit 15: %d, Bit 23: %d, Bit 29: %d, Bit 31: %d\n",
            bit15(o15), bit23(o15), bit29(o15), bit31(o15));
    printf("o23: Bit 15: %d, Bit 23: %d, Bit 29: %d, Bit 31: %d\n",
            bit15(o23), bit23(o23), bit29(o23), bit31(o23));
    printf("o29: Bit 15: %d, Bit 23: %d, Bit 29: %d, Bit 31: %d\n",
            bit15(o29), bit23(o29), bit29(o29), bit31(o29));
    printf("o31: Bit 15: %d, Bit 23: %d, Bit 29: %d, Bit 31: %d\n\n",
            bit15(o31), bit23(o31), bit29(o31), bit31(o31));

    printf("o15: Bit 15: %d, Bit 23: %d, Bit 29: %d, Bit 31: %d\n",
            biti(15, o15), biti(23, o15), biti(29, o15), biti(31, o15));
    printf("o23: Bit 15: %d, Bit 23: %d, Bit 29: %d, Bit 31: %d\n",
            biti(15, o23), biti(23, o23), biti(29, o23), biti(31, o23));
    printf("o29: Bit 15: %d, Bit 23: %d, Bit 29: %d, Bit 31: %d\n",
            biti(15, o29), biti(23, o29), biti(29, o29), biti(31, o29));
    printf("o31: Bit 15: %d, Bit 23: %d, Bit 29: %d, Bit 31: %d\n\n",
            biti(15, o31), biti(23, o31), biti(29, o31), biti(31, o31));

    r.Zero();
    for(i=0; i<iNumInputs; i++) {
        fillFromWord(t, rgIn[i]);
        oF.F(s, t, r);
        printFour((char*)"key: ", r); printFour((char*)" t: ", t); 
        printFour((char*)" s: ", s); printf((char*)"\n");

        j= biti(13, s)^biti(7, t)^biti(15, t)^biti(23, t)^biti(31, t)^0x1;
        printf("\tY[13]+X[7,15,23,29]+1 =  %d\n", j);

        j= biti(5, s)^biti(15, s)^biti(7, t);
        printf("\tS[5,15](Y)+S[7](X)    =  %d\n", j);

        j= biti(15, s)^biti(21, s)^biti(23, t)^biti(31, t);
        printf("\tY[15,21]+X[23,31]     =  %d\n", j);

        j= biti(23, s)^biti(29, s)^biti(31, t)^0x1;
        printf("\tY[23,29]+X[31]+1      =  %d\n", j);
    }
}


#define TESTCOUNT
int TestLinear(int iNumInputs, FealState* rgIn, FealState* rgOut, int iMaxOutputs, 
               FourBytes* rgCandidates, FourBytes& oKeyStart, FourBytes& oKeyEnd, 
               int iMaxResults=2)
//
//  Test: a= (L[0]+R[0]+L[4])[23,29] + (L[0]+L[4]+R[4])[31] + (F(L[0]+R[0], K[0]))[31]
//          returns number of keys that pass test
//  Note: Only bits 10..15 and 18..23 affect outcome
{
    FourBytes   tK;
    int         j, k;
    int         iNumOut= 0;
    Feal4       oF;
    int         c[2];
    FourBytes   oL0R0L4, oL0L4R4, oL0R0, t;

    printf("TestLinear: %d, ", iNumInputs); 
    printFour("Keystart: ", oKeyStart);
    printFour("KeyEnd: ", oKeyEnd); printf("\n");
    //  Find candidates
    tK.CopyToMe(oKeyStart);
    while(!tK.Bump()) {
        c[0] = 0; c[1] = 0;
        for(k=0 ; k<iNumInputs; k++) {
            oL0R0L4.XorandPut(rgIn[k].Left, rgIn[k].Right);
            oL0R0L4.XorToMe(rgOut[k].Left);
            oL0L4R4.XorandPut(rgIn[k].Left, rgOut[k].Left);
            oL0L4R4.XorToMe(rgOut[k].Right);
            oL0R0.XorandPut(rgIn[k].Left, rgIn[k].Right);
            oF.F(t, oL0R0, tK);
            j= bit23(oL0R0L4)^bit29(oL0R0L4)^bit31(oL0L4R4)^bit31(t);
            c[j]++;
            if (c[0] * c[1] != 0) {
                printf("c[0]: %d, c[1]: %d\n", c[0], c[1]);
                break;
            }
        }
        printf("K** %d\n", k);
        if(k == iNumInputs) {
            if(iNumOut<iMaxOutputs) {
                rgCandidates[iNumOut++].CopyToMe(tK);
                if(iNumOut>=iMaxResults)
                    break;
            }
            printFour("Key Candidate: ", tK); printf("\n");
        }
        if(tK.Equal(oKeyEnd))
            break;
    }
    return(iNumOut);
}


bool GetFourthRoundFOutputs(int iNumPairs, FourBytes& oCandKey,
                            FourBytes* y0, FourBytes* y1, FourBytes* y2,
                            FourBytes* z0, FourBytes* z1, FourBytes* z2,
                            bool fPrint=true)
{
    int         i;
    FourBytes   zPrime, zPrime2;
    Feal4       oF;

    for(i=0;i<iNumPairs;i++) {
        oF.TestRound(z0[i], y0[i], oCandKey); 
        oF.TestRound(z1[i], y1[i], oCandKey);
        oF.TestRound(z2[i], y2[i], oCandKey);
        zPrime.XorandPut(z0[i], z1[i]);
        zPrime2.XorandPut(z0[i], z2[i]);
        if(fPrint) {
            printFour((char*)"  z0: ", z0[i]);
            printFour((char*)"  z1: ", z1[i]);
            printFour((char*)"  z2: ", z2[i]);
            printFour((char*)"  zPrime: ", zPrime); 
            printFour((char*)"  zPrime2: ", zPrime2); 
            printf("\n");
        }
    }
    return true;
}


bool GetThirdRoundInputs(int iNumPairs, FourBytes* rgOut, FourBytes* rgOutd, FourBytes* rgOutd2,
                            FourBytes* z0, FourBytes* z1, FourBytes* z2,
                            FourBytes* t0, FourBytes* t1, FourBytes* t2,
                            bool fPrint=true)

{
    int i;
    FourBytes tPrime, tPrime2;

    for(i=0;i<iNumPairs;i++) {
        t0[i].XorandPut(z0[i], rgOut[i]);
        t1[i].XorandPut(z1[i], rgOutd[i]);
        t2[i].XorandPut(z2[i], rgOutd2[i]);
        tPrime.XorandPut(t0[i], t1[i]);
        tPrime2.XorandPut(t0[i], t2[i]);
        if(fPrint) {
            printFour((char*)"  t0: ", t0[i]);
            printFour((char*)"  t1: ", t1[i]);
            printFour((char*)"  t2: ", t2[i]);
            printFour((char*)"  tPrime: ", tPrime); 
            printFour((char*)"  tPrime2: ", tPrime2); 
            printf("\n");
        }
    }
    return true;
}


bool GetThirdRoundFOutputs(int iNumPairs, FourBytes& oCandKey,
                            FourBytes* x0, FourBytes* x1, FourBytes* x2,
                            FourBytes* t0, FourBytes* t1, FourBytes* t2)
{
    int         i;
    FourBytes   xPrime, xPrime2;
    Feal4       oF;

    for(i=0;i<iNumPairs;i++) {
        oF.TestRound(x0[i], t0[i], oCandKey);
        oF.TestRound(x1[i], t1[i], oCandKey);
        oF.TestRound(x2[i], t2[i], oCandKey);
        xPrime.XorandPut(x0[i], x1[i]);
        xPrime2.XorandPut(x0[i], x2[i]);
        printFour((char*)"  x0: ", x0[i]);
        printFour((char*)"  x1: ", x1[i]);
        printFour((char*)"  x2: ", x2[i]);
        printFour((char*)"  xPrime: ", xPrime); 
        printFour((char*)"  xPrime2: ", xPrime2); 
        printf("\n");
    }
    return true;
}


bool GetSecondRoundInputs(int iNumPairs, FourBytes* x0, FourBytes* x1, FourBytes* x2,
                          FourBytes* y0, FourBytes* y1, FourBytes* y2,
                          FourBytes* s0, FourBytes* s1, FourBytes* s2, 
                          bool fPrint=true)

{
    int i;
    FourBytes sPrime, sPrime2;

    for(i=0;i<iNumPairs;i++) {
        s0[i].XorandPut(x0[i], y0[i]);
        s1[i].XorandPut(x1[i], y1[i]);
        s2[i].XorandPut(x2[i], y2[i]);
        sPrime.XorandPut(s0[i], s1[i]);
        sPrime2.XorandPut(s0[i], s2[i]);
        if(fPrint) {
            printFour((char*)"  s0: ", s0[i]);
            printFour((char*)"  s1: ", s1[i]);
            printFour((char*)"  s2: ", s2[i]);
            printFour((char*)"  sPrime: ", sPrime); 
            printFour((char*)"  sPrime2: ", sPrime2); 
            printf("\n");
        }
    }
    return true;
}


bool BackSolve(FourBytes* oTestKeys, bool fPrint=true)
{
    bool fSuccess= false;
    FourBytes   oZero;

    oZero.Zero();

    SolveBackForKeys(oTestKeys[2], oTestKeys[3], oTestKeys[4], oTestKeys[5]);
    SolveBackForKeys(oTestKeys[1], oTestKeys[2], oTestKeys[3], oTestKeys[4]);
    SolveBackForKeys(oTestKeys[0], oTestKeys[1], oTestKeys[2], oTestKeys[3]);

    if(fPrint) {
        printf("\nBacksolve\n");
        printFour((char*)"  TestKey[0]; ", oTestKeys[0]); printf("\n");
        printFour((char*)"  TestKey[1]; ", oTestKeys[1]); printf("\n");
        printFour((char*)"  TestKey[2]; ", oTestKeys[2]); printf("\n");
        printFour((char*)"  TestKey[3]; ", oTestKeys[3]); printf("\n");
        printFour((char*)"  TestKey[4]; ", oTestKeys[4]); printf("\n");
        printFour((char*)"  TestKey[5]; ", oTestKeys[5]); printf("\n");
    }

    if(oZero.Equal(oTestKeys[0])) {
        fSuccess= true;
    }
    return fSuccess;
}


bool DifferentialAttack(unsigned key1, unsigned key2, int iNumPairs, unsigned* inBlocks)
{
    Feal4       oFeal[MAXPAIRS];
    Feal4       oFeald[MAXPAIRS];
    Feal4Diff   oFealDiff[MAXPAIRS];
    Feal4       oFeald2[MAXPAIRS];
    Feal4Diff   oFealDiff2[MAXPAIRS];
    unsigned    inBlockd[2*MAXPAIRS];
    unsigned    inBlockd2[2*MAXPAIRS];
    FealState   key;
    FealState   in;
    FealState   out;
    FealState   ind;
    FealState   outd;
    FealState   ind2;
    FealState   outd2;
    FourBytes   t;
    FealState   r;
    int         i,j,k,m,n;
    char        szLabel[32];

    bool        fFoundKey= false;
    bool        fNoisy= true;
    bool        fVeryNoisy= false;


    //  Differential Patterns
    g_oPattern1.rg[0]= 0x80; g_oPattern1.rg[1]= 0x80; 
    g_oPattern1.rg[2]= 0x00; g_oPattern1.rg[3]= 0x00;
    g_oPattern2.rg[0]= 0x02; g_oPattern2.rg[1]= 0x00; 
    g_oPattern2.rg[2]= 0x00; g_oPattern2.rg[3]= 0x00;
    g_oPattern3.rg[0]= 0xa0; g_oPattern3.rg[1]= 0x00; 
    g_oPattern3.rg[2]= 0x80; g_oPattern3.rg[3]= 0x00;

    //  Init corresponding plain and ciphertext for differential analysis
    fillFromWord(key.Left, key1);
    fillFromWord(key.Right, key2);

    for(k=0; k<iNumPairs; k++) {

        fillFromWord(in.Left, inBlocks[2*k]);
        fillFromWord(in.Right, inBlocks[2*k+1]);

        inBlockd[2*k]= inBlocks[2*k]^0x80800000;
        inBlockd[2*k+1]= inBlocks[2*k+1]^0x80800000;
        inBlockd2[2*k]= inBlocks[2*k]^0xa2008000;
        inBlockd2[2*k+1]= inBlocks[2*k+1]^0x22808000;

        fillFromWord(ind.Left, inBlockd[2*k]);
        fillFromWord(ind.Right, inBlockd[2*k+1]);
        fillFromWord(ind2.Left, inBlockd2[2*k]);
        fillFromWord(ind2.Right, inBlockd2[2*k+1]);

        oFeal[k].KeyInit(key);
        oFeal[k].SetIn(in);
        oFeal[k].Encrypt();

        oFeald[k].KeyInit(key);
        oFeald[k].SetIn(ind);
        oFeald[k].Encrypt();

        oFeald2[k].KeyInit(key);
        oFeald2[k].SetIn(ind2);
        oFeald2[k].Encrypt();

    }

    printf("%d pairs, round keys:\n", iNumPairs);
    for(j=1; j<7; j++) {
        sprintf(szLabel, "    Round %d: ", j);
        oFeal[0].GetRoundKey(j, t);
        printFour(szLabel, t);
        printf("\n");
    }
    printf("\n");

    if(fNoisy) {
        for(k=0; k<iNumPairs; k++) {
            printf("\nLeft Encryption %d\n", k);
            sprintf(szLabel, "Input             : "); 
            printState(szLabel, oFeal[k].In);
            sprintf(szLabel, "Output            : "); 
            printState(szLabel, oFeal[k].Out);
            for(i=0; i<5; i++) {
                    sprintf(szLabel, "Round %d           : ", i);
                    printState(szLabel, oFeal[k].Rounds[i]); 
            }
        }
        printf("\n");

        for(k=0; k<iNumPairs; k++) {
            printf("\nRight Encryption %d\n", k);
            sprintf(szLabel, "Input             : "); 
            printState(szLabel, oFeald[k].In);
            sprintf(szLabel, "Output            : "); 
            printState(szLabel, oFeald[k].Out);
            for(i=0; i<5; i++) {
                    sprintf(szLabel, "Round %d           : ", i);
                    printState(szLabel, oFeald[k].Rounds[i]); 
            }
        }
        printf("\n");

        for(k=0; k<iNumPairs; k++) {
            printf("\nRight Encryption %d for second differential\n", k);
            sprintf(szLabel, "Input             : "); 
            printState(szLabel, oFeald2[k].In);
            sprintf(szLabel, "Output            : "); 
            printState(szLabel, oFeald2[k].Out);
            for(i=0; i<5; i++) {
                sprintf(szLabel, "Round %d           : ", i);
                printState(szLabel, oFeald2[k].Rounds[i]); 
            }
        }
        printf("\n");


        for(k=0; k<iNumPairs; k++) {
            oFealDiff[k].CalcDiffs(oFeal[k], oFeald[k]);
            printf("\nPair %d\n", k);
            sprintf(szLabel, "Input Difference  : "); 
            printState(szLabel, oFealDiff[k].In);
            sprintf(szLabel, "Output Difference : "); 
            printState(szLabel, oFealDiff[k].Out);
            for(i=0; i<5; i++) {
                    sprintf(szLabel, "Round %d difference: ", i);
                    printState(szLabel, oFealDiff[k].Rounds[i]); 
            }
            printFour((char*)"    X'          : ", oFealDiff[k].XPrime); printf("\n");
            printFour((char*)"    Y'          : ", oFealDiff[k].YPrime); printf("\n");
            printFour((char*)"    Z'          : ", oFealDiff[k].ZPrime); printf("\n");
        }
        printf("\n");

        for(k=0; k<iNumPairs; k++) {
            oFealDiff2[k].CalcDiffs2(oFeal[k], oFeald2[k]);
            printf("\nPair %d, second Difference\n", k);
            sprintf(szLabel, "Input Difference  : "); 
            printState(szLabel, oFealDiff2[k].In);
            sprintf(szLabel, "Output Difference : "); 
            printState(szLabel, oFealDiff2[k].Out);
            for(i=0; i<5; i++) {
                sprintf(szLabel, "Round %d difference: ", i);
                printState(szLabel, oFealDiff2[k].Rounds[i]); 
            }
        }

    }

    //      The attack
    Feal4       oF;             // Utility for TestRounds
    FourBytes   y0[MAXPAIRS];   // Round 4 input
    FourBytes   y1[MAXPAIRS];   // Round 4 input
    FourBytes   y2[MAXPAIRS];   // Round 4 input, second differential
    FourBytes   z0[MAXPAIRS];   // Round 4 output
    FourBytes   z1[MAXPAIRS];   // Round 4 output
    FourBytes   z2[MAXPAIRS];   // Round 4 output, second differential

    FourBytes   t0[MAXPAIRS];   // Round 3 input
    FourBytes   t1[MAXPAIRS];   // Round 3 input
    FourBytes   t2[MAXPAIRS];   // Round 3 input, second differential
    FourBytes   x0[MAXPAIRS];   // Round 3 output
    FourBytes   x1[MAXPAIRS];   // Round 3 output
    FourBytes   x2[MAXPAIRS];   // Round 3 output, second differential

    FourBytes   s0[MAXPAIRS];   // Round 2 input
    FourBytes   s1[MAXPAIRS];   // Round 2 input
    FourBytes   s2[MAXPAIRS];   // Round 2 input, second differential
    FourBytes   r0[MAXPAIRS];   // Round 2 output
    FourBytes   r1[MAXPAIRS];   // Round 2 output
    FourBytes   r2[MAXPAIRS];   // Round 2 output, second differential

    FourBytes oKey1Start, oKey1End, oKey2Start, oKey2End, oKey3Start, oKey3End;

    int         iKeys3;
    int         iKeys2;
    int         iKeys1;
    int         iNumk3= 0;
    int         iNumk2= 0;
    int         iNumk1= 0;

    FourBytes   k3Cand[MAXPAIRS];
    FourBytes   k2Cand[MAXPAIRS];
    FourBytes   k1Cand[MAXPAIRS];

    FourBytes   zPrime;
    FourBytes   zPrime2;
    FourBytes   yPrime;
    FourBytes   yPrime2;
    FourBytes   xPrime;
    FourBytes   xPrime2;
    FourBytes   tPrime;
    FourBytes   tPrime2;
    FourBytes   sPrime;
    FourBytes   sPrime2;
    FourBytes   rPrime;
    FourBytes   rPrime2;

    FourBytes   rgoYDiffs[MAXPAIRS];
    FourBytes   rgoZDiffs[MAXPAIRS];
    FourBytes   rgoTDiffs[MAXPAIRS];
    FourBytes   rgoXDiffs[MAXPAIRS];

    FourBytes   rgoRDiffs2[MAXPAIRS];

    int         iNumInputs= 0;
    FourBytes   rgInLeft[MAXPAIRS];
    FourBytes   rgInRight[MAXPAIRS];
    FourBytes   rgOutLeft[MAXPAIRS];
    FourBytes   rgOutRight[MAXPAIRS];
    FourBytes   rgOutLeftd[MAXPAIRS];
    FourBytes   rgOutLeftd2[MAXPAIRS];
    FourBytes   oTestKeys[6];

    bool        fSuccess;
    bool        fSuccess1;
    bool        fSuccess2;
    bool        fSuccess3;


    oKey1Start.Zero();
    oKey1End.AntiZero(); 
    oKey2Start.Zero(); 
    oKey2End.AntiZero();
    oKey3Start.Zero(); 
    oKey3End.AntiZero();

    printf("\nDifferential test\n\n");

    // Get fourth round key candidates
    printf("Looking for fourth round keys\n");
    printf("Fourth round inputs\n");
    for(k=0;k<iNumPairs;k++) {
        y0[k].XorandPut(oFeal[k].Out.Left, oFeal[k].Out.Right);
        y1[k].XorandPut(oFeald[k].Out.Left, oFeald[k].Out.Right);
        y2[k].XorandPut(oFeald2[k].Out.Left, oFeald2[k].Out.Right);
        yPrime.XorandPut(y0[k], y1[k]);
        yPrime2.XorandPut(y0[k], y2[k]);
        if(fNoisy) {
            printFour((char*)"  y0: ", y0[k]);
            printFour((char*)"  y1: ", y1[k]);
            printFour((char*)"  y2: ", y2[k]);
            printFour((char*)"  yPrime: ", yPrime);
            printFour((char*)"  yPrime2: ", yPrime2);
        }
        rgoYDiffs[k].CopyToMe(oFealDiff[k].YPrime);
        rgoZDiffs[k].CopyToMe(oFealDiff[k].ZPrime);
    }
#ifndef SLOWSOLVE
    iNumk3= FastTestKeys(iNumPairs, y0, y1, MAXPAIRS, k3Cand, rgoYDiffs, rgoZDiffs);
#else
    iNumk3= TestKeys(iNumPairs, y0, y1, MAXPAIRS, k3Cand, rgoZDiffs, oKey3Start, oKey3End);
#endif
    if(iNumk3<=0) {
        printf("No round 4 keys, quitting\n");
        return 0;
    }
    printf("Fourth round candidate keys\n");
    for(i=0;i<iNumk3; i++) {
        printf("%d: ", i);
        printFour(NULL, k3Cand[i]); printf("\n");
    }


    // Loop through fourth round candidates keys until we find a coplete solution
    fSuccess3= false;
    fSuccess2= false;
    fSuccess1= false;
    iNumk2= 0;
    // for(iKeys3=0; iKeys3<1 /*iNumk3*/; iKeys3++) {           // FIX index
    for(iKeys3=0; iKeys3<iNumk3; iKeys3++) {

        // Get third round key candidates
        printf("\nLooking for third round keys\n");
        printFour((char*)"Fourth round F-function test outputs with key ", k3Cand[iKeys3]); printf("\n");
        GetFourthRoundFOutputs(iNumPairs, k3Cand[iKeys3], y0, y1, y2, z0, z1, z2);

        printf("Resulting third round inputs\n");
        for(i=0;i<iNumPairs;i++) {
            rgOutLeft[i]= oFeal[i].Out.Left;
            rgOutLeftd[i]= oFeald[i].Out.Left;
            rgOutLeftd2[i]= oFeald2[i].Out.Left;
            rgoXDiffs[i].CopyToMe(oFealDiff[i].XPrime);
            rgoTDiffs[i].CopyToMe(oFealDiff[i].TPrime);
        }
        GetThirdRoundInputs(iNumPairs, rgOutLeft, rgOutLeftd, rgOutLeftd2, z0, z1, z2, t0, t1, t2);

#ifndef SLOWSOLVE
        m= FastTestKeys(iNumPairs, t0, t1, MAXPAIRS, &k2Cand[iNumk2], rgoTDiffs, rgoXDiffs);
#else
        m= TestKeys(iNumPairs, t0, t1, MAXPAIRS, &k2Cand[iNumk2], rgoXDiffs, oKey2Start, oKey2End);
#endif
        if(m>0) {
            iNumk2+= m;
            fSuccess3= true;
        }
    
        if(!fSuccess3) {
            printf("No round 3 keys, for this round 4 key\n");
            continue;
        }
        printf("Third round candidate keys\n");
        for(i=0;i<iNumk2; i++) {
            printf("%d: ", i);
            printFour(NULL, k2Cand[i]); printf("\n");
        }

        // Get second round key candidates, input differential: 0xa200 8000  0x2280 8000
        printf("\nLooking for second round keys\n");

        fSuccess2= false;
        iNumk1= 0;

        // for(iKeys2=5; iKeys2<6 /*iNumk2*/; iKeys2++) {           // FIX index
        for(iKeys2=5; iKeys2<iNumk2; iKeys2++) {
            printFour((char*)"Third round F-function outputs with key ", k2Cand[iKeys2]); printf("\n"); 
            GetThirdRoundFOutputs(iNumPairs, k2Cand[iKeys2], x0, x1, x2, t0, t1, t2);
            printf("Resulting second round inputs\n");
            GetSecondRoundInputs(iNumPairs, x0, x1, x2, y0, y1, y2, s0, s1, s2);

#ifdef OLDSECONDROUNDSOLVE
            // CL= t, CR= s
            for(i=0; i<iNumPairs;i++) {
                rgInLeft[i].CopyToMe(oFeal[i].In.Left);
                rgInRight[i].CopyToMe(oFeal[i].In.Right);
                rgOutLeft[i].CopyToMe(t0[i]);
                rgOutRight[i].CopyToMe(s0[i]);
            }
            for(i=0; i<iNumPairs;i++) {
                rgInLeft[i+iNumPairs].CopyToMe(oFeald[i].In.Left);
                rgInRight[i+iNumPairs].CopyToMe(oFeald[i].In.Right);
                rgOutLeft[i+iNumPairs].CopyToMe(t1[i]);
                rgOutRight[i+iNumPairs].CopyToMe(s1[i]);
            }
            iNumInputs= 2*iNumPairs;
            if(iNumInputs>32)
                iNumInputs= 32;
    
            printf("Second round keys\n");
            oKey1Start.rg[3]= 0xd6;
            m= Round2TestKeys(iNumInputs, rgInLeft, rgInRight, rgOutLeft, 
                            rgOutRight, MAXPAIRS, &k1Cand[iNumk1],
                            oKey1Start, oKey1End, 60, 2);
            if(m>0) {
                iNumk1+= m;
                fSuccess2= true;
            }
#else
            // s --> r
            for(i=0; i<iNumPairs;i++) {
                rgoRDiffs2[i].XorandPut(t0[i],t2[i]); 
                rgoRDiffs2[i].XorToMe(g_oPattern1); 
            }
            printf("Second round keys\n");
            m= Round2TestKeys2(iNumPairs, s0, s2, rgoRDiffs2 , MAXPAIRS, &k1Cand[iNumk1], oKey1Start, oKey1End);
    
            if(m>0) {
                iNumk1+= m;
                fSuccess2= true;
            }
#endif
          if(!fSuccess2) {
                printf("No round 2 keys for this round 3 key\n");
                continue;
            }

            printf("Second round candidate keys\n");
            for(i=0;i<iNumk1; i++) {
                printf("%d: ", i);
                printFour(NULL, k1Cand[i]); printf("\n");
            }
   
            // Solving for master and round keys
            oTestKeys[5].CopyToMe(k3Cand[iKeys3]);
            oTestKeys[4].CopyToMe(k2Cand[iKeys2]);
            for(iKeys1=0; iKeys1<iNumk1; iKeys1++) {
                oTestKeys[3].CopyToMe(k1Cand[iKeys1]);
     
                if(BackSolve(oTestKeys)) {
                    fFoundKey= true;
                    printFour((char*)"  Valid Key: ", oTestKeys[1]);
                    printFour((char*)" ", oTestKeys[2]); printf("\n");
                    break;
                }
            }
    
            printf("\n");
            if(fFoundKey)
                break;
        }
        if(fFoundKey)
            break;
    }

    printf("%d Round4 keys saved\n", iNumk3);
    printf("%d Round3 keys saved\n", iNumk2);
    printf("%d Round2 keys saved\n", iNumk1);
    if(fFoundKey) {
        printFour((char*)"Recovered key:  ", oTestKeys[1]);
        printFour((char*)" ", oTestKeys[2]); printf("\n");
    }
    else {
        printf("No key found\n");
    }
    printf("\ndone\n");
    return 0;
}
    

// ---------------------------------------------------------------------------------------


//      Linear Cryptanalysis

bool LinearAttack(unsigned key1, unsigned key2, int iNumBlocks, unsigned* inBlocks)
//
//  a= S[23,29](L[0]+R[0]+L[4]) + S[31](L[0]+L[4]+R[4] + S[31](F(L[0]+R[0]+K[0]))
//
{
    FealState   key;
    FealState   in;
    FealState   out;
    int         i,j,k,m,n;
    char        szLabel[32];
    FourBytes   t;

#ifdef  LINARBITTEST
#define LINARBITTEST
    TestBitPositions(iNumBlocks, inBlocks);
    return true;
#endif

    fillFromWord(key.Left, key1);
    fillFromWord(key.Right, key2);
    FealState   rgIn[MAXPAIRS];
    FealState   rgOut[MAXPAIRS];

    for(k=0; k<iNumBlocks; k++) {
        fillFromWord(in.Left, inBlocks[2*k]);
        fillFromWord(in.Right, inBlocks[2*k+1]);
        EncryptPair(key, in, out, true);
        rgIn[k].CopyToMe(in);
        rgOut[k].CopyToMe(out);
    }

    printf("Calling TestLinear\n");
    int         iNumk0= 0;
    FourBytes   k0Cand[MAXPAIRS];
    FourBytes   oKeyStart, oKeyEnd;

    oKeyStart.Zero();
    oKeyEnd.AntiZero();
    oKeyEnd.rg[0]= 0;
    oKeyEnd.rg[1]= 1;
    oKeyEnd.rg[2]= 0;
    oKeyEnd.rg[3]= 0;

    iNumk0= TestLinear(iNumBlocks, rgIn, rgOut, MAXPAIRS, k0Cand, oKeyStart, oKeyEnd, 100);
    printf("TestLinear returns %d\n", iNumk0);
    return iNumk0;
}


// ---------------------------------------------------------------------------------------


//  TestBlock
unsigned g_inBlock[16]={
    0x12345678, 0x09abcdef, 0x09abcdef, 0x12345678, 
    0x34567812, 0xbcdef9a0, 0xaaaa5555, 0x66669999,
    0xcd0ef9ab, 0x56781234, 0x14159265, 0x35877933,
    0xaabbaabb, 0xffffbbbb, 0xffffbbbb, 0xaabbaabb,
};


void test_encrypt(unsigned key1, unsigned key2, unsigned in1, unsigned in2) {
    Feal4       oFeal;
    FealState   key;
    FealState   in;
    FealState   out;
    FourBytes   t;
    FealState   r;
    int         i,j;
    char        szLabel[32];

    printf("Feal4 Key: %08x %08x, Input: %08x %08x\n\n", key1, key2, in1, in2);

    fillFromWord(key.Left, key1);
    fillFromWord(key.Right, key2);
    fillFromWord(in.Left, in1);
    fillFromWord(in.Right, in2);

    oFeal.KeyInit(key);

    printf("RoundKeys:\n");
    for(j=1; j<7; j++) {
        sprintf(szLabel, "Round %d: ", j);
        oFeal.GetRoundKey(j, t);
        printFour(szLabel, t);
        printf("\n");
    }

    oFeal.SetIn(in);
    oFeal.Encrypt();
    oFeal.GetIn(r);
    printf("\nEncrypt:\n");
    printState("in     : ", r);
    for(j=0; j<5; j++) {
        sprintf(szLabel, "Round %d: ", j);
        oFeal.GetRound(j, r);
        printState(szLabel, r);
    }
    oFeal.GetOut(r);
    printState("out:     ", r);
    printf("\n");
    printf("\n");

    oFeal.SetIn(r);
    oFeal.Decrypt();
    oFeal.GetIn(r);
    printf("Decrypt:\n");
    printState("in     : ", r);
    for(j=0; j<5; j++) {
        sprintf(szLabel, "Round %d: ", j);
        oFeal.GetRound(j, r);
        printState(szLabel, r);
    }
    oFeal.GetOut(r);
    printState("out:     ", r);
    printf("\n");
}


int main(int an, char** av)
{
    unsigned    key1, key2;
    unsigned    in1, in2, in1d, in2d;
    Feal4       oFeal;
    Feal4       oFeald;
    Feal4Diff   oFealDiff;
    FealState   key;
    FealState   in;
    FealState   out;
    FealState   ind;
    FealState   outd;
    FourBytes   t;
    FealState   r;
    int         i,j;
    char        szLabel[32];
    bool        fDoDifferential= false;
    int         inFile;
    int         iNumPairs= 8;
    byte        rgInBlock[8*MAXPAIRS];

    if (an < 4) {
        printf("Feal key1(x) key2(x) in1(x) in2(x) or\n");
        printf("Feal -differentialattack key1 key2 [file number]\n");
        printf("or Feal -linearattack key1 key2 [file number]\n");
        return 1;
    }

    if(strcmp(av[1], "-test")==0) {
        sscanf(av[2],"%x", &key1);
        sscanf(av[3],"%x", &key2);
        sscanf(av[4],"%x", &in1);
        sscanf(av[5],"%x", &in2);
        test_encrypt(key1, key2, in1, in2);
        return 0;
    } else if(strcmp(av[1], "-linearattack")==0) {
        sscanf(av[2],"%x", &key1);
        sscanf(av[3],"%x", &key2);
        printf("Feal4 attack Key: %08x %08x\n\n", key1, key2);
        if(an < 5) {
            LinearAttack(key1, key2, 8, g_inBlock);
            return 0;
        }
        
        if((inFile= open(av[4], O_RDONLY))<0) {
            printf("Cant open: %s\n", av[4]);
            return 1;
        }
        if(inFile<0) {
            printf("Cant open %s\n", av[4]);
            return 1;
        }
#ifndef JLMUNIX
        setmode(inFile, _O_BINARY);
#endif
        if(an < 6) {
            iNumPairs= 8;
            }
        else {
            sscanf(av[5],"%d", &iNumPairs);
            }

        i= read(inFile, rgInBlock, 8*iNumPairs);
        close(inFile);
        if(i<0) {
            printf("Cant read %s\n", av[4]);
            return 1;
        }
        LinearAttack(key1, key2, iNumPairs, (unsigned*) rgInBlock);
        return 0;
    } else if(strcmp(av[1], "-differentialattack")==0) {
        sscanf(av[2],"%x", &key1);
        sscanf(av[3],"%x", &key2);
        printf("Feal4 attack Key: %08x %08x\n\n", key1, key2);
        if(an < 5) {
            DifferentialAttack(key1, key2, 8, g_inBlock);
            return 0;
        }
        
        if((inFile= open(av[4], O_RDONLY))<0) {
            printf("Cant open: %s\n", av[4]);
            return 1;
        }
        if(inFile<0) {
            printf("Cant open %s\n", av[4]);
            return 1;
        }
#ifndef JLMUNIX
        setmode(inFile, _O_BINARY);
#endif
        if(an<6) {
            iNumPairs= 8;
            }
        else {
            sscanf(av[5],"%d", &iNumPairs);
            }

        i= read(inFile, rgInBlock, 8*iNumPairs);
        close(inFile);
        if(i<0) {
            printf("Cant read %s\n", av[4]);
            return 1;
        }
        DifferentialAttack(key1, key2, iNumPairs, (unsigned*) rgInBlock);
        return 0;
    }
    else if(an<5) {
        printf("Feal key1(x) key2(x) in1(x) in2(x) or\n");
        return 1;
    }

    sscanf(av[1],"%x", &key1);
    sscanf(av[2],"%x", &key2);
    sscanf(av[3],"%x", &in1);
    sscanf(av[4],"%x", &in2);

    if(an>5) {
        if(strcmp(av[5], "-differential")==0) {
            fDoDifferential= true;
        }
    }

    in1d= in1^0x80800000;
    in2d= in2^0x80800000;

    printf("Feal4 Differential Key: %08x %08x\n\tInput1: %08x %08x, Input2: %08x %08x\n\n", 
            key1, key2, in1, in2, in1d, in2d);

    fillFromWord(key.Left, key1);
    fillFromWord(key.Right, key2);
    fillFromWord(in.Left, in1);
    fillFromWord(in.Right, in2);
    fillFromWord(ind.Left, in1d);
    fillFromWord(ind.Right, in2d);

    oFeal.KeyInit(key);
    oFeald.KeyInit(key);

    printf("RoundKeys:\n");
    for(j=1; j<7; j++) {
        sprintf(szLabel, "    Round %d: ", j);
        oFeal.GetRoundKey(j, t);
        printFour(szLabel, t);
        printf("\n");
    }
    printf("\n");

    oFeal.SetIn(in);
    oFeal.Encrypt();
    oFeal.GetIn(r);
    printf("\nEncrypt:\n");
    printState((char*)"in     : ", r);
    for(j=0; j<5; j++) {
        sprintf(szLabel, "Round %d: ", j);
        oFeal.GetRound(j, r);
        printState(szLabel, r);
    }
    oFeal.GetOut(r);
    printState((char*)"out:     ", r);
    printf("\n");

    oFeald.SetIn(ind);
    oFeald.Encrypt();
    oFeald.GetIn(r);
    printf("\nEncrypt:\n");
    printState((char*)"in     : ", r);
    for(j=0; j<5; j++) {
        sprintf(szLabel, "Round %d: ", j);
        oFeald.GetRound(j, r);
        printState(szLabel, r);
    }
    oFeald.GetOut(r);
    printState((char*)"out:     ", r);
    printf("\n");
    printf("\n");

    oFealDiff.CalcDiffs(oFeal, oFeald);
    sprintf(szLabel, "Input Difference  : "); 
    printState(szLabel, oFealDiff.In);
    sprintf(szLabel, "Output Difference : "); 
    printState(szLabel, oFealDiff.Out);
    for(i=0; i<5; i++) {
        sprintf(szLabel, "Round %d difference: ", i);
        printState(szLabel, oFealDiff.Rounds[i]); 
    }
    sprintf(szLabel, "    X'          : "); 
    printFour(szLabel, oFealDiff.XPrime); printf("\n");
    sprintf(szLabel, "    Y'          : "); 
    printFour(szLabel, oFealDiff.YPrime); printf("\n");
    sprintf(szLabel, "    Z'          : "); 
    printFour(szLabel, oFealDiff.ZPrime); printf("\n");

    if(!fDoDifferential) {
        printf("\ndone\n");
        return 0;
    }

    FourBytes tK;
    FourBytes y0;
    FourBytes y1;
    FourBytes z0;
    FourBytes z1;
    FourBytes zPrime;

    y0.XorandPut(oFeal.Out.Left, oFeal.Out.Right);
    y1.XorandPut(oFeald.Out.Left, oFeald.Out.Right);
    printf("Differential test\n");
    sprintf(szLabel, "    y0: "); printFour(szLabel, y0); printf("\n");
    sprintf(szLabel, "    y1: "); printFour(szLabel, y1); printf("\n");

    int  iLimit= 0;
    tK.Zero();
    while(!tK.Bump()) {
        oFeal.TestRound(z0, y0, tK);
        oFeald.TestRound(z1, y1, tK);
        zPrime.XorandPut(z0, z1);
        if(zPrime.Equal(oFealDiff.ZPrime)) {
            sprintf(szLabel, "Matching differential, key: ");
            printFour(szLabel, tK); printf("\n");
            sprintf(szLabel, "    z0: "); printFour(szLabel, z0); printf("\n");
            sprintf(szLabel, "    z1: "); printFour(szLabel, z1); printf("\n");
            iLimit++;
        }
    }

    printf("%d matching differentials\n", iLimit);
    printf("\ndone\n");
    return 0;
}


// ---------------------------------------------------------------------------------------



