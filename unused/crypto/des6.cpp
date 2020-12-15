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

#include"BigCount.h"


//      des6.cpp
//      Differential cryptanalysis of 6 Round DES
//
//      John Manferdelli


typedef unsigned char byte;

class Round {
public:
    unsigned    uLeft, uRight;
    Round() {uLeft= 0; uRight= 0;};
};


unsigned uDiff1In=  0x02000000;
unsigned uDiff1Out= 0x40004010;


// ---------------------------------------------------------------------------------


//      DES data

byte ip[64]= {
    58,50,42,34,26,18,10, 2,60,52,44,36,28,20,12, 4,
    62,54,46,38,30,22,14, 6,64,56,48,40,32,24,16, 8,
    57,49,41,33,25,17, 9, 1,59,51,43,35,27,19,11, 3,
    61,53,45,37,29,21,13, 5,63,55,47,39,31,23,15, 7};
byte ipi[64]= {
    40, 8,48,16,56,24,64,32,39, 7,47,15,55,23,63,31,
    38, 6,46,14,54,22,62,30,37, 5,45,13,53,21,61,29,
    36, 4,44,12,52,20,60,28,35, 3,43,11,51,19,59,27,
    34, 2,42,10,50,18,58,26,33, 1,41, 9,49,17,57,25};
byte P[32]= {
    16, 7,20,21,29,12,28,17, 1,15,23,26, 5,18,31,10,
     2, 8,24,14,32,27, 3, 9,19,13,30, 6,22,11, 4,25};
byte eb[48]= {
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9,
     8, 9,10,11,12,13, 12,13,14,15,16,17,
    16,17,18,19,20,21, 20,21,22,23,24,25,
    24,25,26,27,28,29, 28,29,30,31,32,1 };

byte s[512]= {
    /* s1 */
    14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,
    0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
    4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,
    15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13,
    /* s2 */
    15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,
    3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
    0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,
    13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9,
    /* s3 */
    10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,
    13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
    13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,
    1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12,
    /* s4 */
    7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,
    13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
    10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,
    3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14,
    /* s5 */
    2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,
    14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
    4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,
    11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3,
    /* s6 */
    12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,
    10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
    9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,
    4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13,
    /* s7 */
    4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,
    13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
    1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,
    6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12,
    /* s8 */
    13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,
    1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
    7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,
    2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11};

byte pc1[64]= {
    57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,
    59,51,43,35,27,19,11,3,60,52,44,36,63,55,47,39,
    31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,
    29,21,13,5,28,20,12,4,1,1,1,1,1,1,1,1};

byte pc2[48]= {
    14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,
    26,8,16,7,27,20,13,2,41,52,31,37,47,55,30,40,
    51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32};

int krot[16]={1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};

unsigned short FastSbox[512];


// ----------------------------------------------------------------------- 


#define INDEXSIZE 64*16


int indexTab(short unsigned suIn, short unsigned suOut)
{
    int i= (int) (16*suIn+suOut);
    return i;
}


void initFastSbox(short unsigned f[512], byte s[512])
{
    unsigned uBox;
    unsigned u;

    for(uBox=0; uBox<8; uBox++) {
        for(u=0;u<64;u++) {
            f[uBox*64+u]= s[uBox*64+((((u>>4&0x2)|u&0x1)<<4)|((u>>1)&0xf))];
        }
    }
}


class SBoxDiffTable {
public:
    SBoxDiffTable();
    bool                m_fValid;
    int                 m_iBox;
    short unsigned*     m_pFirstEnt;
    int*                m_iNumDiffs;
    short unsigned**    m_rgpuDiff;

    bool                Calculate(int iBox, int iNumEntsAlloc, 
                                  int* piNumFilled, short unsigned* puLoc);
    void                printDiffTable(bool fFull=false);

};


class DESDiffTables {
public:
    DESDiffTables();
    bool                m_fValid;
    int                 m_iEntTabSize;
    short unsigned*     m_pEntTable;
    SBoxDiffTable*      m_rgBoxTable;
    bool                Init(int iNum);
};


void SBoxDiffTable::printDiffTable(bool fFull)
{
    int             i, j, k;
    short unsigned* psuDiff;
    long long unsigned u;

    printf("Sbox %d difference table\nin ", m_iBox);
    for(j=0;j<16;j++) {
       printf("  %x", j); 
    }
    printf(" out\n");

    for(i=0; i<64; i++) {
        printf("%02x ", i);
        for(j=0; j<16; j++) {
            printf(" %2d", m_iNumDiffs[indexTab(i,j)]);
        }
        printf("\n");
    }
    
    if(!fFull)
        return;

    for(i=0; i<64; i++) {
        for(j=0; j<16; j++) {
            k= m_iNumDiffs[indexTab(i,j)];
            printf("%02x-->%02x (%2d):", i, j, k);
            psuDiff=  m_rgpuDiff[indexTab(i,j)];
             while(k-- >0)
                 printf("%02x ", *(psuDiff++));
            //u= (long long unsigned) psuDiff;
            //printf("%08x\n", (unsigned)u);
        printf("\n");
        }
    }
    printf("\n");
}


bool SBoxDiffTable::Calculate(int iBox, int iNumEntsAlloc, int* piNumFilled, short unsigned* puLoc)
{
    unsigned short  t, inDiff, outDiff;
    short unsigned* pNext= puLoc;
    int             iUsed= 0;
    int             n;

    m_iBox= iBox+1;
    m_pFirstEnt= puLoc;
 
    try {
        m_iNumDiffs= new int[INDEXSIZE];
        m_rgpuDiff= new short unsigned* [INDEXSIZE];
    }
    catch(...) {
        return false;
    }
    
    for(inDiff=0; inDiff<64; inDiff++) {
        for(outDiff=0; outDiff<16; outDiff++) {
            n= 0;
            m_rgpuDiff[indexTab(inDiff, outDiff)]= pNext;
            for(t=0; t<64; t++) {
                if((FastSbox[iBox*64+(int)(t^inDiff)]^FastSbox[iBox*64+(int)(t)])==outDiff) {
                    if(iUsed++>iNumEntsAlloc)
                        return false;
                    *(pNext++)= t;
                    n++;
                 }
            }
            m_iNumDiffs[indexTab(inDiff,outDiff)]= n;
        }
    }

    *piNumFilled= iUsed;
    m_fValid= true;
    return true;
}


SBoxDiffTable::SBoxDiffTable() 
{
    m_fValid= false;
}


DESDiffTables::DESDiffTables()
{
    m_fValid= false;
}


bool DESDiffTables:: Init(int iTabSize)
{
    int             j;
    int             iEntLeft;
    int             iUsed;
    short unsigned* pFirst;

#ifdef DEBUGD
    printf("iTabSize: %d\n", iTabSize);
#endif
    initFastSbox(FastSbox,s);
    try {
        m_rgBoxTable= new SBoxDiffTable [8];
        m_pEntTable= new short unsigned [iTabSize];
    }
    catch(...) {
        return false;
    }
    pFirst= m_pEntTable;
    m_iEntTabSize= iTabSize;
    iEntLeft= iTabSize;

    for(j=0;j<8;j++) {
        if(!m_rgBoxTable[j].Calculate(j, iEntLeft, &iUsed, pFirst)) {
            printf("Too few table entries, cannot init difference table\n");
            return false;
        }
        pFirst+= iUsed;
        iEntLeft-= iUsed;
    }

#ifdef DEBUGD
    printf("iEntLeft: %d\n", iEntLeft);
#endif
    m_fValid= true;
    return true;
}


// ----------------------------------------------------------------------- 


void prbit(char* pstrText, byte* mat, int size, int iSizeBlock)

// pretty print block

{
    int i;

    printf((char*)"%s", pstrText);
    for(i=0;i<size;i++)
        if((i%iSizeBlock)==0)
            printf((char*)" %d", mat[i]);
        else
            printf((char*)"%d", mat[i]);
    return;
    }


int permute(byte bits[], byte perm[], int n, int m)

{
    int i;
    byte tmp[64];

    for(i=0;i<m;i++)
        tmp[i]= bits[i];

    for(i=0;i<n;i++)
        bits[i]= tmp[perm[i]-1];
    return(1);
}


int invert(byte a[], byte b[], int n)

{
    int i,j;

    for(i=0;i<n;i++) {
        j= a[i];
        b[j-1]= i+1;
        }
    return(1);
    }


void tobits(unsigned in, byte* out)

{
    int i;

    for(i=0;i<32;i++)  {
        out[31-i]= in&0x1;
        in>>= 1;
        }
    return;
}


void frbits(byte* in, unsigned* out)

{
    int i;

    for(i=0;i<32;i++) {
        *out<<=1;
        *out|= in[i];
        }

    return;
}


// --------------------------------------------------------------------


//      DES Algorithm


struct kr {
    byte tbits[56];
    } kround[16];



void sub(byte m1[], byte m2[], int box)

{
    int i,j,k;

    k= (m1[0]<<1)|m1[5];
    for(i=1;i<5;i++)
        k= (k<<1)|m1[i];

    j= s[64*box+k];
    for(i=3;i>=0;i--) {
        m2[i]= j&0x1;
        j>>= 1;
        }
    return;
}


void f(int ks, byte res[], byte inb[])

{
    int i;
    byte spare[48];

    for(i=0;i<32;i++)
        spare[i]= inb[i];
    permute(spare,eb,48,32);
    for(i=0;i<48;i++)  { 
        spare[i]+= kround[ks-1].tbits[i];
        spare[i]&= 0x1;
        }

    for(i=0;i<8;i++)
        sub(&spare[6*i],&res[4*i],i);

    permute(res,P,32,32);

    return;
}


void SingleBoxf(int box, byte ks[], byte res[], byte inb[])

{
    int i;
    byte spare[48];

    for(i=0;i<6;i++)  { 
        spare[i]= inb[i]^ks[i];
        spare[i]&= 0x1;
        }
    sub(&spare[0], &res[0], box);
    return;
}


// ------------------------------------------------------------------- 


void compkeys(unsigned key[2], bool fNoisy=false)
{
    int i, j, k, t;
    byte tkey[64];

    tobits(key[0],&tkey[0]);
    tobits(key[1],&tkey[32]);
    permute(tkey,pc1,56,64);

    for(i=0;i<6;i++) {
        for(t=0;t<krot[i];t++)
            for(j=0;j<27;j++) {
                k= tkey[j];
                tkey[j]= tkey[j+1];
                tkey[j+1]= k;
                k= tkey[j+28];
                tkey[j+28]= tkey[j+29];
                tkey[j+29]= k;
                }
        for(j=0;j<56;j++)
            kround[i].tbits[j]= tkey[j];
        permute(&kround[i].tbits[0],pc2,48,56);
        }

    if(fNoisy) {
        printf((char*)"Key schedule:\n");
        for(i=0; i<6;i++) {
            printf((char*)"  Round %d: ",i+1);
            prbit((char*)" ", &kround[i].tbits[0], 48, 6);
            printf((char*)"\n");
        }
    }

    return;
}


// ------------------------------------------------------------------------ 


unsigned rgExpectedIn[3]=  { 0x04000000, 0, 0x04000000 };
unsigned rgExpectedOut[3]= { 0x40080000, 0, 0x40080000 };



void Xor(byte* rgOut, byte* rg1, byte* rg2, int n)
{
    int i;

    for(i=0;i<n;i++)
        rgOut[i]= rg1[i]^rg2[i];
}


bool BitsEqual(byte* rb1, byte* rb2, int n)
{
    int     i;

    for(i=0; i<n;i++) {
        if(rb1[i]!=rb2[i])
            return false;
    }
    return true;
}


void GetDes6Diff(int in, char* szOut, unsigned* rgDiffIn, unsigned* rgDiffOut, bool fVeryNoisy=false) 
{
    int         i, j, k;
    int         nb= 0;
    int         nc= 0;
    unsigned    inblock[2];
    unsigned    inblock1[2], outblock1[2];
    unsigned    inblock2[2], outblock2[2];

    byte        FIn1Diff[32], FOut1Diff[32];
    byte        FIn2Diff[32], FOut2Diff[32];
    byte        FIn3Diff[32], FOut3Diff[32];
    
    byte*       rgInP[3]= { FIn1Diff, FIn2Diff, FIn3Diff};
    byte*       rgOutP[3]= { FOut1Diff, FOut2Diff, FOut3Diff};

    byte        kbits[64];

    byte        fout1[32]; 
    byte        dbits1[64];
    byte        fout2[32]; 
    byte        dbits2[64];

    byte        FOutDiff[32];
    byte        FInDiff[32];

    byte        iP[32];
    int         out;
    unsigned    inDiff[2]= {0x40080000, 0x04000000};
    bool        fMatch;


    printf("GetDesDiff called %s\n", szOut);
    if((out=creat(szOut,0666))<0)  {
        printf((char*)"Cannot creat %s quitting\n", szOut);
        return;
    }

    tobits(rgDiffIn[0], FIn1Diff);
    tobits(rgDiffOut[0], FOut1Diff);
    tobits(rgDiffIn[1], FIn2Diff);
    tobits(rgDiffOut[1], FOut2Diff);
    tobits(rgDiffIn[2], FIn3Diff);
    tobits(rgDiffOut[2], FOut3Diff);

    for(;;) {
        if(read(in,inblock,8)<8)
            break;
        nb++;

        inblock1[0]= inblock[0];
        inblock2[0]= inblock[0]^inDiff[0];
        inblock1[1]= inblock[1];
        inblock2[1]= inblock[1]^inDiff[1];
        printf("\tInput pair (%08x, %08x), (%08x, %08x)\n", 
                inblock1[0], inblock1[1], inblock2[0], inblock2[1]);

        // Do rounds, note last round is exceptional
        tobits(inblock1[0],&dbits1[0]);
        tobits(inblock1[1],&dbits1[32]);
        tobits(inblock2[0],&dbits2[0]);
        tobits(inblock2[1],&dbits2[32]);
        fMatch= true;
        for(i=1;i<=3;i++) {
            f(i, fout1, &dbits1[32]);
            f(i, fout2, &dbits2[32]);
            Xor(FOutDiff, fout1, fout2, 32);
            Xor(FInDiff, &dbits1[32], &dbits2[32], 32);
            for(j=0;j<32;j++) {
                k= dbits1[j];
                dbits1[j]= dbits1[32+j];
                dbits1[32+j]= (k^fout1[j])&0x1;
                k= dbits2[j];
                dbits2[j]= dbits2[32+j];
                dbits2[32+j]= (k^fout2[j])&0x1;
                }
            if(!BitsEqual(FInDiff, rgInP[i-1], 32) || !BitsEqual(FOutDiff, rgOutP[i-1], 32)) {
#if 0
                printf("\tFailed %d\n", i);
                prbit("Calculated in Diff: ", FInDiff, 32, 8);
                prbit(", Intended in Diff: ", rgInP[i-1], 32, 8);
                printf("\n");
                prbit("Calculated out Diff: ", FOutDiff, 32, 8);
                prbit(", Intended out Diff: ", rgOutP[i-1], 32, 8);
                printf("\n");
#endif
                fMatch= false;
                break;
            }
        }
        if(fMatch) {
            printf("Found valid pair %08x %08x\n", inblock[0], inblock[1]);
            write(out, &inblock[0], sizeof(unsigned));
            write(out, &inblock[1], sizeof(unsigned));
            nc++;
        }
    }

    printf((char*)"\n%d pairs analyzed, %d right pairs found.\n", nb, nc);
    close(out);
}


void des6(unsigned* input, unsigned* output, bool fReverse= false, bool fVeryNoisy=false) 
{
    int         i, j, k;
    byte        fout[32]; 
    byte        dbits[64];
    byte        kbits[64];

    // to internal
    tobits(input[0],&dbits[0]);
    tobits(input[1],&dbits[32]);
    if(fVeryNoisy) {
        prbit((char*)"\ninput: ", &dbits[0], 32, 8);
        prbit((char*)" ", &dbits[32], 32, 8);
        printf((char*)"\n");
    }

    // no initial permutation
    // permute(dbits,ip,64,64);

    // Do rounds, note last round is exceptional
    for(i=1;i<=6;i++) {
        if(!fReverse)
            f(i, fout, &dbits[32]);
        else
            f(7-i, fout, &dbits[32]);
        if(i!=6) {
            for(j=0;j<32;j++) {
                k= dbits[j];
                dbits[j]= dbits[32+j];
                dbits[32+j]= (k+fout[j])&0x1;
                }
        }
        else {
            for(j=0;j<32;j++)
                dbits[j]= (dbits[j]+fout[j])&0x1;
        }
        if(fVeryNoisy) {
            printf((char*)"Round %d:\n", i);
            prbit((char*)"\tf:", fout, 32, 8);
            printf((char*)"\n");
            prbit((char*)"\tresult:", &dbits[0], 32, 8);
            prbit((char*)"  ", &dbits[32], 32, 8);
            printf((char*)"\n");
        }
    }

    //  no final permutation
    //  permute(dbits,ipi,64,64);

    // pack back into 2 words
    frbits(&dbits[0],&output[0]);
    frbits(&dbits[32],&output[1]);
    if(fVeryNoisy) {
        prbit((char*)"output:", &dbits[0], 32, 8);
        prbit((char*)"  ", &dbits[32], 32, 8);
        printf((char*)"\n\n");
    }

    return;
}

void fillbits(byte* out, byte* in, int n)
{
    int     j;

    for(j=0;j<n;j++)
        out[j]= in[j];
}


void reportSKeys(char* szText, int* rgK, int iSize, bool fReportAll=false)
{
    int     i;
    int     max;

    max= rgK[0];
    for(i=1; i<iSize; i++) {
        if(rgK[i]>max)
            max= rgK[i];
    }

    printf("\n%s\n", szText);
    for(i=1; i<iSize; i++) {
        if(fReportAll || rgK[i]==max)
            printf("\tKey: %02x, count: %d\n", i, rgK[i]);
    }
}


void AnalyseDes6Diff(int in, DESDiffTables& oDiffTab, bool fReverse= false, bool 
                     fVeryNoisy=false, int iNum=16) 
//
//      Use two differentials
//              04000000-->40080000, p=1/4  --- S2, S5, S6, S7. S8 xors 0
//              04000000-->00200008, p=1/4  --- S1, S2, S4, S5, S6 xors are 0
//      Study f' --> F', f'= Cr', F'= Cl'+0x04000000+(D')[S2,S5,S,S7,S8]
{
    int         i, j, k;
    int         nb= 0;
    unsigned    inblock[2];

    unsigned    inblock1[2], outblock1[2];
    unsigned    inblock2[2], outblock2[2];
    unsigned    outputD[2];
    byte        iP[32];

    unsigned    inDiff1[2]= {0x40080000, 0x04000000};
    unsigned    inDiff2[2]= {0x00200008,0x04000000};
    unsigned    FPrime, fPrime, InvertedFPrime;

    byte        allSIn1[32];
    byte        allSIn2[32];
    byte        allSOut1[32];
    byte        allSOut2[32];
    byte        allSDiffIn[32];
    byte        allSDiffOut[32];
    byte        allExpandedInput[48];
    byte        allExpandedDiff[48];
    byte        SInvertedDifferential[32];
    byte        SelectedDiff[32];
    byte        SelectedInput[32];

    unsigned        aKey;
    unsigned        aDiff;
    unsigned        anInput;

    short unsigned  t2;
    short unsigned  t5;
    short unsigned  t6;
    short unsigned  t7;
    short unsigned  t8;

    short unsigned  suIn2;
    short unsigned  suOut2;
    short unsigned  suIn5;
    short unsigned  suOut5;
    short unsigned  suIn6;
    short unsigned  suOut6;
    short unsigned  suIn7;
    short unsigned  suOut7;
    short unsigned  suIn8;
    short unsigned  suOut8;

    short unsigned* psu2;
    short unsigned* psu5;
    short unsigned* psu6;
    short unsigned* psu7;
    short unsigned* psu8;

    int             ik2;
    int             ik5;
    int             ik6;
    int             ik7;
    int             ik8;
    int             n= 0;
    int             m= 0;
    int             max= 0;


#ifdef NEWCOUNT
    BigCount        oCK(32000);
#else
    int             rgiKey2Count[64], rgiKey5Count[64], rgiKey6Count[64], rgiKey7Count[64], rgiKey8Count[64];

    for(j=0;j<64;j++) {
        rgiKey2Count[j]= 0; 
        rgiKey5Count[j]= 0;
        rgiKey6Count[j]= 0;
        rgiKey7Count[j]= 0; 
        rgiKey8Count[j]= 0;
    }
#endif
    invert(P, iP, 32);

    for(;;) {

        if(nb>=iNum)
            break;
        if(read(in,inblock,8)<8)
            break;
        nb++;

        inblock1[0]= inblock[0];
        inblock2[0]= inblock[0]^inDiff1[0];
        inblock1[1]= inblock[1];
        inblock2[1]= inblock[1]^inDiff1[1];

        des6(inblock1, outblock1, false, fVeryNoisy);
        des6(inblock2, outblock2, false, fVeryNoisy);

        outputD[0]= outblock1[0]^outblock2[0];
        outputD[1]= outblock1[1]^outblock2[1];
        fPrime= outputD[1];
        FPrime= outputD[0]^inDiff1[1];  // correct in positions from S2, S5, S6, S7, S8

        printf((char*)"Des6 input (%08x %08x, %08x %08x), output(%08x %08x, %08x %08x)\n", 
                inblock1[0], inblock1[1], inblock2[0], inblock2[1],
                outblock1[0], outblock1[1], outblock2[0], outblock2[1]);
        printf((char*)"              using %08x --> %08x\n", fPrime, FPrime);

        tobits(outblock1[1], allSIn1);
        tobits(outblock2[1], allSIn2);
        tobits(FPrime, allSDiffOut);
        tobits(fPrime, allSDiffIn);

        for(j=0; j<32;j++) {
            SInvertedDifferential[j]= allSDiffOut[iP[j]-1];
        }
        for(j=0; j<48;j++) {
            allExpandedInput[j]= allSIn1[eb[j]-1];
            allExpandedDiff[j]= allSDiffIn[eb[j]-1];
        }

        // accumulate bits from S2,S5,S6,S7,S8
        // SelectedDiff[32];
        SelectedDiff[0]= 0;
        SelectedDiff[1]= 0;
        SelectedInput[0]= 0;
        SelectedInput[1]= 0;

        i= 2;
        // S2
        for(j=0;j<6;j++) {
            SelectedInput[i]= allExpandedInput[j+6];
            SelectedDiff[i++]= allExpandedDiff[j+6];
        }
        // S5
        for(j=0;j<6;j++) {
            SelectedInput[i]= allExpandedInput[j+24];
            SelectedDiff[i++]= allExpandedDiff[j+24];
        }
        // S6
        for(j=0;j<6;j++) {
            SelectedInput[i]= allExpandedInput[j+30];
            SelectedDiff[i++]= allExpandedDiff[j+30];
        }
        // S7
        for(j=0;j<6;j++) {
            SelectedInput[i]= allExpandedInput[j+36];
            SelectedDiff[i++]= allExpandedDiff[j+36];
        }
        // S8
        for(j=0;j<6;j++) {
            SelectedInput[i]= allExpandedInput[j+42];
            SelectedDiff[i++]= allExpandedDiff[j+42];
        }

        frbits(SInvertedDifferential, &InvertedFPrime);
        frbits(SelectedDiff, &aDiff);
        frbits(SelectedInput, &anInput);

        // Look up difference partners and xor input to get key candidates

        // S2
        suIn2=  (aDiff>>24)&0x3f;
        suOut2= (InvertedFPrime>>24)&0xf;
        ik2=    oDiffTab.m_rgBoxTable[1].m_iNumDiffs[indexTab(suIn2,suOut2)];
        psu2=   oDiffTab.m_rgBoxTable[1].m_rgpuDiff[indexTab(suIn2,suOut2)];

        // S5
        suIn5=  (aDiff>>18)&0x3f;
        suOut5= (InvertedFPrime>>12)&0xf;
        ik5=    oDiffTab.m_rgBoxTable[4].m_iNumDiffs[indexTab(suIn5,suOut5)];
        psu5=   oDiffTab.m_rgBoxTable[4].m_rgpuDiff[indexTab(suIn5,suOut5)];

        // S6
        suIn6=  (aDiff>>12)&0x3f;
        suOut6= (InvertedFPrime>>8)&0xf;
        ik6=    oDiffTab.m_rgBoxTable[5].m_iNumDiffs[indexTab(suIn6,suOut6)];
        psu6=   oDiffTab.m_rgBoxTable[5].m_rgpuDiff[indexTab(suIn6,suOut6)];

        // S7
        suIn7=  (aDiff>>6)&0x3f;
        suOut7= (InvertedFPrime>>4)&0xf;
        ik7=    oDiffTab.m_rgBoxTable[6].m_iNumDiffs[indexTab(suIn7,suOut7)];
        psu7=   oDiffTab.m_rgBoxTable[6].m_rgpuDiff[indexTab(suIn7,suOut7)];

        // S8
        suIn8=  aDiff&0x3f;
        suOut8= InvertedFPrime&0xf;
        ik8=    oDiffTab.m_rgBoxTable[7].m_iNumDiffs[indexTab(suIn8,suOut8)];
        psu8=   oDiffTab.m_rgBoxTable[7].m_rgpuDiff[indexTab(suIn8,suOut8)];

        // Definitely not a right pair
        if(ik2==0 || ik5==0 || ik6==0 || ik7==0 || ik8==0) {
            m++;
            continue;
            }

        if(fVeryNoisy) {
            printf("\nS2(%02x, %x), S5(%02x, %x), S6(%02x, %x), S7(%02x, %x), S8(%02x, %x)\n",
                    suIn2, suOut2, suIn5, suOut5, suIn6, suOut6, suIn7, suOut7, suIn8, suOut8);
            printf("InvertedFPrime: %08x aDiff: %08x anInput: %08x\n", InvertedFPrime, aDiff, anInput);
            printf("ik2: %d, ik5: %d, ik6: %d, ik7: %d, ik8: %d\n\n", ik2, ik5, ik6, ik7, ik8);
        }

        // Add candidate keys
        int     i2, i5, i6, i7, i8;
#ifdef NEWCOUNT
        for(i2=0; i2<ik2;i2++) {
          t2= *(psu2++);
          t2^= (anInput>>24)&0x3f;
          for(i5=0; i5<ik5; i5++) {
            t5= *(psu5++);
            t5^= (anInput>>18)&0x3f;
            for(i6=0; i6<ik6; i6++) {
              t6= *(psu6++);
              t6^= (anInput>>12)&0x3f;
              for(i7=0; i7<ik7; i7++) {
                t7= *(psu7++);
                t7^= (anInput>>6)&0x3f;
                for(i8=0; i8<ik8; i8++) {
                    t8= *(psu8++);
                    t8^= anInput&0x3f;
                    aKey= ((unsigned)t8) | (((unsigned)t7)<<6) | (((unsigned)t6)<<12) |
                          (((unsigned)t5)<<18) | (((unsigned)t2)<<24);
                    if(fVeryNoisy) {
                        printf("t2: %02x, t5: %02x, t6: %02x, t7: %02x, t8: %02x\n\n", t2, t5, t6, t7, t8);
                    }
                    oCK.AddEnt(aKey);
                    n++;
                }
              }
            }
          }
        }
#else
        for(i2=0; i2<ik2;i2++) {
            t2= *(psu2++);
            t2^= (anInput>>24)&0x3f;
            rgiKey2Count[t2]++; 
        }
        for(i5=0; i5<ik5; i5++) {
            t5= *(psu5++);
            t5^= (anInput>>18)&0x3f;
            rgiKey5Count[t5]++; 
        }
        for(i6=0; i6<ik6; i6++) {
            t6= *(psu6++);
            t6^= (anInput>>12)&0x3f;
            rgiKey6Count[t6]++; 
        }
        for(i7=0; i7<ik7; i7++) {
            t7= *(psu7++);
            t7^= (anInput>>6)&0x3f;
            rgiKey7Count[t7]++; 
        }
        for(i8=0; i8<ik8; i8++) {
            t8= *(psu8++);
            t8^= anInput&0x3f;
            rgiKey8Count[t8]++; 
        }
        n++;
#endif
    }

#ifdef NEWCOUNT
    // sort and count candidates
    oCK.Sort();

    max= oCK.m_pCounts[0].iCount;
    j= 0;
    while(j<oCK.m_iCountSize && max==oCK.m_pCounts[j].iCount) 
        j++;
    printf("\nCount entries: %d, %d have maximum count.\n",oCK.m_iCountSize,j);

    const int iNumOut= 32;
    if(j>iNumOut)
        k= j;
    else if(oCK.m_iCountSize<iNumOut)
        k= oCK.m_iCountSize;
    else
        k= iNumOut;

    for(i=0; i<k;i++) {
        printf("\tValue: %08x, count: %d\n", oCK.m_pCounts[i].uValue, oCK.m_pCounts[i].iCount);
    }
    printf((char*)"\n%d pairs analyzed, %d filtered, %d candidate keys counted.\n", nb, m, n);
#else
    reportSKeys("S2 Keys", rgiKey2Count, 64);
    reportSKeys("S5 Keys", rgiKey5Count, 64);
    reportSKeys("S6 Keys", rgiKey6Count, 64);
    reportSKeys("S7 Keys", rgiKey7Count, 64);
    reportSKeys("S8 Keys", rgiKey8Count, 64);
    printf((char*)"\n%d pairs analyzed, %d filtered, %d pairs used.\n", nb, m, n);
#endif

}


// ------------------------------------------------------------------- 


#ifdef COUNTTEST
#define COUNTTEST
unsigned  rgCT[]= { 
    4,2,6,8,2,5,7,9,1,2,4,5,6,6,6,0,3,5,5,7,2,1,0,5,
    4,2,6,8,2,5,7,9,1,2,4,5,6,6,6,0,3,5,5,7,2,1,0,5,
    4,2,6,8,2,5,7,9,1,2,4,5,6,6,6,0,3,5,5,7,2,1,0,5,
    4,2,6,8,2,5,7,9,1,2,4,5,6,6,6,0,3,5,5,7,2,1,0,5,
    4,2,6,8,2,5,7,9,1,2,4,5,6,6,6,0,3,5,5,7,2,1,0,5,
    4,2,6,8,2,5,7,9,1,2,4,5,6,6,6,0,3,5,5,7,2,1,0,5,
    4,2,6,8,2,5,7,9,1,2,4,5,6,6,6,0,3,5,5,7,2,1,0,5,
    4,2,6,8,2,5,7,9,1,2,4,5,6,6,6,0,3,5,5,7,2,1,0,5,
    4,2,6,8,2,5,7,9,1,2,4,5,6,6,6,0,3,5,5,7,2,1,0,5,
    4,2,6,8,2,5,7,9,1,2,4,5,6,6,6,0,3,5,5,7,2,1,0,5,
    4,2,6,8,2,5,7,9,1,2,4,5,6,6,6,0,3,5,5,7,2,1,0,5,
    4,2,6,8,2,5,7,9,1,2,4,5,6,6,6,0,3,5,5,7,2,1,0,5,
    4,2,6,8,2,5,7,9,1,2,4,5,6,6,6,0,3,5,5,7,2,1,0,5,
    4,2,6,8,2,5,7,9,1,2,4,5,6,6,6,0,3,5,5,7,2,1,0,5,
    4,2,6,8,2,5,7,9,1,2,4,5,6,6,6,0,3,5,5,7,2,1,0,5,
    4,2,6,8,2,5,7,9,1,2,4,5,6,6,6,0,3,5,5,7,2,1,0,5,
    4,2,6,8,2,5,7,9,1,2,4,5,6,6,6,0,3,5,5,7,2,1,0,5,
    4,2,6,8,2,5,7,9,1,2,4,5,6,6,6,0,3,5,5,7,2,1,0,5,
    4,2,6,8,2,5,7,9,1,2,4,5,6,6,6,0,3,5,5,7,2,1,0,5,
    4,2,6,8,2,5,7,9,1,2,4,5,6,6,6,0,3,5,5,7,2,1,0,5,
    4,2,6,8,2,5,7,9,1,2,4,5,6,6,6,0,3,5,5,7,2,1,0,5,
    4,2,6,8,2,5,7,9,1,2,4,5,6,6,6,0,3,5,5,7,2,1,0,5,
    4,2,6,8,2,5,7,9,1,2,4,5,6,6,6,0,3,5,5,7,2,1,0,5,
    4,2,6,8,2,5,7,9,1,2,4,5,6,6,6,0,3,5,5,7,2,1,0,5,
    4,2,6,8,2,5,7,9,1,2,4,5,6,6,6,0,3,5,5,7,2,1,0,5,
    4,2,6,8,2,5,7,9,1,2,4,5,6,6,6,0,3,5,5,7,2,1,0,5,
};


void CountTest()
{
    int             i, j, k, n;
    BigCount        oCK(32000);

    n= sizeof(rgCT)/4;
    printf("CountTest, %d entries\n", n);

    for(i=0;i<n;i++) {
        oCK.AddEnt(rgCT[i]);
    }
    printf("\n Before Sort\n");
    for(i=0;i<oCK.m_iNumEnts;i++) {
        printf("%2d ", oCK.m_pHead[i]);
        if((i%16)==15)
            printf("\n");
    }
    printf("\n");
    oCK.Sort();
    printf("\n After Sort\n");
    for(i=0;i<oCK.m_iNumEnts;i++) {
        printf("%2d ", oCK.m_pHead[i]);
        if((i%16)==15)
            printf("\n");
    }
    printf("\n");
    printf("\n Counts \n");
    for(i=0;i<oCK.m_iCountSize;i++) {
        printf("(%2d, %2d) ", oCK.m_pCounts[i].uValue, oCK.m_pCounts[i].iCount);
        if((i%8)==7)
            printf("\n");
    }
    printf("\n");
}
#endif



// ------------------------------------------------------------------- 


main(int argn, char** argv)

{
    int         i,j,k;
    unsigned    key[2];
    unsigned    inblock1[2], outblock1[2];
    unsigned    inblock2[2], outblock2[2];
    int         in, out;
    char*       szIn= NULL;
    char*       szOut= NULL;
    bool        fDoAttack= false;
    bool        fGetPairs= false;
    bool        fNoisy= false;
    bool        fVeryNoisy= false;
    int         iNum= 32;
    int         nb= 0;

    if(argn<2) {
        printf((char*)"des6 -DoAttack [-Num n] -k 01234567 89abcdef input\n");
        return 1;
    }

    key[0]= 0;
    key[1]= 0;

    for(i=1;i<argn;i++) {
        if(strcmp(argv[i],(char*)"-DoAttack")==0) {
            fDoAttack= true;
        }
        else if(strcmp(argv[i],(char*)"-GetPairs")==0) {
            fGetPairs= true;
        }
        else if(strcmp(argv[i],(char*)"-Noisy")==0) {
            fNoisy= true;
        }
        else if(strcmp(argv[i],(char*)"-k")==0) {
            if(argn<(i+2)) {
                printf((char*)"No key args, quitting %d\n",i);
                return 1;
            }
            sscanf(argv[i+1], (char*)"%x", &key[0]);
            sscanf(argv[i+2], (char*)"%x", &key[1]);
            i+= 2;
        }
        else if(strcmp(argv[i],(char*)"-Num")==0) {
            if(argn<(i+1)) {
                printf((char*)"No number of pairs specified, quitting\n");
                return 1;
            }
            sscanf(argv[i+1], (char*)"%d", &iNum);
            i+= 1;
        }
        else if(*argv[i]!='-') {
            if(argn<i) {
                printf((char*)"No input file specified, quitting\n");
                return 1;
            }
            szIn= argv[i];
            i+= 1;
            if(fGetPairs) {
                szOut= argv[i];
                i+= 1;
            }
        }
    }

    if(!fDoAttack && !fGetPairs) {
        printf((char*)"No action specified, quittting\n");
        return 1;
    }

    if(szIn==NULL) {
        printf((char*)"No input file, quittting\n");
        return 1;
    }

    if((in=open(szIn,0))<0) {
        printf((char*)"Cannot open %s quittting\n", szIn);
        return 1;
    }

    if(fGetPairs) {
        printf((char*)"des6, Input: %s, output: %s, Key: %08x%08x, %d trials\n\n", 
               szIn, szOut, key[0], key[1], iNum);
        compkeys(key, true); printf((char*)"\n");
        GetDes6Diff(in, szOut, rgExpectedIn, rgExpectedOut, true);
        close(in);
        return 0;
    }

    // Generate S different tables
    DESDiffTables oDiffTab;
    if(!oDiffTab.Init(64*10*64)) {
        printf("Init failed \n\n");
        return 1;
    }

#define TESTBOXGEN
#ifdef  TESTBOXGEN
    oDiffTab.m_rgBoxTable[1].printDiffTable(true);
    for(j=0;j<8; j++) {
        oDiffTab.m_rgBoxTable[j].printDiffTable();
        printf("\n\n");
    }
#endif

    if(fDoAttack) {
        printf((char*)"des6, Input: %s, Key: %08x%08x, %d trials\n\n", 
               szIn, key[0], key[1], iNum);
        compkeys(key, true); printf((char*)"\n");
        AnalyseDes6Diff(in, oDiffTab, false, fNoisy, iNum); 
        close(in);
    }

    return 0;
}


// ---------------------------------------------------------------------------------------


