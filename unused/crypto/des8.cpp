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



//      des8.cpp
//      Differential cryptanalysis of 8 Round DES


typedef unsigned char byte;

class Round {
public:
    unsigned    uLeft, uRight;
    Round() {uLeft= 0; uRight= 0;};
};


unsigned uDiff1In=  0x02000000;
unsigned uDiff1Out= 0x40004010;
unsigned uDiff2In=  0x000006c0;
unsigned uDiff2Out= 0x02000000;


// ------------------------------------------------------------------------------------------------------------


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


unsigned rgExpectedDiffs[5]= {0x40004010, 0x02000000,0,0x02000000, 0x40004010};


void des8Diff(unsigned* input, unsigned* inDiff, unsigned* outputD, bool fReverse= false, bool fVeryNoisy=false) 
{
    int         i, j, k;
    unsigned    input1[2], input2[2], output1[2], output2[2];
    unsigned    inputD[2];
    byte        kbits[64];
    byte        fout1[32]; 
    byte        dbits1[64];
    byte        fout2[32]; 
    byte        dbits2[64];
    byte        foutD[32]; 
    byte        dbitsD[64];
    unsigned    fDiff, rDiff[2];


    input1[0]= input[0];
    input1[1]= input[1];
    input2[0]= input[0]^inDiff[0];
    input2[1]= input[1]^inDiff[1];
    inputD[0]= input1[0]^input2[0];
    inputD[1]= input1[1]^input2[1];

    // to internal
    tobits(input1[0],&dbits1[0]);
    tobits(input1[1],&dbits1[32]);
    tobits(input2[0],&dbits2[0]);
    tobits(input2[1],&dbits2[32]);
    tobits(inputD[0],&dbitsD[0]);
    tobits(inputD[1],&dbitsD[32]);


    if(fVeryNoisy) {
        printf((char*)"InDiff: %08x %08x\n", inputD[0], inputD[1]);
    }

    // Do rounds, note last round is exceptional
    for(i=1;i<=5;i++) {
        if(!fReverse) {
            f(i, fout1, &dbits1[32]);
            f(i, fout2, &dbits2[32]);
        }
        else {
            f(6-i, fout1, &dbits1[32]);
            f(6-i, fout2, &dbits2[32]);
        }
        if(i!=5) {
            for(j=0;j<32;j++) {
                k= dbits1[j];
                dbits1[j]= dbits1[32+j];
                dbits1[32+j]= (k+fout1[j])&0x1;
            
                k= dbits2[j];
                dbits2[j]= dbits2[32+j];
                dbits2[32+j]= (k+fout2[j])&0x1;

                foutD[j]= fout1[j]^fout2[j];
                }
        }
        else {
            for(j=0;j<32;j++) {
                dbits1[j]= (dbits1[j]+fout1[j])&0x1;
                dbits2[j]= (dbits2[j]+fout2[j])&0x1;

                foutD[j]= fout1[j]^fout2[j];
            }
        }
        
        for(j=0;j<64;j++) {
            dbitsD[j]= dbits1[j]^dbits2[j];
        }

        if(fVeryNoisy) {

            frbits(&foutD[0], &fDiff);
            frbits(&dbitsD[0], &rDiff[0]);
            frbits(&dbitsD[32], &rDiff[1]);
        }
        if(fVeryNoisy) {
            printf((char*)"  Round %d, fDiff: %08x, rDiff: %08x %08x\n", i, fDiff, rDiff[0], rDiff[1]);
        }
    }

    // pack back into 2 words
    frbits(&dbitsD[0], &outputD[0]);
    frbits(&dbitsD[32] ,&outputD[1]);

    if(fVeryNoisy) {
        printf((char*)"OutDiff: %08x %08x\n\n", outputD[0], outputD[1]);
    }

    return;
}


void des8(unsigned* input, unsigned* output, bool fReverse= false, bool fVeryNoisy=false) 
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
    for(i=1;i<=5;i++) {
        if(!fReverse)
            f(i, fout, &dbits[32]);
        else
            f(6-i, fout, &dbits[32]);
        if(i!=5) {
            for(j=0;j<32;j++) {
                k=dbits[j];
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


void AnalyseDes8Diff(int in, unsigned* inDiff, unsigned* outDiff, bool fReverse= false, bool fVeryNoisy=false) 
{
    int         i, j, k;
    int         nb= 0;
    unsigned    inblock[2], outputD[2];
    unsigned    inblock1[2], outblock1[2];
    unsigned    inblock2[2], outblock2[2];
    byte        S2In1[32];
    byte        S2In2[32];
    byte        bKey[32];
    byte        result1[32];
    byte        result2[32];
    byte        resultD[32];
    byte        bOut[32];
    byte        cmpres[32];
    byte        iP[32];
    unsigned    tkey;
    int         iKey[64];
    unsigned    uMask;
    bool        fMatch;
    unsigned    t;
    int         max;

    tobits(outDiff[0], bOut);

    invert(P, iP, 32);
    for(j=0;j<4;j++) {
        cmpres[j]= bOut[iP[j+4]-1];
    }
    for(j=4;j<32;j++) {
        cmpres[j]= 0;
    }

    if(fVeryNoisy) {
        prbit((char*)"cmpres: ", cmpres, 4, 6); prbit((char*)",  bOut: ", bOut, 32, 8);  printf((char*)"\n");
    }

    for(j=0;j<64;j++) {
        iKey[j]= 0;
    }

    for(;;) {
        if(read(in,inblock,8)<8)
            break;
        nb++;

        inblock1[0]= inblock[0];
        inblock2[0]= inblock[0]^inDiff[0];
        inblock1[1]= inblock[1];
        inblock2[1]= inblock[1]^inDiff[1];

        des8(inblock1, outblock1, false, false);
        des8(inblock2, outblock2, false, false);

        outputD[0]= outblock1[0]^outblock2[0];
        outputD[1]= outblock1[1]^outblock2[1];

        printf((char*)"\nRight pair -  input (%08x %08x, %08x %08x), output(%08x %08x, %08x %08x)\n", 
                inblock1[0], inblock1[1], inblock2[0], inblock2[1],
                outblock1[0], outblock1[1], outblock2[0], outblock2[1]);
        printf((char*)"              output difference: %08x %08x\n", outputD[0], outputD[1]);
                
                

        // try keys to see if the output differential holds
        for(tkey=0; tkey<64; tkey++) {

            t= tkey;
            for(j=0;j<6;j++) {
                bKey[5-j]= t&0x1;
                t>>= 1;
            }

            // S2Input comes from bits 4,5,6,7,8,9 of right hand word
            uMask= 0x10000000;
            for(j=0;j<6;j++) {
                S2In1[j]= (outblock1[1]&uMask)!=0?1:0;
                S2In2[j]= (outblock2[1]&uMask)!=0?1:0;
                uMask>>= 1;
            }

            SingleBoxf(1, bKey, result1, S2In1);
            SingleBoxf(1, bKey, result2, S2In2);


            fMatch= true;
            for(j=0;j<4;j++) {
                resultD[j]= result1[j]^result2[j];
                if(resultD[j]!=cmpres[j]) {
                    fMatch= false;
                    // break;
                }
            }

            if(fVeryNoisy) {
                prbit((char*)"  bKey:", bKey, 6, 8); prbit((char*)", S2In1:", S2In1, 6, 8); prbit((char*)", result1:", result1, 4, 6);  
                prbit((char*)", S2In2:", S2In2, 6, 8); prbit((char*)", result2:", result2, 4, 6); prbit((char*)", resultD:", resultD, 4, 6);
                printf((char*)"\n");
            }

            if(fMatch) {
                iKey[tkey]++;
            }
        }
    }

    printf((char*)"\n");
    max= 0;
    for(j=0;j<64;j++) {
        if(iKey[j]>max)
            max= iKey[j];
    }
    printf((char*)"Potential keys:\n");
    for(j=0;j<64;j++) {
        if(iKey[j]==max)
            printf((char*)"      %02x, %d\n", j, iKey[j]);
    }

    printf((char*)"\n%d right pairs analyzed.\n", nb);
}


main(int argn, char** argv)

{
    int         i,j,k;
    unsigned    key[2];
    unsigned    inblock1[2], outblock1[2];
    unsigned    inblock2[2], outblock2[2];
    unsigned    inDiff[2], outDiff[2];
    unsigned    outputD[2];
    int         in, out;
    char*       szIn= NULL;
    char*       szOut= NULL;
    bool        fGenRight= false;
    bool        fDoAttack= false;
    bool        fNoisy= false;
    bool        fVeryNoisy= false;
    int         iNumRight= 5;
    int         iNumPairs= 0;
    Round       rgRightPair[64];
    int         nb= 0;

    if(argn<2) {
        printf((char*)"des8 [-GenRight|-DoAttack] [-NumRight n] -k 01234567 89abcdef input output\n");
        return 1;
    }

    inDiff[0]=  0x400046d0;
    inDiff[1]=  0x02000000;
    outDiff[0]= 0x400046d0;
    outDiff[1]= 0x02000000;

    key[0]= 0;
    key[1]= 0;

    for(i=1;i<argn;i++) {

        if(strcmp(argv[i],(char*)"-GenRight")==0) {
            fGenRight= true;
        }
        else if(strcmp(argv[i],(char*)"-DoAttack")==0) {
            fDoAttack= true;
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
        else if(strcmp(argv[i],(char*)"-NumRight")==0) {
            if(argn<(i+1)) {
                printf((char*)"No number of pairs specified, quitting\n");
                return 1;
            }
            sscanf(argv[i+1], (char*)"%d", &iNumRight);
            i+= 1;
        }
        else if(*argv[i]!='-') {
            if(argn<i) {
                printf((char*)"No input file specified, quitting\n");
                return 1;
            }
            szIn= argv[i];
            i+= 1;
            if(fGenRight) {
                if(argn<i) {
                    printf((char*)"No output file specified, quitting\n");
                    return 1;
                }
                szOut= argv[i];
                i+= 1;
            }
        }
    }


    if(!fGenRight && !fDoAttack) {
        printf((char*)"No action specified, quittting\n");
        return 1;
    }


    // Generate sufficient number of right pairs
    if(fGenRight) {

        if(szIn==NULL) {
            printf((char*)"No input file, quittting\n");
            return 1;
        }
        if(szOut==NULL) {
            printf((char*)"No output file, quittting\n");
            return 1;
        }

        if((in=open(szIn,0))<0) {
            printf((char*)"Cannot open %s quittting\n", szIn);
            return 1;
        }
        if((out=creat(szOut,0666))<0)  {
            printf((char*)"Cannot creat %s quitting\n", szOut);
            close(in);
            return 1;
        }

        printf((char*)"des8, Generating right pairs, Input: %s, Output: %s, Key: %08x%08x\n\n", szIn, szOut, key[0], key[1]);

        compkeys(key, true); printf((char*)"\n");

        for(;;) {

            if(read(in,inblock1,8)<8)
                break;
            nb++;

            des8Diff(inblock1, inDiff, outputD, false, fVeryNoisy);

            if(fNoisy) {
                printf((char*)"In 1: %08x %08x, inDiff: %08x, %08x, OutDiff: %08x %08x\n", inblock1[0], inblock1[1], 
                        inDiff[0], inDiff[1], outputD[0], outputD[1]);
            }

            if((outputD[0]==outDiff[0]) && (outputD[1]==outDiff[1])) {
                printf((char*)"Got right pair: %08x %08x\n", inblock1[0], inblock1[1]);
                write(out, inblock1, 8);
                iNumPairs++;
                if(iNumPairs>=iNumRight)
                    break;
            }
        }

        close(in);
        close(out);
        printf((char*)"\n");
        printf((char*)"Found %d pairs, %d inputs tried\n", iNumPairs, nb);
    } 


    // Use right keys to find key in round 8
    if(fDoAttack) {

        if(szIn==NULL) {
            printf((char*)"No input file, quittting\n");
            return 1;
        }

        if((in=open(szIn,0))<0) {
            printf((char*)"Cannot open %s quittting\n", szIn);
            return 1;
        }

        printf((char*)"des8, Analyzing right pairs, Input: %s, Key: %08x%08x\n\n", szIn, key[0], key[1]);

        compkeys(key, true); printf((char*)"\n");

        AnalyseDes8Diff(in, inDiff, outDiff, false, fVeryNoisy); 

        close(in);
    }

    return 0;
}


// ---------------------------------------------------------------------------------------------------------------


