#include <stdio.h>
#include <io.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>


// search dict

#define INBUFSIZE   4096
#define OUTBUFSIZE  2048

int     iInSize= 0;
int     iCurinPos= 0;
int     iTotalBytesInBuf= 0;
int     iNumWords= 0;

char    rginBuf[OUTBUFSIZE];
char    rglineBuf[INBUFSIZE];

#define READFLAGS  _O_RDONLY | _O_BINARY
#define CREATFLAGS _O_CREAT | _O_BINARY

#ifndef byte
typedef unsigned char byte;
#endif


// --------------------------------------------------------------------- 


inline bool whitespace(char b)
{
    return(b==' ' || b=='\t' || b=='\r' || b=='\n');
}


inline bool validHex(char b)
{
    if(b>='0' && b<='9')
        return true;
    if(b>='a' && b<='f')
        return true;
    if(b>='A' && b<='F')
        return true;
    return false;
}


int getLine(int inFile)
{
    int     iLineSize= 0;

    for(;;) {
        if(iCurinPos>=iTotalBytesInBuf) {
            iTotalBytesInBuf= read(inFile, rginBuf, INBUFSIZE);
            if(iTotalBytesInBuf<=0)
                return -1;
            iCurinPos= 0;
        }
        rglineBuf[iLineSize++]= rginBuf[iCurinPos++];
        if(rglineBuf[iLineSize-1]=='\n') {
            rglineBuf[--iLineSize]= '\0';
            return iLineSize;
        }
    }
}


#define SIZEPATTERN 64


bool matchpattern(byte* szWord, int iLen, byte* rgMatch, int iPLen)
{
    byte        rgMatchMat[26];
    byte        a, b, c;

    if(iLen!=iPLen)
        return false;

    memset((void*)rgMatchMat, 0, 26);

    for(int i=0; i<iLen; i++) {
        a= szWord[i];
        b= rgMatch[i];

        if((b>='a')&&(b<='z')) {
            if(a==b)
                continue;
            return false;
        }
        if((b<'A')&&(b>'Z'))
            return false;

        c= rgMatchMat[b-'A'];
        if(c>0) {
            if((c-1)!=(a-'A'))
                return false;
            else
                continue;
        }
        c= a-'A'+1;
        rgMatchMat[b-'A']= c;
    }

    return true;
}


int parsePattern(char* szP, byte* rgP)
{
    for(int i=0;;i++) {
        rgP[i]= szP[i];
        if(szP[i]=='\0')
            return i;
    }

    return 0;
}


int main(int an, char** av)

{
        int         iIn;
        char*       szinFile=  NULL;
        char*       szPattern= NULL;
        int         iPLen= 0;
        byte        rgProtoPattern[SIZEPATTERN];
        int         iLen= 0;

        if(an<3) {
            printf("searchdict inFile pattern\n");
            return 1;
        }
        szinFile=  av[1];
        szPattern= av[2];

        iPLen= parsePattern(szPattern, rgProtoPattern);
        if(iPLen<=0) {
            printf("No pattern\n");
            return 1;
        }

        if((iIn=_open(szinFile, READFLAGS))<0) {
                printf("Cant open %s\n", szinFile);
                return 1;
                }

        while((iLen=getLine(iIn))>=0) {
            if(matchpattern((byte*) rglineBuf, iLen, rgProtoPattern, iPLen))
                printf("%s\n", rglineBuf);
            iNumWords++;
        }

        close(iIn);
        printf("%d words examined\n", iNumWords);

        return 0;
}


// --------------------------------------------------------------------- 


