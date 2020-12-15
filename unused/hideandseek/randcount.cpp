#include <stdio.h>
#include <io.h>
#include <fcntl.h>

#ifndef byte
typedef unsigned char byte;
#endif


// -------------------------------------------------------------------------------------


void PrintBytes(char* szMsg, byte* pbData, int iSize)
{
  int i;

  printf("\t%s: ", szMsg);
  for (i= 0; i<iSize; i++) {
        printf("%02x", pbData[i]);
  }
  printf("\n");
  }


void PrintHex(char* strTitle, int iSize, byte* pb)
{
  int i;
  printf("%s\n", strTitle);
  for(i=0; i<iSize; i++) {
  if(i==16) {
  	iSize-= 16;
  	i= 0;
  	printf("\n");
  	}
  printf("%02x", *(pb++));
  }
  if(i>0)
  printf("\n");
  }



// -------------------------------------------------------------------------------------


const int  g_iInBufSize= 2048;
const int  g_iNumCountSize= 256;
int  		g_rgiBitTallies[g_iNumCountSize];
int  		g_rgiCounts[g_iNumCountSize];
byte  	g_rgInBuf[g_iInBufSize];


void SnapReport(int* rgiCount, int* rgiCountStore)
{
  int i;

  for(i=0; i<g_iNumCountSize; i++) {
  rgiCountStore[i]= rgiCount[i]-rgiCountStore[i];
  }
  }


void InitReport(int* rgiCount, int* rgiCountStore)
{
  int i;

  for(i=0; i<g_iNumCountSize; i++) {
  rgiCountStore[i]= rgiCount[i];
  }
  }


void zeroCount(int iSize, int* rgiTally)
{
  int i;

  for(i=0; i<iSize; i++)
  rgiTally[i]= 0;
  }


void InitBitTally(int* rgiBitTally)
{
  int i, j, k;

  for(i=0; i<g_iNumCountSize; i++) {
  j= 0;
  for(k=0; k<8; k++) {
  	if(((1<<k)&i)!=0)
  		j++;
  	}
  rgiBitTally[i]= j;
  }
  }


int bitTally(int* rgiCount, int* rgiBitTally)
{
  int i;
  int iCount= 0;

  for(i=0; i<g_iNumCountSize; i++) {
  iCount+= rgiCount[i]*rgiBitTally[i];
  }

  return(iCount);
  }


inline int NextByte(int iFile, int& iNumLeft, int& iCurrent, byte* rgbBuf)
{
  if(iNumLeft<=0) {
  if((iNumLeft=read(iFile, rgbBuf, g_iInBufSize))<=0)
  	return(-1);
  iCurrent= 0;
  }
  iNumLeft--;
  return((int) rgbBuf[iCurrent++]);
  }


// -------------------------------------------------------------------------------------


void PrintReport(int* rgiCount, bool fPrintCounts= true)
{
  int	i;
  int	iNumBytes= 0;
  int	iNumBits= 0;
  int	iNumOnBits= 0;
  doublexBitRatio= 0.0;
  doublexFreq= 0.0;
  doublexIC= 0.0;

  for(i=0; i<g_iNumCountSize; i++) {
  iNumBytes+= rgiCount[i];
  iNumBits+= 8*rgiCount[i];
  iNumOnBits+= rgiCount[i]*g_rgiBitTallies[i];
  }

  for(i=0; i<g_iNumCountSize; i++) {
  xFreq= ((double)rgiCount[i])/((double)iNumBytes);
  xIC+= xFreq*xFreq;		
  }


  if(fPrintCounts) {
  for(i=0; i<g_iNumCountSize; i++)
  	printf("%05d %05d\n", i, rgiCount[i]);
  }
  xBitRatio= ((double)iNumOnBits)/((double)iNumBits);
  printf("Bit Ratio: %8.4f, IC: %8.4f\n", xBitRatio, xIC);
  }


int main(int argn, char** argv)

{
  int iInFile= 0;
  intiNumLeft= 0;
  intiCurrent= 0;
  int iNumBytes= 0;
  int j;

  if(argn<2) {
  printf("hide input, no input file\n");
  return(1);
  }
  if((iInFile=_open(argv[1], _O_RDONLY | _O_BINARY))<0) {
  printf("\nCannot open %s quittting\n",argv[1]);
  return(1);
  }
  printf("File: %s\n", argv[1]);

  zeroCount(g_iNumCountSize, g_rgiCounts);
  InitBitTally(g_rgiBitTallies);

  while((j=NextByte(iInFile, iNumLeft, iCurrent, g_rgInBuf))>=0) {
  g_rgiCounts[j]++;
  }
  
  PrintReport(g_rgiCounts);
  close(iInFile);
  return(0);
}



// -------------------------------------------------------------------------------------


