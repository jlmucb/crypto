//
//	Implements OAEP
//

#include "oaep.h"
#include "inlrng.hxx"
#include "inlsha.hxx"

#define RANDURC 0x01
#define HASHSHA 0x02

//
//	For message, m,
//	Generate r - random.
//	Compute (rand(r)^m, r^Hash(rand(r)^m))
//	Block so top 2 bytes contain sizes



// -----------------------------------------------------------------


bool GetSeed(int iSize, byte* pbSeed)
{
	// call Mikes RNG
	// for now
	if(pbSeed==NULL)
		return(false);

	DWORD dwTick;
	dwTick= GetTickCount();
	int iRC4Offset= (dwTick*2731)%61;
	InlineRNG	oRc4(sizeof(DWORD),(byte*)dwTick);
	int j

	oRc4.Init();
	while(iRC4Offset-->0)
		oRc4.NextByte(pbSeed);

	while(iSize-->0)
		oRc4.NextByte(pbSeed++);

	return(true);
}


bool BlockOAEP(int iBlockSize, int iSizeIn, byte* pbIn, 
			   int* piOut, byte* pbOut, 
			   unsigned uHash, unsigned uRandGen)

{
	int		  iHashSize= 20;
	int		  iRandSize= 20;
	InlineRNG oRc4;
	InlineSha oSha;
	const int iSeedSize= 20;
	byte	  rgbSeed[iSeedSize];
	byte*	  pbTmp= _alloca(iSizeIn+oSha.DIGESTSIZE);
	byte	  bRNG;
	int		  j;
	short unsigned pu;
	
	if(uHash!=HASHSHA)
		return(false);
	if(uRandGen!=RANDURC)
		return(false);
	if(sizeof(unsigned short)!=2)
		return(false);  // should be assert

	int iOut= 0;
	int i= iBlockSize-2;

	iOut= (iSizeIn+i-1)/i;
	iOut*= iBlockSize*i;

	if(pbOut==NULL) {
		*piOut= iOut;
		return(true);
		}
	if(iOut>(*piOut))
		return(false);
	*piOut= iOut;

	if(!GetSeed(iSeedSize, rgbSeed))
		return(false);
	oRc4.Init(iSeedSize, rgbSeed);
	memcpy(pbTmp, pbIn, iSizeIn);
	for(j=0; j<iSizeIn; j++) {
		oRc4.NextByte(&bRNG);
		pbTmp[j]^= bRNG;
		}

	// hash it
	oSha.Init();
	oSha.Update(pbTmp, iSizeIn);
	oSha.Final(&pbTmp[iSizeIn]);
	for(j=0; j< ;j++)
		pbTmp[iSize+j]^= rgbSeed[j];

	// Block it
	int iLeft= iSizeIn+oSha.DIGESTSIZE;
	byte pbLeftNext= pbTmp;
	byte pbRightNext= pbOut;
	

	while(iLeft>0) {
		if(iLeft>= (iBlockSize-2))
			j= iBlockSize-2;
		else
			j= iLeft;
		memcpy(pbRightNext, pbLeft, j);
		pbLeft+= j;
		pbRightNext+= j;
		if(j<(iBlockSize-2)) {
			memset(pbRightNext, 0, iBlockSize-2-j);
			pbRightNext+= iBlockSize-2-j;
			}
		pu= (unsigned short *) pbRightNext;
		*pu= (unsigned) j;
		pbRightNext+= sizeof(unsigned short);
		iLeft-= j;
		}

	return(true);
	}


bool UnBlockOAEP(int iBlockSize, int iSizeIn, byte* pbIn, 
			     int* piOut, byte* pbOut, 
			     unsigned uHash, unsigned uRandGen)

{
	int		  iHashSize= 20;
	int		  iRandSize= 20;
	InlineRNG oRc4;
	InlineSha oSha;
	const int iSeedSize= 20;
	short unsigned pu;
	byte	  rgbSeed[iSeedSize];
	byte	  rgbHash[oSha.DIGESTSIZE];
	byte	  bRNG;
	int		  j;

	if(uHash!=HASHSHA)
		return(false);
	if(uRandGen!=RANDURC)
		return(false);
	if((iSizeIn%iBlockSize)!=0)
		return(false);
	if(sizeof(unsigned short)!=2)
		return(false);  // should be assert

	// get size
	int iOut= 0;
	for(j= 0; j<iSizeIn; j+=iBlockSize) {
		pu= (unsigned*) &pbIn[iBlockSize-2+j];
		iOut+= *pu;
		}
	iOut-= oSha.DIGESTSIZE;

	if(pbOut==NULL) {
		*piOut= iOut;
		return(true);
		}
	if(iOut>(*piOut))
		return(false);
	*piOut= iOut;

	// UnBlock it
	byte*	pbTmp= _alloca(iOut+oSha.DIGESTSIZE);
	int		iLeft= iSizeIn;
	byte	pbLeftNext= pbIn;
	byte	pbRightNext= pbTmp;
	
	while(iLeft>0) {
		pu= (unsigned short*) &pbLeftNext[iBlockSize-2];
		j= *pu;
		memcpy(pbRightNext, pbLeft, j);
		pbLeft+= j;
		pbRightNext+= iBlockSize;
		iLeft-= iBlockSize;
	}

	// hash it
	oSha.Init();
	oSha.Update(pbTmp, iOut);
	oSha.Final(&rgbHash);
	for(j=0; j<iSeedSize;j++)
		rgbSeed[j]= rgbHash[j]^pbTmp[iOut+j];

	// generate stream
	oRc4.Init(iSeedSize, rgbSeed);
	for(j=0; j<iOut; j++) {
		oRc4.NextByte(&bRNG);
		pbOut[j]= pbTmp[j]^bRNG;
		}

	return(true);
	}


// -----------------------------------------------------------------


