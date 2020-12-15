#include <stdio.h>
#include <string.h>
#include <io.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
extern "C" {
#include "deslib.h"
};


int main(int argn, char** argv)

//	Encode using DES as random stream generator

{
	int				i;
	int				iIn= 0;
	int				iOut= 0;
	unsigned		rguSeed[2]= {017722472025, 034716300336};
	unsigned		rguKey[2]=	{0, 0};
	unsigned char	rgbIn[8];
	unsigned char	rgbOut[8];
	unsigned		inblk[2], outblk[2];
	int				nb= 0;
	int				nTot= 0;
	char			szKey[16];
	unsigned char*	pubA= 0;

	if(argn<3) {
		printf("FwdEnc key input output\n");
		return(1);
		}

	rguKey[0]= 0;
	rguKey[1]= 0;

	strncpy(szKey, argv[1], 8);
	szKey[8]= 0;
	sscanf(szKey,"%x", &rguKey[0]);
	strncpy(szKey, argv[1]+8, 8);
	szKey[8]= 0;
	sscanf(szKey,"%x", &rguKey[1]);
	
	printf("FwdEnc Key: %08x %08x, Input: %s, Output: %s\n", 
		    rguKey[0], rguKey[1], argv[2], argv[3]);
	printf("FwdEnc Seed: %08x %08x\n", rguSeed[0], rguSeed[1]);

	if((iIn=_open(argv[2], _O_RDONLY | _O_BINARY))<0) {
		printf("\nCannot open %s quittting\n",argv[1]);
		return(1);
		}

	if((iOut=_open(argv[3], _O_WRONLY | _O_CREAT | _O_BINARY))<0)  {
		printf("\nCannot creat %s quitting\n",argv[3]);
		return(1);
		}

	compkeys((int*)rguKey);

	inblk[0]= rguSeed[0];
	inblk[1]= rguSeed[1];
	for(;;) {
		des((int*)inblk, (int*)outblk,0);	
		inblk[0]^= outblk[0];
		inblk[1]^= outblk[1];

		if((nb=read(iIn, rgbIn, 8))<=0)
			break;

		pubA= (unsigned char*) &outblk[0];
		for(i=0; i<nb; i++)
			rgbOut[i]= rgbIn[i]^*(pubA++);
		write(iOut, rgbOut, nb);
		nTot+= nb;
		}

	close(iIn);
	close(iOut);
	printf("Done %d bytes\n",nTot);
	return(0);
}


// -------------------------------------------------------------------------------


