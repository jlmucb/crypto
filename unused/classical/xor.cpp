#include <stdio.h>
#include <io.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

const int s_iBufMax= 8192;
unsigned char g_bIn1[s_iBufMax];
unsigned char g_bIn2[s_iBufMax];
unsigned char g_bOut[s_iBufMax];


int main(int argn, char** argv)


/*
 *	xor random streams
 */

{
	int i;
	int iIn1= 0;
	int iIn2= 0;
	int iOut= 0;
	unsigned char* pb1= g_bIn1;
	unsigned char* pb2= g_bIn2;
	unsigned char* pb3= g_bOut;
	int nf= s_iBufMax;
	int nb= 0;
	int nTot= 0;

	if(argn<3) {
		printf("xor input1 input2 output\n");
		return(1);
		}
	
	printf("Xor Input1: %s, Input1: %s, Output: %s\n",
		argv[1],argv[2],argv[3]);

	if((iIn1=_open(argv[1], _O_RDONLY | _O_BINARY))<0) {
		printf("\nCannot open %s quittting\n",argv[1]);
		return(1);
		}
	if((iIn2=_open(argv[2], _O_RDONLY  | _O_BINARY))<0) {
		printf("\nCannot open %s quittting\n",argv[2]);
		return(1);
		}
	if((iOut=_open(argv[3], _O_WRONLY | _O_CREAT | _O_BINARY))<0)  {
		printf("\nCannot creat %s quitting\n",argv[3]);
		return(1);
		}

	for(;;) {
			
		if((nb=read(iIn1, g_bIn1, nf))<=0)
			break;

		if(read(iIn2, g_bIn2, nb)<nb) {
			printf("Not enough random Numbers\n");
			break;
			}
	
		pb1= g_bIn1;
		pb2= g_bIn2;
		pb3= g_bOut;

		for(i=0; i<nb;i++) {
			*(pb3++)= (*(pb1++))^(*(pb2++));
			}

		write(iOut, g_bOut, nb);

		nTot+= nb;
		}

	close(iIn1);
	close(iIn2);
	close(iOut);
	printf("Done %d bytes\n",nTot);
	return(0);
}
