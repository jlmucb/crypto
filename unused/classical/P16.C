#include <stdio.h>


double bcf[17]=
	{1.,16.,56.,560.,1820.,4032.,8008.,11440.,12870.,
	 11440.,8008.,4032.,1820.,560.,56.,16.,1};


main(argn,argv)

int argn;
char *argv[];

{
	int i,j,k,n;
	double p,x,y,z,w;

	printf("Probabalistic equations for DES\nCoefficients: ");
	for(i=0;i<17;i++)
		printf("%d:%4.1f, ", i, bcf[i]);
	printf("\np\tcombined\n");
	for(n=0;n<=argn;n++) {
		sscanf(argv[n],"%F\0",&p);
		if(p==0.0) {
			printf("probability is 0\n");
			continue;
			}
		x= 0.0;
		y= 1.0;
		for(i=0;i<16;i++)
			y*= p;
		z= 1.0;
		for(i=0;i<17;i+=2) {
			x+= bcf[i]*y*z;
			z*= (1.0-p)*(1.0-p);
			y/= p*p;
			}
		printf("%7.4f\t%7.4f\n",p,x);
		}
	printf("\n\ndone\n");
	exit();

}

