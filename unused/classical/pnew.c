#include <stdio.h>

// pnew.c
//		calculate proabilities from recurrence


main(argn,argv)

int argn;
char *argv[];

{
	int i,j,k,n;
	double p,q,pn,qn;

	printf("Probabalistic equations\n");
	printf("recurrence: pn= pn*p+qn*q, qn= 1-pn\n");
	for(n=1;n<argn;n++) {
		sscanf(argv[n],"%F\0",&p);
		for(k=2;k<64;k*=2) {
			q= 1.0-p;
			pn= 1.0;
			qn= 0;
			for(j=0;j<k;j++) {
				pn= pn*p+qn*q;
				qn= 1.0-pn;
				}
			printf("%d\t%7.4f\t%10.7f\n",k,p,pn);
			}
		}
	printf("\n\ndone\n");
	exit();

}

