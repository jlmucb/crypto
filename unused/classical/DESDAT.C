
/* -------------------------------------------------------------------- */

// desdat.c  --- print out desdata

#include "deslib.h"

/* --------------------------------------------------------------------- */


main()

{
	int i,j,k,m;
	char bi[100];

	printf("\nP[32]:\n\n");
	printmat(P,32);
	inver(P,bi,32);
	printf("\nP-1[32]:\n\n");
	printmat(bi,32);
	printf("\nIP[48]:\n\n");
	printmat(ip,48);
	inver(ip,bi,48);
	printf("\nIP-1[48]:\n\n");
	printmat(bi,48);
	exit();
}


/* ----------------------------------------------------------------------- */

