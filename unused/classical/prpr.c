
/*
 *	prpr
 *		print des data with sbox values permuted to reflect usage in
 *		algorithm
 */

/* --------------------------------------------------------------------- */

main() 
{
	int i,j,k,m,n;

	printf("\n\n\t\tE\n");
	for(i=0;i<8;i++) {
		printf("\n\t");
		for(j=0;j<6;j++)
			printf("%2d ",eb[6*i+j]);
		}

	printf("\n\n\t\t\tP");
	for(i=0;i<2;i++) {
		printf("\n\n\t");
		for(j=1;j<=16;j++)
			printf("%2d ",i*16+j);
		printf("\n\t");
		for(j=0;j<16;j++)
			printf("%2d ",P[i*16+j]);
		}
	printf("\n\n\t\t\tIP");
	for(i=0;i<4;i++) {
		printf("\n\n\t");
		for(j=1;j<=16;j++)
			printf("%2d ",i*16+j);
		printf("\n\t");
		for(j=0;j<16;j++)
			printf("%2d ",ip[i*16+j]);
		}
	printf("\n\n\t\t\tIP inverse");
	for(i=0;i<4;i++) {
		printf("\n\n\t");
		for(j=1;j<=16;j++)
			printf("%2d ",i*16+j);
		printf("\n\t");
		for(j=0;j<16;j++)
			printf("%2d ",ipi[i*16+j]);
		}
		for(k=0;k<8;k++) {
			printf("\n\n\t\t\tS Box %d",k+1);
			for(i=0;i<4;i++) {
			printf("\n\t");
			for(j=0;j<16;j++) {
				n= i*16+j;
				m= (n&040)|((n<<4)&020)|((n>>1)&017);
				printf("%2d ",s[k*64+m]);
				}
			}
		}
	printf("\n\ndone\n");
	exit();
}

