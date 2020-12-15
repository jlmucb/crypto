// keyuse.c boolean key use values

/* ----------------------------------------------------------------------- */



struct {
	char tbits[56];
	} kround[16];


/* ----------------------------------------------------------------------- */


compkeys()

/*
 *	compute key schedule
 */

{
	int i, j, k, t;
	char tkey[64];

	for(i=0;i<64;i++)
		tkey[i]= i+1;
	permute(tkey,pc1,56,64);

	for(i=0;i<16;i++) {
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
	return;
}


/* ------------------------------------------------------------------------ */


main(argn,argv)

int argn;
char *argv[];

/*
 * bit use table
 */

{
	int i,j,k,n;
	short int k1[64], k2[64];


	compkeys();
	for(i=0;i<16;i++) {
		printf("\n\nKey schedule round %d\n",i+1);
		for(j=0;j<48;j++) {
			if((j%24)==0)
				printf("\n\t");
			printf("%2d ",kround[i].tbits[j]);
			}
		}

	printf("\n\nDone\n");
	for(i=1;i<=64;i++) {
		printf("\nbit %d: ",i);
		n= 0;
		for(j=0;j<16;j++)
		    for(k=0;k<48;k++)
			if(kround[j].tbits[k]==i) {
				printf("%d ",j+1);
				n++;
				}
		printf("\t\t   %d rounds",n);
		}
	printf("\n\nDone\n");
	printf("\n\nIntersection and Symmertic difference\n");
	for(i=0;i<16;i++) {
	    for(k=0;k<64;k++)
		k1[k]= 0;
	    for(k=0;k<48;k++)
		k1[kround[i].tbits[k]-1]= 1;
	    for(j=i+1;j<16;j++) {
		for(k=0;k<64;k++)
			k2[k]= 0;
		for(k=0;k<48;k++)
			k2[kround[j].tbits[k]-1]= 1;
		printf("\nRounds %d, %d, intersection\n",i+1,j+1);
		for(k=0;k<64;k++)
			if((k1[k]==1)&&(k2[k]==1))
				printf(" %2d", k+1);
		printf("\n\tsymmetric difference: ");
		for(k=0;k<64;k++)
			if(k1[k]!=k2[k])
				printf(" %2d",k+1);
		}
	    }
	printf("\n\nDone\n");
	exit();
}



/* ----------------------------------------------------------------------- */

