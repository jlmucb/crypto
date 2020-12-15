#include <stdio.h>
#include <string.h>
#include <io.h>


// Heburn Cryptograph

// KC(i)R1C(-i)C(j)R2C(-j)C(k)R3C(-k)C(l)R4C(-l)C(m)R5C(-m)L=c

// rotors 2 and 4 don't turn
// rachet wheels on rotors 1 and 5, 5 turns fastest
// both toggle after n appears.

// To set:
//	1. Rotor Order
//	2. ratchet and rotor positions
//	3. direct/reverse

// Representation:

//  LR- left ratchet
//  RR- right ratchet
//  R1,...,R5 are 5 rotors

//  LR  R1  R2  R3  R4  R5  RR
//  m   e   a   n   i   n   g
//  m   e   a   n   i   o   h
//            ...
//  m   e   a   n   i   u   n
//  n   f   a   n   i   v   o
//  n   f   a   o   i   w   p


char *kba= "x a k h s z j l y w g p m i o u r d b f t n v c q e";	//	Keyboard
char *r1a= "g a d b o c t k n u z x  i w h f q y j v p m e l s r";  //	Rotor 1
char *r2a= "i z n c t k u d p j e v o w l f h x s m g q a y b r";	//	Rotor 2
char *r3a= "p jx f w l t a u g y b m h r o v n c k s e q i z d";	//	Rotor 3
char *r4a= "f l v a r g w c m q b x n y i o t j u p s k e d h z";	//	Rotor 4
char *r5a= "f q t g x a n w c j o i v z p h y b d r k u s l e m";	//	Rotor 5
char *lpa= "t y o e u m x d f j q v k w b n s h c i l r z a g p";	//	Lampboard




char kb[26],lp[26], kbi[26], lpi[26];
char r1i[26], r2i[26], r3i[26], r4i[26], r5i[26];
char r1[26], r2[26], r3[26], r4[26], r5[26];
char rotset[5], ratset[2];


#define NBUF 256
int in, out;
int nb={-1};
char buf[NBUF];
char *pc;



/* -----------------------------------------------------------------  */


int filalpha(char *s,char a[])

{
	int i;
	char  c;

	i= 0;
	while((c=*s)!=0) {
	    if((c>='a')&&(c<='z'))
	    	a[i++]= (char) (c-'a');
		s++;
		}
	return(1);
}


printwire(char *s,char a[])

{
	int i;

	printf("%s wires: ",s);
	for(i=0;i<26;i++)
		printf("%c ", a[i]+'a');
    printf("\n");
    return(1);
}


initmachine(int an,char *av[])

{
	int i;

    /* rotor and ratched settings */
	ratset[0]= *(av[1]);
	rotset[0]= *(av[1]+1);
	rotset[1]= *(av[1]+2);
	rotset[2]= *(av[1]+3);
	rotset[3]= *(av[1]+4);
	rotset[4]= *(av[1]+5);
	ratset[1]= *(av[1]+6);

   /* translate wirings */
	filalpha(kba,kb);
	filalpha(lpa,lp);
	filalpha(r1a,r1);
	filalpha(r2a,r2);
	filalpha(r3a,r3);
	filalpha(r4a,r4);
	filalpha(r5a,r5);

    /* take inverses */
	for(i=0;i<26;i++) {
		kbi[(int)kb[i]]= (char) i;
		lpi[(int)lp[i]]= (char) i;
		r1i[(int)r1[i]]= (char) i;
		r2i[(int)r2[i]]= (char) i;
		r3i[(int)r3[i]]= (char) i;
		r4i[(int)r4[i]]= (char) i;
		r5i[(int)r5[i]]= (char) i;
		}

	for(i=0;i<an;i++) {
		if(strcmp(av[i],"printwiring")==0) {
			printwire("KB",kb);
			printwire("KB(-1)",kbi);
			printwire("Lamp",lp);
			printwire("Lamp(-1)",lpi);
			printwire("R1",r1);
			printwire("R1(-1)",r1i);
			printwire("R2",r2);
			printwire("R2(-1)",r2i);
			printwire("R3",r3);
			printwire("R3(-1)",r3i);
			printwire("R4",r4);
			printwire("R4(-1)",r4i);
			printwire("R5",r5);
			printwire("R5(-1)",r5);
			break;
			}
		}
	return(1);
}


/* ----------------------------------------------------------------- */


int inlet()

{
	if(nb<=0) {
		if((nb=read(in,buf, NBUF))<=0)
			return(-1);
		pc= buf;
		}
	nb--;
	return((int)(*(pc++)));
}


int outlet(int n)

{
	char a;

	a= (char) n;
	write(out,&a,1);
	return(1);
}


initio(int an,char *av[])

{

	if((in=open(av[2],0))<0) {
		printf("Cant open input\n");
		exit(1);
		}
	if((out=creat(av[3],1))<0) {
		printf("Cant open output\n");
		exit(1);
		}

  	return(1);
}


/* -------------------------------------------------------------------- */


main(an,av)

int an;
char *av[];

{
	int direct, internal;
	int i,j,k,m,n;
	int rots1,rots2,rots3, rots4, rots5, ratsl, ratsr;
	int t1,t2,t3,t4,t5,t6,t7,t8,t9,t10;


    initio(an,av);
    initmachine(an,av);

	ratsl= ratset[0]-'a';
	ratsr= ratset[1]-'a';
	rots1= rotset[0]-'a';
	rots2= rotset[1]-'a';
	rots3= rotset[2]-'a';
	rots4= rotset[3]-'a';
	rots5= rotset[4]-'a';

	printf("ratchet settings %2d %2d, ratchet trips at position 14\n",ratsl,ratsr);
	printf("rotor settings %2d %2d %2d %2d %2d\n",rots1,rots2,rots3,rots4,rots5);

	direct= 0;
	for(i=0;i<an;i++)
		if(strcmp(av[i],"reverse")==0) {
			direct= 1;
			break;
			}

    internal= 0;
	for(i=0;i<an;i++)
		if(strcmp(av[i],"printstages")==0) {
			internal= 1;
			break;
			}

	if(direct==0) {

		printf("Encrypt (left to right)\n");

		while((i=inlet())>0) {

			if((i>=((int)'a'))&&(i<=((int)'z')))
				i-= 'a';
			else {
				outlet(i);
				continue;
				}

			// encryption: input i.
			t1= kb[i%26];							// after keyboard
			t2= (r1[(t1+rots1)%26]+26-rots1)%26;   	// after rotor 1
			t3= (r2[(t2+rots2)%26]+26-rots2)%26;	// after rotor 2
			t4= (r3[(t3+rots3)%26]+26-rots3)%26;	// after rotor 3
			t5= (r4[(t4+rots4)%26]+26-rots4)%26;	// after rotor 4
			t6= (r5[(t5+rots5)%26]+26-rots5)%26;	// after rotor 5
			t7= lp[t6];								// after lampboard

			if(internal>0)
				printf("%c %c %c %c %c %c %c %c\r\n",i+'a',t1+'a',
					t2+'a',t3+'a',t4+'a',t5+'a',t6+'a',t7+'a');

			// rotor motion
			rots5= (rots5+1)%26;
			if(ratsr==14) {
				if(ratsl==14)
					rots3= (rots3+1)%26;
				rots1= (rots1+1)%26;
				ratsl= (ratsl+1)%26;
				}
			ratsr= (ratsr+1)%26;

			outlet(t7+'a');
			}
        }
    else {

		printf("Decrypt(right to left)\n");

		while((i=inlet())>0) {

			if((i>=((int)'a'))&&(i<=((int)'z')))
				i-= 'a';
			else {
				outlet(i);
				continue;
				}

			// decryption: input i.
			t1= lpi[i%26];
			t2= (r5i[(t1+rots5)%26]+26-rots5)%26;
			t3= (r4i[(t2+rots4)%26]+26-rots4)%26;
			t4= (r3i[(t3+rots3)%26]+26-rots3)%26;
			t5= (r2i[(t4+rots2)%26]+26-rots2)%26;
			t6= (r1i[(t5+rots1)%26]+26-rots1)%26;
			t7= kbi[t6];
			t7= t2;			// special

			// rotor motion
			rots5= (rots5+1)%26;
			if(ratsr==14) {
				if(ratsl==14)
					rots3= (rots3+1)%26;
				rots1= (rots1+1)%26;
				ratsl= (ratsl+1)%26;
				}
			ratsr= (ratsr+1)%26;

			if(internal>0)
				printf("%c %c %c %c %c %c %c %c\r\n",i+'a',t1+'a',
					t2+'a',t3+'a',t4+'a',t5+'a',t6+'a',t7+'a');

			outlet(t7+'a');
			}
    	}
    close(in);
    close(out);
	exit(0);
	}

/* ---------------------------------------------------------------------- */