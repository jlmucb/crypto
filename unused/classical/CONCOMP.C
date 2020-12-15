#define NOBITS 64
#define NFREE 1000
#define NCONS 300
#define NULL 0


struct list {
        int no;
        struct list *next;
        };

struct list *bitptr[NOBITS];
struct list freel[NFREE];
int nfree={0};

short int component[NOBITS];

short int cons[NCONS];


/* -------------------------------------------------------------------- */


markremove(bits,comp)

int bits,comp;

{
        int i;
#ifdef DEBUG
        printf("markremove(%d,%d)\n",bits,comp);
#endif

        if(bitptr[bits]==NULL)
                return;
        component[(i=(bitptr[bits]->no))]= comp;
        bitptr[bits]= bitptr[bits]->next;
        markremove(bits,comp);
        markremove(i,comp);
        return;
}



/* -------------------------------------------------------------------- */

# define EOF 0
# define USYM 1
# define UNUM 2
# define EQUAL 3
# define MINUS 4
# define LP 5
# define RP 6
# define COMMA 7
# define COLON 8
# define ARROW 9
# define UNK 20

#define TBUF 100
#define IOBUF 3072


/* --------------------------------------------------------------------- */


int line={1};
int errors={0};
int infile,tokenl;
char tokenc[TBUF];


getrc()

/*
 *      Get next real character strips comments.
 */

{
        char c;

        if((c=getc())=='#') {
                for(;;) {
                        if((c=getc())=='\n')
                                break;
                        if(c==NULL)
                                return(NULL);
                        }
                return(getrc());
                }
        return(c);
}

char buf[IOBUF];
int nl={0};
char *cp;

getc()

/*
 *      Gets a character, maintains character buffer.
 */

{
        if(nl<=0)
                if((nl=read(infile,buf,IOBUF))<=0)
                        return(NULL);
                else
                        cp= buf;
        nl--;
        if(*cp=='\n')
                line++;

        return(*(cp++));
}


ungetc()
{
        nl++;
        if(*cp=='\n')
                line--;
        cp--;
        return;
}


/* ---------------------------------------------------------------------- */
#define WSPACE ((c==' ')||(c=='\t')||(c=='\n'))


yylex()

{
        char c;
        int i;

        for(;;)
                if((c=getrc())==NULL)
                        return(EOF);
                else if(!WSPACE)
                        break;
        if(tokes(c)==1) {
                tokenc[0]= c;
                tokenl= 1;
                for(;;)  {
                        if((c=getrc())<=0)
                                return(0);
                        if(tokes(c)==1)
                                tokenc[tokenl++]= c;
                        else {
                                ungetc();
                                if(((tokenc[0]>='0')&&(tokenc[0]<='9'))||(tokenc[0]=='.'))
                                        return(UNUM);
                                return(USYM);
                                }
                        }
                }
        switch(c) {
          default:
                return(UNK);
          case '=':
                return(EQUAL);
          case '(':
                return(LP);
          case ')':
                return(RP);
          case ',':
                return(COMMA);
          case ':':
                return(COLON);
          case '-':
                return(MINUS);
          case '>':
                return(ARROW);
          }
}


tokes(c)

char c;

{
        if((c>='A')&&(c<='Z'))
                return(1);
        if((c>='a')&&(c<='z'))
                return(1);
        if((c>='0')&&(c<='9'))
                return(1);
        switch(c) {
          default:
                return(0);
          case '_':
          case '.':
          case '%':
          case '$':
                return(1);
          }
}

 /* ---------------------------------------------------------------------- */


tonum(radix,pt,dig)

int radix;
char *pt;
int dig;

{
        int j,k;

        j= 0;
        while(dig-->0) {

            k= *(pt++)-'0';
            if((k<0)||(k>=radix)) {
                printf("\nError %d, bad numeric (%d) line %d",++errors,k,line);
                return(0);
                }
            j= j*radix+k;
            }
        return(j);
}


short int keylist[48*16];


getklist()


{
        int i,j;

        for(i=0;i<(48*16);i++)
                if(yylex()!=UNUM)
                        printf("Bad format in keylist\n");
                else
                        keylist[i]= tonum(10,tokenc,tokenl);
        return;
}


getconnlist()


{
        int i,j;

        j=0;
        while(yylex()==UNUM) {
                cons[j++]= tonum(10,tokenc,tokenl);
                }
        return(j);
}


makeadjac(n)


int n;

{
        int i,j,k,m;

        nfree= 0;
        for(i=0;i<NOBITS;i++)
                bitptr[i]= NULL;
        for(i=0;i<(n/2);i++) {
                j= 48*(cons[2*i]-1);
                k= 48*(cons[2*i+1]-1);
                for(m=0;m<48;m++)
                        addedge(keylist[j+m]-1,keylist[k+m]-1);
                }
        
        return;
}


addedge(a,b)

int a,b;

{
        struct list *p;
#ifdef DEBUG
        printf("addedge(%d,%d)\n",a,b);
#endif

        if(nfree>=NFREE) {
                printf("Bad freelist, quitting\n");
                exit();
                }
        p= &freel[nfree];
        nfree++;
        p->no= b;
        p->next= bitptr[a];
        bitptr[a]= p;
        return;
}


dumpadj()

{
        int i,j;
        struct list *p,*q;

        printf("dumping adjacency list %d\n",nfree);
        for(i=0;i<NOBITS;i++) {
                p= bitptr[i];
                printf("Bit %d: ",i+1);
                while(p!=NULL) {
                        printf(" %d",p->no);
                        p= p->next;
                        }
                printf("\n");
                }

        return;
}



/* -------------------------------------------------------------------- */



main(argn,argv)

int argn;
char *argv[];

/*
 *      find connected components of adjacency graph
 */

{
        int i,j,k;
        int ncons,tcon;

        if((infile=open(argv[1],0))<=0) {
                printf("Cannot open %s, quitting\n",argv[1]);
                exit();
                }
        for(j=0;j<NOBITS;j++) {
                bitptr[j]= NULL;
                component[j]= 0;
                }
        tcon= 0;
        printf("getklist\n");
        getklist();
        printf("getconnlist\n");
        ncons= getconnlist();
        printf("makeadjac\n");
        makeadjac(ncons);
        for(;;) {
                for(j=0;j<NOBITS;j++)
                        if(bitptr[j]!=NULL)
                                break;
                if(j>=NOBITS)
                        break;
                markremove(j,++tcon);
                }
        printf("Key equivalences: ");
        for(i=0;i<(ncons/2);i++) {
                printf("(%d,%d) ",cons[2*i],cons[2*i+1]);
                if((i%10)==9)
                        printf("\n");
                }
        if((i%10)!=0)
                printf("\n");
        printf("%d Connected components\n");
        for(i=1;i<=tcon;i++) {
                printf("\tComponent %d: ",i);
                k= 0;
                for(j=0;j<NOBITS;j++) {
                        if(component[j]==i) {
                                if((k%9)==0)
                                        printf("\n\t\t");
                                printf("%d ",j+1);
                                k++;
                                }
                        }
                printf("\n");
                }

        close(infile);
        printf("done\n");
        exit();
}


/* -------------------------------------------------------------------- */

