DES_HOME=	\jlm
BIN=		$(DES_HOME)\bin
SRC=		$(DES_HOME)\crypto

CC=		cl
OPTSW=		-O
INCLDIR=	"\Program Files\Devstudio\Vc\include"
CFLAGS=		/nologo /c /DEBUG $(OPTSW) -I$(INCLDIR) -I$(INCLDIR)/sys \
/D "_DEBUG" /D "DEBUG" /D "_CONSOLE" /D "_MBCS" /Zi /Fd$(BIN)\desvc.pdb
LINK=		link
LINKFLAGS=	/nologo /DEBUG /debug /subsystem:console  
LIBDIR=		"\Program Files\DevStudio\Vc\lib"
LIB=		"\Program Files\DevStudio\Vc\lib"
LIBEXT=		libcd.lib

srcs= desdriv.c deslib.c

dobjs= $(BIN)\desdrive.obj $(BIN)\deslib.obj
pobjs= $(BIN)\dumpbool.obj $(BIN)\deslib.obj
polyobjs= $(BIN)\polyd.obj $(BIN)\deslib.obj

all: des.exe dumpbool.exe poly.exe

des.exe: $(BIN)\desdrive.obj $(BIN)\deslib.obj
	@echo "des"
	$(LINK) $(LINKFLAGS) /OUT:$(BIN)/des.exe $(dobjs) /pdb:$(BIN)\des.pdb $(LIBEXT)

dumpbool.exe: $(BIN)\dumpbool.obj $(BIN)\deslib.obj
	@echo "dumpbool"
	$(LINK) $(LINKFLAGS) /OUT:$(BIN)/dumpbool.exe $(pobjs) /pdb:$(BIN)\dumpbool.pdb $(LIBEXT)


poly.exe: $(BIN)\polyd.obj $(BIN)\deslib.obj
	@echo "dumpbool"
	$(LINK) $(LINKFLAGS) /OUT:$(BIN)/poly.exe $(polyobjs) /pdb:$(BIN)\poly.pdb $(LIBEXT)

$(BIN)/deslib.obj: deslib.c
	$(CC) $(CFLAGS) -c deslib.c
	mv deslib.obj $@
$(BIN)/desdrive.obj: desdrive.c 
	$(CC) $(CFLAGS) -c desdrive.c
	mv desdrive.obj $@
$(BIN)/dumpbool.obj: dumpbool.c 
	$(CC) $(CFLAGS) -c dumpbool.c
	mv dumpbool.obj $@
$(BIN)/polyd.obj: polyd.c 
	$(CC) $(CFLAGS) -c polyd.c
	mv polyd.obj $@

