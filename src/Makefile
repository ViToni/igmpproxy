
#BINDIR=../bin
BINDIR=/usr/local/bin
ETCDIR=/usr/local/etc
MANDIR=/usr/local/man


# CFLAGS=-g
CFLAGS+=-O2 -Wall -Wextra -fno-builtin-log

default : build.h igmpproxy

all	: igmpproxy

clean	:
	rm -f *.o *.asm build.h igmpproxy  

install : 
	cp igmpproxy ${BINDIR}
	cp ../doc/igmpproxy.8 ${MANDIR}/man8
	cp ../doc/igmpproxy.conf.5 ${MANDIR}/man5
	if [ ! -e ${ETCDIR}/igmpproxy.conf ]; then cp igmpproxy.conf ${ETCDIR}; fi

SRC = igmpproxy.c config.c confread.c request.c mcgroup.c rttable.c \
			igmp.c ifvc.c callout.c kern.c syslog.c lib.c mroute-api.c
OBJS = ${SRC:.c=.o}
igmpproxy: build.h ${OBJS}
	cc ${CFLAGS} ${OBJS} -o igmpproxy

build.h	:  
	echo '#define BUILD "' `date +%y%m%d` '"' >build.h


