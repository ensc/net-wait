builddir ?= .
srcdir ?= $(dir $(firstword ${MAKEFILE_LIST}))
VPATH = ${srcdir}

INSTALL =	install
INSTALL_BIN =	${INSTALL} -p -m 0755
MKDIR_P =	${INSTALL} -d -m 0755

OPTFLAGS =	-O2 -g3 -flto
AM_CFLAGS =	-std=gnu11 -Wall -W -Wno-unused-parameter -Wmissing-prototypes
AM_CPPFLAGS =	-I${srcdir} -D_GNU_SOURCE -DDEBUG_LEVEL=${DEBUG_LEVEL}
CFLAGS =	${OPTFLAGS} -Werror -D_FORTIFY_SOURCE=2 -fstack-protector
LDFLAGS =	-fuse-linker-plugin -Wl,-as-needed
LDLIBS  =

compile_link = ${CC} -o $@ \
	${AM_CPPFLAGS} ${CPPFLAGS} \
	${AM_CFLAGS} ${CFLAGS} \
	${AM_LDFLAGS} ${LDFLAGS} \
	$1 \
	${LDLIBS}

prefix ?=			/usr/local
sbindir ?=			${prefix}/sbin

sbin_PROGRAMS = \
	net-wait

net-wait_SOURCES = \
	src/net-wait.c \
	ensc-lib/list.h

all:	${sbin_PROGRAMS}

clean:
	rm -f ${sbin_PROGRAMS} ${noinst_PROGRAMS}
	rm -f *.gcno *.gcda ${LCOV_INFO}
	rm -rf ${GENHTML_OUTDIR} .gcov

install:	.install-sbin

.install-sbin:	${sbin_PROGRAMS}
	${MKDIR_P} ${DESTDIR}${sbindir}
	${INSTALL_BIN} $^ ${DESTDIR}${sbindir}/

net-wait:	${net-wait_SOURCES}
	$(call compile_link,$(filter %.c,$^))
