# dhcpcd Makefile

PROG=		dhcpcd
SRCS=		arp.c bind.c common.c control.c dhcp.c dhcpcd.c duid.c eloop.c
SRCS+=		dbus-dict.c dhcpcd-dbus.c
SRCS+=		if-options.c if-pref.c ipv4ll.c net.c signals.c
PKG_CONFIG ?= pkg-config

CFLAGS?=	-O2
CSTD?=		c99
CFLAGS+=	-std=${CSTD}
include config.mk

FILES+=		dhcpcd.conf dhcpcd-dbus.conf

_DBUSCFLAGS_SH=	$(PKG_CONFIG) --cflags dbus-1
_DBUSCFLAGS!=	${_DBUSCFLAGS_SH}
DBUSCFLAGS=	${_DBUSCFLAGS}$(shell ${_DBUSCFLAGS_SH})

_DBUSLIBS_SH=	$(PKG_CONFIG) --libs dbus-1
_DBUSLIBS!=	${_DBUSLIBS_SH}
DBUSLIBS=	${_DBUSLIBS}$(shell ${_DBUSLIBS_SH})

DBUSDIR=	${SYSCONFDIR}/dbus-1/system.d

# Linux needs librt
_LIBRT_SH=	[ "$$(uname -s)" = "Linux" ] && echo "-lrt" || echo ""
_LIBRT!=	${_LIBRT_SH}
LIBRT?=		${_LIBRT}$(shell ${_LIBRT_SH})

CFLAGS+=	${DBUSCFLAGS}
LDADD+=		${DBUSLIBS} ${LIBRT}

OBJS+=		${SRCS:.c=.o} ${COMPAT_SRCS:.c=.o}

CLEANFILES+=	.depend

LDFLAGS+=	-Wl,-rpath=${LIBDIR}

SED_SYS=	-e 's:@SYSCONFDIR@:${SYSCONFDIR}:g'

_DEPEND_SH=	test -e .depend && echo ".depend" || echo ""
_DEPEND!=	${_DEPEND_SH}
DEPEND=		${_DEPEND}$(shell ${_DEPEND_SH})

_VERSION_SH=	sed -n 's/\#define VERSION[[:space:]]*"\(.*\)".*/\1/p' defs.h
_VERSION!=	${_VERSION_SH}
VERSION=	${_VERSION}$(shell ${_VERSION_SH})

GITREF?=	HEAD
DISTPREFIX?=	${PROG}-${VERSION}
DISTFILE?=	${DISTPREFIX}.tar.bz2

CLEANFILES+=	*.tar.bz2

.PHONY:		import import-bsd

.SUFFIXES:	.in

.in:
	${SED} ${SED_SYS} $< > $@

all: config.h ${PROG} ${FILES}

.c.o:
	${CC} ${CFLAGS} ${CPPFLAGS} -c $< -o $@

.depend: ${SRCS} ${COMPAT_SRCS}
	${CC} ${CPPFLAGS} -MM ${SRCS} ${COMPAT_SRCS} > .depend

depend: .depend

${PROG}: ${DEPEND} ${OBJS}
	${CC} ${LDFLAGS} -o $@ ${OBJS} ${LDADD}

_proginstall: ${PROG}
	${INSTALL} -d ${DESTDIR}${SBINDIR}
	${INSTALL} -m ${BINMODE} ${PROG} ${DESTDIR}${SBINDIR}

_confinstall:
	# dhcpcd config file
	${INSTALL} -d ${DESTDIR}${SYSCONFDIR}
	${INSTALL} -m ${CONFMODE} dhcpcd.conf ${DESTDIR}${SYSCONFDIR}
	# dhcpcd d-bus registration file (note file rename)
	${INSTALL} -d ${DESTDIR}${DBUSDIR}
	${INSTALL} -m ${CONFMODE} dhcpcd-dbus.conf \
		${DESTDIR}${DBUSDIR}/dhcpcd.conf

install: _proginstall _confinstall
	for x in ${SUBDIRS}; do cd $$x; ${MAKE} $@; cd ..; done

clean:
	rm -f ${OBJS} ${PROG} ${PROG}.core ${CLEANFILES}

dist:
	git archive --prefix=${DISTPREFIX}/ ${GITREF} | bzip2 > ${DISTFILE}

import:
	rm -rf /tmp/${DISTPREFIX}
	${INSTALL} -d /tmp/${DISTPREFIX}
	cp ${SRCS} dhcpcd.conf *.in /tmp/${DISTPREFIX}
	cp $$(${CC} ${CPPFLAGS} -MM ${SRCS} | \
		sed -e 's/^.*c //g' -e 's/\\//g' | \
		tr ' ' '\n' | \
		sed -e '/^compat\//d' | \
		sort -u) /tmp/${DISTPREFIX}
	if test -n "${COMPAT_SRCS}"; then \
		${INSTALL} -d /tmp/${DISTPREFIX}/compat; \
		cp ${COMPAT_SRCS} /tmp/${DISTPREFIX}/compat; \
		cp $$(${CC} ${CPPFLAGS} -MM ${COMPAT_SRCS} | \
			sed -e 's/^.*c //g' -e 's/\\//g' | \
			tr ' ' '\n' | \
			sort -u) /tmp/${DISTPREFIX}/compat; \
	fi;
	cd dhcpcd-hooks; ${MAKE} DISTPREFIX=${DISTPREFIX} $@

include Makefile.inc
