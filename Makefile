#ident $Id$

# The PAM library directory
SECURITY_DIR = /usr/lib/security

# The Mozilla LDAP libraries
LDAP_LIB_DIR = /usr/local/ldapsdk/lib
LDAP_INC_DIR = /usr/local/ldapsdk/include
LDAPLIBS = -L$(LDAP_LIB_DIR) -lldap -llber -lpam -lnsl

#CDEFS = -O2
WARNINGS = -ansi -D_POSIX_SOURCE -Wall -Wwrite-strings \
	-Wpointer-arith -Wcast-qual -Wcast-align \
	-Wtraditional -Wstrict-prototypes -Wmissing-prototypes \
	-Wnested-externs -Winline -Wshadow -pedantic

CDEFS = -g $(WARNINGS) #-DYPLDAPD

# Which Make is gnu make
MAKE = make
#MAKE = gnumake

# OS Part
# Linux Section
CC = gcc
CFLAGS = -Wall -I$(LDAP_INC_DIR) $(CON_FILE) -D_GNU_SOURCE -DLINUX $(CDEFS) -fPIC
LD_FLAGS = -x --shared -rpath $(LDAP_LIB_DIR)

# Solaris 2.6 Sun Pro C Compiler
#CC = /opt/SUNWspro/bin/cc
#CFLAGS = -I$(LDAP_INC_DIR) $(CON_FILE) -DSOLARIS $(CDEFS) -K PIC 

# Solaris 2.6 GCC 2.7.2.3
#CC = gcc
CFLAGS = -Wall -I$(LDAP_INC_DIR) -DSOLARIS -D__EXTENSIONS__ $(CDEFS) -fPIC
LD_FLAGS = -M mapfile -G -h $(LIBAUTHSH) -z text -Bsymbolic \
			-R$(LDAP_LIB_DIR) -R/usr/ucblib

LIBAUTHSH = pam_ldap.so.1

LIBAUTHOBJ =  pam_ldap.o
LIBAUTHSRC =  pam_ldap.c
LIBOBJ = $(LIBAUTHOBJ) 
LIBSRC = $(LIBAUTHSRC)

LIBSHARED = $(LIBAUTHSH) 

LIBOBJD = $(addprefix dynamic/,$(LIBOBJ))
LIBOBJS = $(addprefix static/,$(LIBOBJ)) 
export CFLAGS CC

dynamic/%.o : %.c
	$(CC) $(CFLAGS) $(DYNAMIC) $(CPPFLAGS) -c $< -o $@

static/%.o: %.c
	$(CC) $(CFLAGS) $(STATIC) $(CPPFLAGS) -c $< -o $@


########################### don't edit below #######################

dummy: all

install: all
	chmod 755 pam_ldap.so.1
	cp pam_ldap.so.1 $(SECURITY_DIR)
	chown root $(SECURITY_DIR)/pam_ldap.so.1
	-ln -s $(SECURITY_DIR)/pam_ldap.so.1 $(SECURITY_DIR)/pam_ldap.so

all: dirs $(LIBSHARED) 

dirs:
	mkdir -p ./dynamic

$(LIBOBJD): $(LIBSRC)


$(LIBAUTHSH): $(LIBAUTHSRC) $(LIBOBJD) 
	$(LD) $(LD_FLAGS) -o $@  $(addprefix dynamic/,$(LIBAUTHOBJ)) $(LDAPLIBS)

clean:
	rm -f $(LIBAUTHSH) $(LIBOBJD) $(LIBOBJS) a.out core *~

extraclean: clean
	rm -f *.a *.out *.o *.so *.bak

.c.o:	
	$(CC) -c $(CFLAGS) $<

