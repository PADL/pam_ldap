noinst_PROGRAMS = pam_ldap.so
EXTRA_DIST = COPYING.LIB CVSVersionInfo.txt ChangeLog README \
	     ldap.conf pam.conf pam_ldap.spec pam.d

pam_ldap_so_SOURCES = pam_ldap.c pam_ldap.h md5.c md5.h
pam_ldap_so_LDFLAGS = --shared


install-exec-local: pam_ldap.so
	@$(NORMAL_INSTALL)
	$(mkinstalldirs) $(DESTDIR)$(libdir)/security
if EXTENSION_SO
	$(INSTALL_PROGRAM) -o root -g root pam_ldap.so $(DESTDIR)$(libdir)/security/pam_ldap.so
else
	$(INSTALL_PROGRAM) -o root -g root pam_ldap.so $(DESTDIR)$(libdir)/security/pam_ldap.so.1
	-rm -f $(DESTDIR)$(libdir)/security/pam_ldap.so
	-ln -s $(DESTDIR)$(libdir)/security/pam_ldap.so.1 $(DESTDIR)$(libdir)/security/pam_ldap.so
endif

install-data-local:
	@$(NORMAL_INSTALL)
	@if test ! -f $(DESTDIR)$(etcdir)/ldap.conf; then \
		$(mkinstalldirs) $(DESTDIR)$(etcdir); \
		$(INSTALL_DATA) -o root -g root $(srcdir)/ldap.conf $(DESTDIR)$(etcdir)/ldap.conf; \
	fi

uninstall-local:
	@$(NORMAL_UNINSTALL)

