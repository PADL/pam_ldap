/*
 * Copyright (C) 1998-2002 Luke Howard.
 * This file is part of the pam_ldap library.
 * Contributed by Luke Howard, <lukeh@padl.com>, 1998.
 *
 * The pam_ldap library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * The pam_ldap library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with the pam_ldap library; see the file COPYING.LIB.  If not,
 * write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_SECURITY_PAM_APPL_H
#include <security/pam_appl.h>
#elif defined(HAVE_PAM_PAM_APPL_H)
#include <pam/pam_appl.h>
#endif

#ifdef HAVE_SECURITY_PAM_MISC_H
#include <security/pam_misc.h>
#elif defined(HAVE_PAM_PAM_MISC_H)
#include <pam/pam_misc.h>
#endif

#ifndef HAVE_PAM_PAM_MODULES_H
#include <security/pam_modules.h>
#else
#include <pam/pam_modules.h>
#endif

/* /etc/ldap.conf nss_ldap-style configuration */
typedef struct pam_ldap_config
  {
	/* file name read from */
	char *configFile;
    /* URI */
    char *uri;
    /* space delimited list of servers */
    char *host;
    /* port, expected to be common to all servers */
    int port;
    /* base DN, eg. dc=gnu,dc=org */
    char *base;
    /* scope for searches */
    int scope;
    /* deref policy */
    int deref;
    /* bind dn/pw for "anonymous" authentication */
    char *binddn;
    char *bindpw;
    /* bind dn/pw for "root" authentication */
    char *rootbinddn;
    char *rootbindpw;
    /* SSL config states */
#define SSL_OFF          0
#define SSL_LDAPS        1
#define SSL_START_TLS    2
    int ssl_on;
    /* SSL path */
    char *sslpath;
    /* filter to AND with uid=%s */
    char *filter;
    /* attribute to search on; defaults to uid. Use CN with ADS? */
    char *userattr;
    /* attribute to set PAM_USER based on */
    char *tmplattr;
    /* default template user */
    char *tmpluser;
    /* search for Netscape password policy */
    int getpolicy;
    /* host attribute checking, for access authorization */
    int checkhostattr;
    /* group name; optional, for access authorization */
    char *groupdn;
    /* group membership attribute; defaults to uniquemember */
    char *groupattr;
    /* LDAP protocol version */
    int version;
    /* search timelimit */
    int timelimit;
    /* bind timelimit */
    int bind_timelimit;
    /* automatically chase referrals */
    int referrals;
    /* restart interrupted syscalls, OpenLDAP only */
    int restart;
    /* chauthtok config states */
#define PASSWORD_CLEAR   0
#define PASSWORD_CRYPT   1
#define PASSWORD_MD5     2
#define PASSWORD_CLEAR_REMOVE_OLD     3
#define PASSWORD_AD      4
#define PASSWORD_EXOP    5
    int password_type;
    /* min uid */
    uid_t min_uid;
    /* max uid */
    uid_t max_uid;
    /* tls check peer */
    int tls_checkpeer;
    /* tls ca certificate file */
    char *tls_cacertfile;
    /* tls ca certificate dir */
    char *tls_cacertdir;
    /* tls ciphersuite */
    char *tls_ciphers;
    /* tls certificate */
    char *tls_cert;
    /* tls key */
    char *tls_key;
  }
pam_ldap_config_t;

/* Netscape global password policy attributes */
typedef struct pam_ldap_password_policy
  {
    int password_change;
    int password_check_syntax;
    int password_min_length;
    int password_exp;
    int password_max_age;
    int password_warning;
    int password_keep_history;
    int password_in_history;
    int password_lockout;
    int password_max_failure;
    int password_unlock;
    int password_lockout_duration;
    int password_reset_duration;
  }
pam_ldap_password_policy_t;

/* Standard Unix style shadow controls */
typedef struct pam_ldap_shadow
  {
    int shadowacct;		/* is shadowAccount */
    long int lstchg;		/* Date of last change.  */
    long int min;		/* Minimum number of days between changes.  */
    long int max;		/* Maximum number of days between changes.  */
    long int warn;		/* Number of days to warn user to change
				   the password.  */
    long int inact;		/* Number of days the account may be
				   inactive.  */
    long int expire;		/* Number of days since 1970-01-01 until
				   account expires.  */
    unsigned long int flag;	/* Reserved.  */
  }
pam_ldap_shadow_t;

/* Password controls sent to client */
#ifndef LDAP_CONTROL_PWEXPIRED
#define LDAP_CONTROL_PWEXPIRED      "2.16.840.1.113730.3.4.4"
#endif /* LDAP_CONTROL_PWEXPIRED */
#ifndef LDAP_CONTROL_PWEXPIRING
#define LDAP_CONTROL_PWEXPIRING     "2.16.840.1.113730.3.4.5"
#endif /* LDAP_CONTROL_PWEXPIRING */

#ifndef LDAP_OPT_ON
#define LDAP_OPT_ON ((void *) 1)
#endif /* LDPA_OPT_ON */
#ifndef LDAP_OPT_OFF
#define LDAP_OPT_OFF ((void *) 0)
#endif /* LDAP_OPT_OFF */

#if defined(LDAP_EXOP_X_MODIFY_PASSWD) && !defined(LDAP_EXOP_MODIFY_PASSWD)
#define LDAP_EXOP_MODIFY_PASSWD LDAP_EXOP_X_MODIFY_PASSWD
#endif

/* Seconds in a day */
#define SECSPERDAY 86400

/* Netscape per-use password attributes. Unused except for DN. */
typedef struct pam_ldap_user_info
  {
    /* user name, to validate info cache */
    char *username;
    /* DN of user in directory */
    char *userdn;
    /* temporary cache of user's bind credentials for rebind function */
    char *userpw;
    /* host attribute from account objectclass */
    char **hosts_allow;
    /* seconds until password expires */
    long password_expiration_time;
    /* password expires now */
    int password_expired;
    /* bound as user DN */
    int bound_as_user;
    /* user ID */
    uid_t uid;
    /* mapped user */
    char *tmpluser;
    /* shadow stuff */
    pam_ldap_shadow_t shadow;
  }
pam_ldap_user_info_t;

/*
 * Per PAM-call LDAP session. We keep the user info and
 * LDAP handle cached to minimize binds and searches to
 * the directory, particularly as you can't rebind within
 * a V2 session.
 */
typedef struct pam_ldap_session
  {
    LDAP *ld;
    pam_ldap_config_t *conf;
    pam_ldap_user_info_t *info;
  }
pam_ldap_session_t;

#define OLD_PASSWORD_PROMPT "Enter login(LDAP) password: "
#define NEW_PASSWORD_PROMPT "New password: "
#define AGAIN_PASSWORD_PROMPT "Re-enter new password: "

/* pam_ldap session */
#define PADL_LDAP_SESSION_DATA "PADL-LDAP-SESSION-DATA"
/* expired user */
#define PADL_LDAP_AUTHTOK_DATA "PADL-LDAP-AUTHTOK-DATA"
/* non-template user (pre-mapping) */
#define PADL_LDAP_AUTH_DATA "PADL-LDAP-AUTH-DATA"
/* authtok for Solaris */
#define PADL_LDAP_OLDAUTHTOK_DATA "PADL-LDAP-OLDAUTHTOK-DATA"

/* Configuration file routines */
static int _alloc_config (pam_ldap_config_t **);
static void _release_config (pam_ldap_config_t **);
static int _read_config (const char *, pam_ldap_config_t **);
#ifdef YPLDAPD
static int _ypldapd_read_config (pam_ldap_config_t **);
#endif /* YPLDAPD */

/* Internal memory management */
static void _release_user_info (pam_ldap_user_info_t **);

/* Internal LDAP session management */
static int _open_session (pam_ldap_session_t *);
static int _connect_anonymously (pam_ldap_session_t *);
#if defined(LDAP_API_FEATURE_X_OPENLDAP) && (LDAP_API_VERSION > 2000)
#if LDAP_SET_REBIND_PROC_ARGS == 3
static int _rebind_proc (LDAP * ld, LDAP_CONST char *url, ber_tag_t request, ber_int_t msgid, void *arg);
#else
static int _rebind_proc (LDAP * ld, LDAP_CONST char *url, int request, ber_int_t msgid);
#endif
#else
#if LDAP_SET_REBIND_PROC_ARGS == 3
static int _rebind_proc (LDAP *, char **, char **, int *, int, void *);
#else
static int _rebind_proc (LDAP * ld, char **whop, char **credp, int *methodp, int freeit);
#endif
#endif /* OpenLDAP */
static int _connect_as_user (pam_ldap_session_t *, const char *);
static int _reopen (pam_ldap_session_t *);

/* LDAP entry helper routines */
static int _get_integer_value (LDAP *, LDAPMessage *, const char *, int *);
static int _get_long_integer_value (LDAP *, LDAPMessage *, const char *, long int *);
static int _get_string_values (LDAP *, LDAPMessage *, const char *, char ***);
static int _has_value (char **, const char *);
static int _host_ok (pam_ldap_session_t * session);
static char *_get_salt (char buf[16]);
static char *_get_md5_salt (char buf[16]);
static void _cleanup_data (pam_handle_t *, void *, int);
static void _cleanup_authtok_data (pam_handle_t *, void *, int);

/* LDAP cover routines */
static int _get_user_info (pam_ldap_session_t *, const char *);
static int _get_password_policy (pam_ldap_session_t *, pam_ldap_password_policy_t *);
static int _do_authentication (pam_ldap_session_t *, const char *, const char *);
static int _update_authtok (pam_ldap_session_t *, const char *, const char *, const char *);

/* PAM API helpers, public session management */
static void _pam_ldap_cleanup_session (pam_handle_t *, void *, int);

static int _pam_ldap_get_session (pam_handle_t *, const char *, const char *, pam_ldap_session_t **);

static int _get_authtok (pam_handle_t *, int, int);
static int _conv_sendmsg (struct pam_conv *, const char *, int, int);

#ifndef PAM_EXTERN
#define PAM_EXTERN
#endif

#ifndef _pam_overwrite
#define _pam_overwrite(x) \
{ \
     register char *__xx__; \
     if ((__xx__=x)) \
          while (*__xx__) \
               *__xx__++ = '\0'; \
}
#endif

#ifndef _pam_drop
#define _pam_drop(X) \
if (X) { \
    free(X); \
    X=NULL; \
}
#endif

#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE !FALSE
#endif

#ifndef LDAP_FILT_MAXSIZ
#define LDAP_FILT_MAXSIZ 1024
#endif /* LDAP_FILT_MAXSIZ */

/* PAM authentication routine */
#define PAM_SM_AUTH
PAM_EXTERN int pam_sm_authenticate (pam_handle_t *, int, int, const char **);
PAM_EXTERN int pam_sm_setcred (pam_handle_t *, int, int, const char **);

/* PAM session management */
#define PAM_SM_SESSION
PAM_EXTERN int pam_sm_open_session (pam_handle_t *, int, int, const char **);
PAM_EXTERN int pam_sm_close_session (pam_handle_t *, int, int, const char **);

/* PAM password changing routine */
#define PAM_SM_PASSWORD
PAM_EXTERN int pam_sm_chauthtok (pam_handle_t *, int, int, const char **);

/* PAM authorization routine */
#define PAM_SM_ACCOUNT
PAM_EXTERN int pam_sm_acct_mgmt (pam_handle_t *, int, int, const char **);

