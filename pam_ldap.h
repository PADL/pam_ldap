/*
 * Copyright (C) 1998-1999 Luke Howard.
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

#ifndef LINUX_PAM
#include <security/pam_appl.h>
#endif /* !LINUX_PAM */

#include <security/pam_modules.h>

/* /etc/ldap.conf nss_ldap-style configuration */
typedef struct pam_ldap_config
  {
    /* space delimited list of servers */
    char *host;
    /* port, expected to be common to all servers */
    int port;
    /* base DN, eg. dc=gnu,dc=org */
    char *base;
    /* scope for searches */
    int scope;
    /* bind dn/pw for "anonymous" authentication */
    char *binddn;
    char *bindpw;
    int ssl_on;
    /* SSL path */
    char *sslpath;
    /* filter to AND with uid=%s */
    char *filter;
    /* attribute to search on; defaults to uid. Use CN with ADS? */
    char *userattr;
    /* search for Netscape password policy */
    int getpolicy;
    /* group name; optional, for access authorization */
    char *groupdn;
    /* group membership attribute; defaults to uniquemember */
    char *groupattr;
    /* LDAP protocol version */
    int version;
    /* generate hashes locally */
    int crypt_local;
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

/* Password controls sent to client */
#ifndef LDAP_CONTROL_PWEXPIRED
#define LDAP_CONTROL_PWEXPIRED      "2.16.840.1.113730.3.4.4"
#endif /* LDAP_CONTROL_PWEXPIRED */
#ifndef LDAP_CONTROL_PWEXPIRING
#define LDAP_CONTROL_PWEXPIRING     "2.16.840.1.113730.3.4.5"
#endif /* LDAP_CONTROL_PWEXPIRING */

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
    int ssl_initialized;
    pam_ldap_config_t *conf;
    pam_ldap_user_info_t *info;
  }
pam_ldap_session_t;

#define OLD_PASSWORD_PROMPT "Enter login(LDAP) password: "
#define NEW_PASSWORD_PROMPT "New password: "
#define AGAIN_PASSWORD_PROMPT "Re-enter new password: "

#define PADL_LDAP_SESSION_DATA "PADL-LDAP-SESSION-DATA"
#define PADL_LDAP_AUTHTOK_DATA "PADL-LDAP-AUTHTOK-DATA"
#define PADL_LDAP_AUTH_DATA "PADL-LDAP-AUTH-DATA"

/* Configuration file routines */
static int _alloc_config (pam_ldap_config_t **);
static void _release_config (pam_ldap_config_t **);
static int _read_config (pam_ldap_config_t **);
#ifdef YPLDAPD
static int _ypldapd_read_config (pam_ldap_config_t **);
#endif /* YPLDAPD */

/* Internal memory management */
static void _release_user_info (pam_ldap_user_info_t **);

/* Internal LDAP session management */
static int _open_session (pam_ldap_session_t *);
static int _connect_anonymously (pam_ldap_session_t *);
#ifdef NETSCAPE_API_EXTENSIONS
static int _rebind_proc (LDAP *, char **, char **, int *, int, void *);
#endif /* NETSCAPE_API_EXTENSIONS */
static int _connect_as_user (pam_ldap_session_t *, const char *);
static int _reopen (pam_ldap_session_t *);

/* LDAP entry helper routines */
static int _get_integer_value (LDAP *, LDAPMessage *, const char *, int *);
static int _get_string_values (LDAP *, LDAPMessage *, const char *, char ***);
static int _has_value (char **, const char *);
static int _host_ok (pam_ldap_session_t * session);
static char *_get_salt (char buf[3]);
static void _cleanup_authtok_data (pam_handle_t *, void *, int);

/* LDAP cover routines */
static int _get_user_info (pam_ldap_session_t *, const char *);
static int _get_password_policy (pam_ldap_session_t *, pam_ldap_password_policy_t *);
static int _authenticate (pam_ldap_session_t *, const char *, const char *);
static int _update_authtok (pam_ldap_session_t *, const char *, const char *, const char *);

/* PAM API helpers, public session management */
static void _pam_ldap_cleanup_session (pam_handle_t *, void *, int);
static int _pam_ldap_get_session (pam_handle_t *, const char *, pam_ldap_session_t **);
static int _get_authtok (pam_handle_t *, int, int);
static int _conv_sendmsg (struct pam_conv *, const char *, int, int);

#ifdef LINUX_PAM
#include <security/pam_misc.h>
#else
#define PAM_EXTERN
#define _pam_overwrite(x) \
{ \
     register char *__xx__; \
     if ((__xx__=x)) \
          while (*__xx__) \
               *__xx__++ = '\0'; \
}

#define _pam_drop(X) \
if (X) { \
    free(X); \
    X=NULL; \
}
#endif /* LINUX_PAM */

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
