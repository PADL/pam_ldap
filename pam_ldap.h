/*
 * Copyright (C) 1998 Luke Howard, PADL Software.
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

/* /etc/ldap.conf nss_ldap-style configuration */
typedef struct
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
        /* SSL path; haven't figured out SSL yet */
        char *sslpath;
        /* filter to AND with uid=%s */
        char *filter;
        /* attribute to search on; defaults to uid. Use CN with ADS? */
        char *attr;
        /* search for Netscape password policy */
        int getpolicy;
} pam_ldap_config;

/* Netscape global password policy attributes */
typedef struct
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
} pam_ldap_password_policy;

/* Netscape per-use password attributes. Unused except for DN. */
typedef struct {
    char *dn;
    /* host attribute from account objectclass */
    char **hosts_allow;
    int password_expiration_time;
    int password_exp_warned;
    int password_retry_count;
    int retry_count_reset_time;
    int account_unlock_time;
} pam_ldap_user_info;

/*
 * Per PAM-call LDAP session. We keep the user info and
 * LDAP handle cached to minimize binds and searches to
 * the directory, particularly as you can't rebind within
 * a V2 session.
 */
typedef struct
{
    LDAP *ld;
    int ldap_version;
    int bound_as_user;
    pam_ldap_config *conf;
    pam_ldap_user_info *info;
} pam_ldap_session;

#define OLD_PASSWORD_PROMPT "Enter login(LDAP) password: "
#define NEW_PASSWORD_PROMPT "New password: "
#define AGAIN_PASSWORD_PROMPT "Re-enter new password: "

#define PAM_SM_AUTH
#define PAM_SM_PASSWORD
