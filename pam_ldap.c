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

/*
 * Portions Copyright Andrew Morgan, 1996.  All rights reserved.
 * Modified by Alexander O. Yuriev
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, and the entire permission notice in its entirety,
 *    including the disclaimer of warranties.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * ALTERNATIVELY, this product may be distributed under the terms of
 * the GNU Public License, in which case the provisions of the GPL are
 * required INSTEAD OF the above restrictions.  (This clause is
 * necessary due to a potential bad interaction between the GPL and
 * the restrictions contained in a BSD-style copyright.)
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Portions by Elliot Lee <sopwith@redhat.com>, Red Hat Software.
 * Copyright (C) 1996.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, and the entire permission notice in its entirety,
 *    including the disclaimer of warranties.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * ALTERNATIVELY, this product may be distributed under the terms of
 * the GNU Public License, in which case the provisions of the GPL are
 * required INSTEAD OF the above restrictions.  (This clause is
 * necessary due to a potential bad interaction between the GPL and
 * the restrictions contained in a BSD-style copyright.)
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE. 
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <netdb.h>

#include <lber.h>
#include <ldap.h>
#ifdef SSL                                                                      
#include <ldap_ssl.h>
#endif /* SSL */

#ifdef YPLDAPD
#include <rpcsvc/yp_prot.h>
#include <rpcsvc/ypclnt.h>
#endif /* YPLDAPD */

#include "pam_ldap.h"

#ifndef LINUX
#define CONST_ARG
#include <crypt.h>
#else
#define CONST_ARG const
#include <sys/param.h>
#endif /* !LINUX */

#include <security/pam_modules.h>

#ifdef LDAP_VERSION3
#define LDAP_MEMFREE(x)	ldap_memfree(x)
#else
#define LDAP_MEMFREE(x)	free(x)
#endif /* LDAP_VERSION3 */

static char rcsid[] = "$Id$";

static void _release_config(
                         pam_ldap_config_t **pconfig
                         )
{
    pam_ldap_config_t *c;

    c = *pconfig;
    if (c == NULL)
        return;

    if (c->host != NULL)
        free(c->host);

    if (c->base != NULL)
        free(c->base);

    if (c->binddn != NULL)
        free(c->binddn);

    if (c->bindpw != NULL) {
        memset(c->bindpw, 0, strlen(c->bindpw));
        free(c->bindpw);
    }

    if (c->sslpath != NULL) {
        free(c->sslpath);
    }

    if (c->userattr != NULL) {
        free(c->userattr);
    }

    if (c->groupattr != NULL) {
        free(c->groupattr);
    }

    if (c->groupdn != NULL) {
        free(c->groupdn);
    }

    if (c->filter != NULL) {
        free(c->filter);
    }
    
    memset(c, 0, sizeof(*c));
    free(c);
    *pconfig = NULL;

    return;
}

static void _release_user_info(
                   pam_ldap_user_info_t **info
                   )
{
    if (*info == NULL)
        return;
    
    if ((*info)->userdn != NULL) {
        LDAP_MEMFREE((void *)(*info)->userdn);
    }

    if ((*info)->hosts_allow != NULL) {
        ldap_value_free((*info)->hosts_allow);
    }

    free((void *)(*info)->username);
    free(&info);
    
    *info = NULL;
    return;
}

static void _pam_ldap_cleanup_session(
                      pam_handle_t *pamh,
                      void *data,
                      int error_status
                      )
{
    pam_ldap_session_t *session = (pam_ldap_session_t *)data;
    
    if (session == NULL)
        return;

    if (session->ld != NULL) {
        ldap_unbind(session->ld);
        session->ld = NULL;
    }

    _release_config(&session->conf);
    _release_user_info(&session->info);

    free(data);
    
    return;
}

static int _alloc_config(
                 pam_ldap_config_t **presult
                 )
{
    pam_ldap_config_t *result;

    if (*presult == NULL) {
        *presult = (pam_ldap_config_t *)calloc(1, sizeof(*result));
        if (presult == NULL)
            return PAM_BUF_ERR;
    }

    result = *presult;

    result->scope = LDAP_SCOPE_SUBTREE;
    result->host = NULL;
    result->base = NULL;
    result->port = LDAP_PORT;
    result->binddn = NULL;
    result->bindpw = NULL;
    result->sslpath = NULL;
    result->filter = NULL;
    result->userattr = NULL;
    result->groupattr = NULL;
    result->groupdn = NULL;
    result->getpolicy = 0;
    result->version = LDAP_VERSION2;
    result->crypt_local = 0;

    return PAM_SUCCESS;
}


#ifdef YPLDAPD
/*
 * Use the "internal" ypldapd.conf map to figure some things
 * out.
 */
static int _ypldapd_read_config(
                        pam_ldap_config_t **presult
                        )
{
    pam_ldap_config_t *result;
    char *domain;
    int len;
    char *tmp;

    if (_alloc_config(presult) != PAM_SUCCESS) {
        return PAM_BUF_ERR;
    }

    result = *presult;

    yp_get_default_domain(&domain);
    yp_bind(domain);
    if (yp_match(
                 domain,
                 "ypldapd.conf",
                 "ldaphost",
                 sizeof("ldaphost") - 1,
                 &tmp,
                 &len
                 )) {
        return PAM_SYSTEM_ERR;
    }

    result->host = (char *)malloc(len + 1);
    if (result->host == NULL)
        return PAM_BUF_ERR;
    
    memcpy(result->host, tmp, len);
    result->host[len] = '\0';
    free(tmp);

    if (yp_match(
                 domain,
                 "ypldapd.conf",
                 "basedn",
                 sizeof("basedn") - 1,
                 &tmp,
                 &len
                 )) {
        result->base = NULL;
    } else {
        result->base = (char *)malloc(len + 1);
        if (result->base == NULL)
            return PAM_BUF_ERR;
        memcpy(result->base, tmp, len);
        result->base[len] = '\0';
        free(tmp);
    }
    
    if (yp_match(
                 domain,
                 "ypldapd.conf",
                 "ldapport",
                 sizeof("ldapport") - 1,
                 &tmp,
                 &len
                 )) {
        result->port = LDAP_PORT;
    } else {
        char *p = (char *)malloc(len + 1);
        if (p == NULL)
            return PAM_BUF_ERR;
        memcpy(p, tmp, len);
        result->port = atoi(p);
        free(tmp);
        free(p);
    }
    
    yp_unbind(domain);

    result->userattr = strdup("uid");
    if (result->userattr == NULL) {
        return PAM_BUF_ERR;
    }

    /* turn on getting policies */
    result->getpolicy = 1;
#ifdef LDAP_VERSION3
    result->version = LDAP_VERSION3;
#endif /* LDAP_VERSION3 */

    return PAM_SUCCESS;
}
#endif /* YPLDAPD */

#define CHECKPOINTER(ptr) do { if ((ptr) == NULL) { \
    fclose(fp); \
    return PAM_BUF_ERR; \
} \
} while (0)

static int _read_config(
                         pam_ldap_config_t **presult
                         )
{
    /* this is the same configuration file as nss_ldap */
    FILE *fp;
    char b[BUFSIZ];
    pam_ldap_config_t *result;

    if (_alloc_config(presult) != PAM_SUCCESS) {
        return PAM_BUF_ERR;
    }

    result = *presult;
    
    fp = fopen("/etc/ldap.conf", "r");
    if (fp == NULL) {
        return PAM_SYSTEM_ERR;
    }

    while (fgets(b, sizeof(b), fp) != NULL) {
        char *k, *v;
        int len;

        if (*b == '\n' || *b == '#')
            continue;

        k = b;
        v = strchr(k, ' ');
        if (v == NULL)
            v = strchr(k, '\t');

        if (v == NULL)
            continue;

        *(v++) = '\0';
        len = strlen(v);
        v[--len] = '\0';
    
        if (!strcmp(k, "host")) {
            CHECKPOINTER(result->host = strdup(v));
        } else if (!strcmp(k, "base")) {
            CHECKPOINTER(result->base = strdup(v));
        } else if (!strcmp(k, "binddn")) {
            CHECKPOINTER(result->binddn = strdup(v));
        } else if (!strcmp(k, "bindpw")) {
            CHECKPOINTER(result->bindpw = strdup(v));
        } else if (!strcmp(k, "scope")) {
            if (!strcmp(v, "sub")) {
                result->scope = LDAP_SCOPE_SUBTREE;
            } else if (!strcmp(v, "one")) {
                result->scope = LDAP_SCOPE_ONELEVEL;
            } else if (!strcmp(v, "base")) {
                result->scope = LDAP_SCOPE_BASE;
            }
        } else if (!strcmp(k, "port")) {
            result->port = atoi(v);
        } else if (!strcmp(k, "ldap_version")) {
            result->version = atoi(v);
        } else if (!strcmp(k, "sslpath")) {
            CHECKPOINTER(result->sslpath = strdup(v));
        } else if (!strcmp(k, "pam_filter")) {
            CHECKPOINTER(result->filter = strdup(v));
        } else if (!strcmp(k, "pam_login_attribute")) {
            CHECKPOINTER(result->userattr = strdup(v));
        } else if (!strcmp(k, "pam_lookup_policy")) {
            result->getpolicy = !strcmp(v, "yes");
        } else if (!strcmp(k, "pam_groupdn")) {
            CHECKPOINTER(result->groupdn = strdup(v));
        } else if (!strcmp(k, "pam_crypt")) {
            result->crypt_local = !strcmp(v, "local");
        } else if (!strcmp(k, "pam_member_attribute")) {
            CHECKPOINTER(result->groupattr = strdup(v));
        }
    }

    if (result->host == NULL) {
        return PAM_SYSTEM_ERR;
    }
    
    if (result->userattr == NULL) {
        CHECKPOINTER(result->userattr = strdup("uid"));
    }

    if (result->groupattr == NULL) {
        CHECKPOINTER(result->groupattr = strdup("uniquemember"));
    }
    
    fclose(fp);
        
    return PAM_SUCCESS;
}

static int _open_session(
                                  pam_ldap_session_t *session
                                  )
{
#ifndef LDAP_VERSION3
    session->ld = ldap_open(
                                session->conf->host,
                                session->conf->port
                                );
#else
    session->ld = ldap_init(
                                session->conf->host,
                                session->conf->port
                                );
#endif /* LDAP_VERSION3 */
    if (session->ld == NULL) {
        return PAM_SYSTEM_ERR;
    }

#ifdef SSL
    /* haven't tested this, I don't know how the SSL API works. */
    if (session->conf->sslpath != NULL) {
        rc = ldapssl_client_init(session->conf->sslpath, NULL);
        if (rc != LDAP_SUCCESS) {
            syslog(LOG_ERR, "pam_ldap: ldapssl_client_init %s", ldap_err2string(rc));
            return PAM_SYSTEM_ERR;
        }
        rc = ldapssl_install_routines(session->ld);
        if (rc != LDAP_SUCCESS) {
            syslog(LOG_ERR, "pam_ldap: ldapssl_install_routines %s", ldap_err2string(rc));
            return PAM_SYSTEM_ERR;
        }
        rc = ldap_set_option(session->ld, LDAP_OPT_SSL, LDAP_OPT_ON);
        if (rc != LDAP_SUCCESS) {
            syslog(LOG_ERR, "pam_ldap: ldap_set_option %s", ldap_err2string(rc));
            return PAM_SYSTEM_ERR;
        }
    }
#endif /* SSL */

#ifdef LDAP_VERSION3
    (void) ldap_set_option(session->ld, LDAP_OPT_PROTOCOL_VERSION, &session->conf->version);
#else
    session->ld->ld_version = session->conf->version;
#endif /* LDAP_VERSION3 */

    return PAM_SUCCESS;
}

static int _connect_anonymously(
                           pam_ldap_session_t *session
                           )
{
    int rc;

    if (session->ld == NULL) {
        rc = _open_session(session);
        if (rc != PAM_SUCCESS)
            return rc;
    }

#ifdef LDAP_VERSION3
    if (session->conf->version == LDAP_VERSION3 &&
        session->conf->binddn == NULL &&
        (session->info == NULL ||
         session->info->bound_as_user == 0)) {
        /*
         * if we're using the V3 protocol with a NULL bind DN,
         * and we don't need to lower our privelege because we
         * previously bound as the user, then we don't need to
         * issue a BindRequest.
         */
        rc = LDAP_SUCCESS;        
    } else {
#endif /* LDAP_VERSION3 */
        rc = ldap_simple_bind_s(
                                session->ld,
                                session->conf->binddn,
                                session->conf->bindpw
                                );
#ifdef LDAP_VERSION3        
    }
#endif /* LDAP_VERSION3 */
    
    if (rc != LDAP_SUCCESS) {
        syslog(LOG_ERR, "pam_ldap: ldap_simple_bind_s %s", ldap_err2string(rc));
        return PAM_CRED_INSUFFICIENT;
    }

    if (session->info != NULL) {
        session->info->bound_as_user = 0;
    }
    
    return PAM_SUCCESS;
}

static int _connect_as_user(
                            pam_ldap_session_t *session,
                            const char *password
                            )
{
    int rc;
#ifdef LDAP_VERSION3
    PLDAPControl *controls;
    int msgid, parserc, finished = 0;
    struct timeval zerotime;   
    LDAPMessage *result;
#endif /* LDAP_VERSION3 */

    /* avoid binding anonymously with a DN but no password */
    if (password == NULL || password[0] == '\0')
        return PAM_AUTH_ERR;
    
    /* this shouldn't ever happen */
    if (session->info == NULL)
        return PAM_SYSTEM_ERR;

    /* if we already bound as the user don't bother retrying */
    if (session->info->bound_as_user)
        return PAM_SUCCESS;

    if (session->ld == NULL) {
        rc = _open_session(session);
        if (rc != PAM_SUCCESS)
            return rc;
    }

#ifndef LDAP_VERSION3
    /*
     * Use the synchronous API as we don't need to fetch controls etc
     */
    rc = ldap_simple_bind_s(session->ld, session->info->userdn, (char *)password);
    if (rc != LDAP_SUCCESS) {
        syslog(LOG_ERR, "pam_ldap: ldap_simple_bind_s %s", ldap_err2string(rc));
        return PAM_AUTH_ERR;
    }
#else
    /*
     * Use LDAP v3 controls to find out when the user's password will
     * expire.
     */
    zerotime.tv_sec = zerotime.tv_usec = 0L;

    msgid = ldap_simple_bind(session->ld, session->info->userdn, (char *)password);
    if (msgid < 0) {
        syslog(LOG_ERR, "pam_ldap: ldap_simple_bind %s",
               ldap_err2string(ldap_get_lderrno(session->ld, NULL, NULL)));
        return PAM_AUTH_ERR;
    }
    
    while (!finished) {        
        rc = ldap_result(session->ld, msgid, 0, &zerotime, &result);
        switch (rc) {
            case -1:
                /* error */
                syslog(LOG_ERR, "pam_ldap: ldap_result %s",
                       ldap_err2string(ldap_get_lderrno(session->ld, NULL, NULL)));
                return PAM_SYSTEM_ERR;
                break;
            case 0:
                /* in progress */
                continue;
            default:
                /* The client has received the bind result */
                finished = 1;
                parserc = ldap_parse_result(
                                            session->ld,
                                            result,
                                            &rc,
                                            NULL,
                                            NULL,
                                            NULL,
                                            &controls,
                                            1
                                            );
                
                if (parserc != LDAP_SUCCESS) {
                    syslog(LOG_ERR, "pam_ldap: ldap_parse_result %s", ldap_err2string(parserc));
                    return PAM_SYSTEM_ERR;
                }
                if (rc != LDAP_SUCCESS) {
                    syslog(LOG_ERR, "pam_ldap: ldap_simple_bind %s", ldap_err2string(rc));
                    return PAM_AUTH_ERR;
                }

                if (controls != NULL) {
                    PLDAPControl *ctlp; /* ldctl_oid, ldctl_value, ldctl_iscritical */
                    for (ctlp = controls; *ctlp != NULL; ctlp++) {
                        if (!strcmp((*ctlp)->ldctl_oid, LDAP_CONTROL_PWEXPIRING)) {
                            char seconds[32];
                            snprintf(seconds, sizeof seconds, "%.*s",
                                          (*ctlp)->ldctl_value.bv_len,
                                          (*ctlp)->ldctl_value.bv_val);
                            session->info->password_expiration_time = atol(seconds);
                        } else if (!strcmp((*ctlp)->ldctl_oid, LDAP_CONTROL_PWEXPIRED)) {
                            session->info->password_expired = 1;
                        }
                    }
                    ldap_controls_free(controls);
                }
        }
    }
#endif /* LDAP_VERSION3 */
                        
    session->info->bound_as_user = 1;
    
    return PAM_SUCCESS;
}                    

static int _get_integer_value(
                     LDAP *ld,
                     LDAPMessage *e,
                     const char *attr,
                     int *ptr
                     )
{
    char **vals;

    vals = ldap_get_values(ld, e, (char *)attr);
    if (vals == NULL) {
        return PAM_SYSTEM_ERR;
    }
    *ptr = atol(vals[0]);
    ldap_value_free(vals);

    return PAM_SUCCESS;
}

#ifdef notdef
static int _get_string_value(
                     LDAP *ld,
                     LDAPMessage *e,
                     const char *attr,
                     char **ptr
                     )
{
    char **vals;
    int rc;

    vals = ldap_get_values(ld, e, (char *)attr);
    if (vals == NULL) {
        return PAM_SYSTEM_ERR;
    }
    *ptr = strdup(vals[0]);
    if (*ptr == NULL) {
        rc = PAM_BUF_ERR;
    } else {
        rc = PAM_SUCCESS;
    }
    
    ldap_value_free(vals);

    return rc;
}
#endif /* notdef */

static int _get_string_values(
                     LDAP *ld,
                     LDAPMessage *e,
                     const char *attr,
                     char ***ptr
                     )
{
    char **vals;

    vals = ldap_get_values(ld, e, (char *)attr);
    if (vals == NULL) {
        return PAM_SYSTEM_ERR;
    }
    *ptr = vals;

    return PAM_SUCCESS;
}

static int _has_value(
                            char **src,
                            const char *tgt
                            )
{
    char **p;

    for (p = src; *p != NULL; p++) {
        if (!strcasecmp(*p, tgt)) {
            return 1;
        }
    }

    return 0;
}

static int _host_ok(
                    pam_ldap_session_t *session
                    )
{
    int herr;
    struct hostent hbuf, *h;
    char hostname[MAXHOSTNAMELEN];
    char buf[1024];
    char **q;

    /* simple host based access authorization */
    if (session->info->hosts_allow == NULL) {
        return PAM_SUCCESS;
    }
    
    if (gethostname(hostname, sizeof hostname) < 0) {
        return PAM_SYSTEM_ERR;
    }

#ifndef LINUX
    h = gethostbyname_r(hostname, &hbuf, buf, sizeof buf, &herr);
    if (h == NULL) {
        return PAM_SYSTEM_ERR;
    }
#else
    if (gethostbyname_r(hostname, &hbuf, buf, sizeof buf, &h, &herr) != 0) {
        return PAM_SYSTEM_ERR;
    }
#endif /* !LINUX */

    if (_has_value(session->info->hosts_allow, h->h_name)) {
        return PAM_SUCCESS;
    }

    if (h->h_aliases != NULL) {
        for (q = h->h_aliases; *q != NULL; q++) {
            if (_has_value(session->info->hosts_allow, *q)) {
                return PAM_SUCCESS;
            }
        }
    }

    return PAM_AUTH_ERR;
}

static char *_get_salt(
                       char salt[3]
                      )
{
   int   i;
   int   j;

   srand(time(NULL));
                                                                                
   for (j = 0; j < 2; j++) {
      i = rand() % 3;
      switch(i) {
      case 0:
         i = (rand() % (57 - 46)) + 46;
         break;
      case 1:
         i = (rand() % (90 - 65)) + 65;
         break;
      case 2:
         i = (rand() % (122 - 97)) + 97;
         break;
      }
      salt[j] = i;
   }
   salt[2] = '\0';
   return (salt);
}

static int _get_user_info(
                   pam_ldap_session_t *session,
                   const char *user
                  )
{
    char filter[LDAP_FILT_MAXSIZ];
    int rc;
    LDAPMessage *res, *msg;

    rc = _connect_anonymously(session);
    if (rc != PAM_SUCCESS) {
        return rc;
    }

#ifdef LDAP_VERSION3
    rc = 1;
    (void) ldap_set_option(session->ld, LDAP_OPT_SIZELIMIT, &rc);
#else
    session->ld->ld_sizelimit = 1;
#endif /* LDAP_VERSION3 */

    if (session->conf->filter != NULL) {
        snprintf(filter, sizeof filter, "(&(%s)(%s=%s))",
                 session->conf->filter,
                 session->conf->userattr,
                 user);
    } else {
        snprintf(filter, sizeof filter, "(%s=%s)",
                 session->conf->userattr,
                 user);
    }
    
    rc = ldap_search_s(
                       session->ld,
                       session->conf->base,
                       session->conf->scope,
                       filter,
                       NULL,
                       0,
                       &res
                       );

    if (rc != LDAP_SUCCESS) {
        syslog(LOG_ERR, "pam_ldap: ldap_search_s %s", ldap_err2string(rc)); 
        return PAM_USER_UNKNOWN;
    }

    msg = ldap_first_entry(session->ld, res);
    if (msg == NULL) {
        ldap_msgfree(res);
        return PAM_USER_UNKNOWN;
    }

    if (session->info != NULL) {
        _release_user_info(&session->info);
    }
    
    session->info = (pam_ldap_user_info_t *)calloc(1, sizeof(pam_ldap_user_info_t));
    if (session->info == NULL) {
        ldap_msgfree(res);
        return PAM_BUF_ERR;
    }
    
    session->info->username = strdup(user);
    if (session->info->username == NULL) {
        ldap_msgfree(res);
        _release_user_info(&session->info);
        return PAM_BUF_ERR;
    }
        
    session->info->userdn = ldap_get_dn(session->ld, msg);
    if (session->info->userdn == NULL) {
        ldap_msgfree(res);
        _release_user_info(&session->info);
        return PAM_SYSTEM_ERR;
    }

    session->info->bound_as_user = 0;

    /*
     * it might be better to do a compare later, that way we can
     * avoid fetching any attributes at all
     */
    _get_string_values(session->ld, msg, "host", &session->info->hosts_allow);
        
    ldap_msgfree(res);

    return PAM_SUCCESS;
}

static int _pam_ldap_get_session(
                                pam_handle_t *pamh,
                                const char *username,
                                pam_ldap_session_t **psession
                                )
{
    pam_ldap_session_t *session;
    int rc;
    
    if (pam_get_data(pamh, "PADL-LDAP-SESSION-DATA", (const void **)&session) == PAM_SUCCESS) {
        /*
         * we cache the information retrieved from the LDAP server, however
         * we need to flush this if the application has changed the user on us.
         */
        if ((session->info != NULL) && (strcmp(username, session->info->username) != 0)) {            
            _release_user_info(&session->info);
        }
        *psession = session;
        return PAM_SUCCESS;
    }

    *psession = NULL;

    session = (pam_ldap_session_t *)calloc(1, sizeof(*session));
    if (session == NULL) {
        return PAM_BUF_ERR;
    }

    session->ld = NULL;
    session->conf = NULL;
    session->info = NULL;
   
#ifdef YPLDAPD
    rc = _ypldapd_read_config(&session->conf);
    if (rc != PAM_SUCCESS) {
        _release_config(&session->conf);
#endif /* YPLDAPD */ 
        rc = _read_config(&session->conf);
        if (rc != PAM_SUCCESS) {
            _release_config(&session->conf);
            free(session);
            return rc;
        }
#ifdef YPLDAPD
    }
#endif /* YPLDAPD */

    rc = pam_set_data(pamh, "PADL-LDAP-SESSION-DATA", session, _pam_ldap_cleanup_session);
    if (rc != PAM_SUCCESS) {
        _release_config(&session->conf);
        free(session);
        return rc;
    }

    *psession = session;

    return PAM_SUCCESS;
}

static int _reopen(
                            pam_ldap_session_t *session
                            )
{
    /* V3 lets us avoid five unneeded binds in a password change */
    if (session->conf->version == LDAP_VERSION2) {
        if (session->ld != NULL) {
            ldap_unbind(session->ld);
            session->ld = NULL;
        }
        if (session->info != NULL) {
            session->info->bound_as_user = 0;
        }
        return _open_session(session);
    }
    return PAM_SUCCESS;
}

static int _get_password_policy(
                                pam_ldap_session_t *session,
                                pam_ldap_password_policy_t *policy
                                )
{
    int rc = PAM_SUCCESS;
    LDAPMessage *res, *msg;

    if (rc != PAM_SUCCESS) {
        return rc;
    }

    /* set some reasonable defaults */
    memset(policy, 0, sizeof(*policy));
    policy->password_min_length = 6;
    policy->password_max_failure = 3;

    if (session->conf->getpolicy == 0) {
        return PAM_SUCCESS;
    }

    rc = _connect_anonymously(session);
    if (rc != PAM_SUCCESS) {
        return rc;
    }

#ifdef LDAP_VERSION3
    rc = 1;
    (void) ldap_set_option(session->ld, LDAP_OPT_SIZELIMIT, &rc);
#else
    session->ld->ld_sizelimit = 1;
#endif /* LDAP_VERSION3 */

    rc = ldap_search_s(
                       session->ld,
                       "",
                       LDAP_SCOPE_BASE,
                       "(objectclass=passwordPolicy)",
                       NULL,
                       0,
                       &res
                       );

    if (rc == LDAP_SUCCESS) {
        msg = ldap_first_entry(session->ld, res);
        if (msg != NULL) {
            _get_integer_value(session->ld, msg, "passwordMaxFailure", &policy->password_max_failure);
            _get_integer_value(session->ld, msg, "passwordMinLength", &policy->password_min_length);
        }
        ldap_msgfree(res);
    }

    return PAM_SUCCESS;
}

static int _authenticate(
                     pam_ldap_session_t *session,
                     const char *user,
                     const char *password
                    )
{
    int rc = PAM_SUCCESS;

    if (rc != PAM_SUCCESS) {
        return rc;
    }

    if (session->info == NULL) {
        rc = _get_user_info(session, user);
        if (rc != PAM_SUCCESS) {
            return rc;
        }
    }
    
    rc = _reopen(session);
    if (rc != PAM_SUCCESS)
        return rc;

    rc = _connect_as_user(session, password);
    if (rc != PAM_SUCCESS)
        return rc;

    return rc;
}

static int _update_authtok(
                                     pam_ldap_session_t *session,
                                     const char *user,
                                     const char *old_password,
                                     const char *new_password
                                     )
{
    char *strvals[2];
    LDAPMod *mods[2], mod;
    char buf[32], saltbuf[3];
    int rc = PAM_SUCCESS;
    
    if (session->info == NULL) {
        rc = _get_user_info(session, user);
        if (rc != PAM_SUCCESS) {
            return rc;
        }
    }

    rc = _reopen(session);
    if (rc != PAM_SUCCESS) {
        return rc;
    }

    rc = _connect_as_user(session, old_password);
    if (rc != PAM_SUCCESS)
        return rc;
   
    /* Netscape generates hashed automatically, but UMich doesn't. */ 
    if (session->conf->crypt_local) {
        snprintf(buf, sizeof buf, "{crypt}%s", crypt(new_password, _get_salt(saltbuf)));
        strvals[0] = buf;
    } else {
        strvals[0] = (char *)new_password;
    }

    strvals[1] = NULL;

    mod.mod_vals.modv_strvals = strvals;
    mod.mod_type = (char *)"userPassword";
    mod.mod_op = LDAP_MOD_REPLACE;
#ifndef LDAP_VERSION3
    mod.mod_next = NULL;
#endif /* LDAP_VERSION3 */

    mods[0] = &mod;
    mods[1] = NULL;

    rc = ldap_modify_s(
                       session->ld,
                       session->info->userdn,
                       mods
                       );
    if (rc != LDAP_SUCCESS) {        
        syslog(LOG_ERR, "pam_ldap: ldap_modify_s %s", ldap_err2string(rc));
        rc = PAM_PERM_DENIED;
    } else {
        rc = PAM_SUCCESS;
    }

    return rc;        
}    

static int _get_authtok(
                         pam_handle_t *pamh,
                         int flags,
                         int first
                         )
{
    int rc;
    char *p;
    struct pam_message msg[1], *pmsg[1];
    struct pam_response *resp;
    struct pam_conv *conv;

    pmsg[0] = &msg[0];
    msg[0].msg_style = PAM_PROMPT_ECHO_OFF;
    msg[0].msg = first ? "Password: " : "LDAP Password: ";
    resp = NULL;

    rc = pam_get_item(pamh, PAM_CONV, (CONST_ARG void **)&conv);
    if (rc == PAM_SUCCESS) {
        rc = conv->conv(
                        1,
                        (CONST_ARG struct pam_message **)pmsg,
                        &resp,
                        conv->appdata_ptr
                        );
    } else {
        return rc;
    }

    if (resp != NULL) {
        if ((flags & PAM_DISALLOW_NULL_AUTHTOK) && resp[0].resp == NULL) {
            free(resp);
            return PAM_AUTH_ERR;
        }

        p = resp[0].resp;
        /* leak if resp[0].resp is malloced. */
        resp[0].resp = NULL;
    } else {
        return PAM_CONV_ERR;
    }

    free(resp);
    pam_set_item(pamh, PAM_AUTHTOK, p);
    
    return PAM_SUCCESS;
}

static int _conv_sendmsg(
                        struct pam_conv *aconv,
                        const char *message,
                        int style,
                        int no_warn
                        )
{
    struct pam_message msg, *pmsg;
    struct pam_response *resp;

    if (no_warn)
        return PAM_SUCCESS;
            
    pmsg = &msg;

    msg.msg_style = style;
    msg.msg = (char *)message;
    resp = NULL;

    return aconv->conv(
                       1,
                       (CONST_ARG struct pam_message **)&pmsg,
                       &resp,
                       aconv->appdata_ptr
                       );
}

PAM_EXTERN int pam_sm_authenticate(
                                   pam_handle_t *pamh,
                                   int flags,
                                   int argc,
                                   const char **argv
                                   )
{
    int rc;
    const char *username;
    char *p;
    int use_first_pass = 0, try_first_pass = 0;
    int i;
    pam_ldap_session_t *session = NULL;

    for (i = 0; i < argc; i++) {
        if (!strcmp(argv[i], "use_first_pass"))
            use_first_pass = 1;
        else if (!strcmp(argv[i], "try_first_pass"))
            try_first_pass = 1;
        else if (!strcmp(argv[i], "no_warn"))
            ;
        else if (!strcmp(argv[i], "debug"))
            ;
        else
            syslog(LOG_DEBUG, "illegal option %s", argv[i]);
    }

    rc = pam_get_user(pamh, (CONST_ARG char **)&username, "login: ");
    if (rc != PAM_SUCCESS)
        return rc;

    rc = _pam_ldap_get_session(pamh, username, &session);
    if (rc != PAM_SUCCESS)
        return rc;

    pam_get_item(pamh, PAM_AUTHTOK, (void *)&p);
    if (p != NULL && (use_first_pass || try_first_pass)) {
        rc = _authenticate(session, username, p);
        if (rc == PAM_SUCCESS || use_first_pass) {
            return rc;
        }
    }

    /* can prompt for authentication token */
    rc = _get_authtok(pamh, flags, (p == NULL) ? 1 : 0);
    if (rc != PAM_SUCCESS) {
        return rc;
    }
    
    pam_get_item(pamh, PAM_AUTHTOK, (void *)&p);
    if (p == NULL) {
        rc = PAM_AUTH_ERR;
    } else {
        rc = _authenticate(session, username, p);
    }
    
    return rc;
}

PAM_EXTERN int pam_sm_setcred(
                   pam_handle_t *pamh,
                   int flags,
                   int argc,
                   const char **argv
                   )
{
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_open_session(
                                   pam_handle_t *pamh,
                                   int flags,
                                   int argc,
                                   const char **argv
                                   )
{
    return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_close_session(
                                   pam_handle_t *pamh,
                                   int flags,
                                   int argc,
                                   const char **argv
                                   )
{
    return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_chauthtok(
                                pam_handle_t *pamh,
                                int flags,
                                int argc,
                                const char **argv
                                )
{
    int rc = PAM_SUCCESS;
    char *username, *curpass = NULL, *newpass = NULL;
    struct pam_conv *appconv;
    struct pam_message msg, *pmsg;
    struct pam_response *resp;
    const char *cmiscptr = NULL;
    int tries = 0, i;
    pam_ldap_session_t *session = NULL;
    int use_first_pass = 0, try_first_pass = 0, no_warn = 0;
    char errmsg[1024];
    pam_ldap_password_policy_t policy;

    for (i = 0; i < argc; i++) {
        if (!strcmp(argv[i], "use_first_pass"))
            use_first_pass = 1;
        else if (!strcmp(argv[i], "try_first_pass"))
            try_first_pass = 1;
        else if (!strcmp(argv[i], "no_warn"))
            no_warn = 1;
        else if (!strcmp(argv[i], "debug"))
            ;
        else
            syslog(LOG_DEBUG, "illegal option %s", argv[i]);
    }

    if (flags & PAM_SILENT)
        no_warn = 1;
    
    rc = pam_get_item(pamh, PAM_CONV, (CONST_ARG void **)&appconv);
    if (rc != PAM_SUCCESS)
        return rc;

    rc = pam_get_item(pamh, PAM_USER, (CONST_ARG void **)&username);
    if (rc != PAM_SUCCESS)
        return rc;

    if (username == NULL)
        return PAM_USER_UNKNOWN;

    rc = _pam_ldap_get_session(pamh, username, &session);
    if (rc != PAM_SUCCESS)
        return rc;

    if (flags & PAM_PRELIM_CHECK) {
        /* see whether the user exists */
        return _get_user_info(session, username);
    }

    if (try_first_pass || use_first_pass) {
        if (pam_get_item(pamh, PAM_OLDAUTHTOK, (CONST_ARG void **)&curpass) == PAM_SUCCESS) {
            rc = _authenticate(session, username, curpass);
            if (use_first_pass && rc != PAM_SUCCESS) {
                _conv_sendmsg(appconv, "LDAP Password incorrect", PAM_ERROR_MSG, no_warn);
                return rc;
            } else {
                _conv_sendmsg(appconv, "LDAP Password incorrect: try again", PAM_ERROR_MSG, no_warn);
            }
        } else {
            curpass = NULL;
        }
    }
    
    tries = 0;

    /* support Netscape Directory Server's password policy */
    rc = _get_password_policy(session, &policy);
    if (rc != PAM_SUCCESS) {
        return rc;
    }
                       
    while ((curpass == NULL) && (tries++ < policy.password_max_failure)) {
        pmsg = &msg;
        msg.msg_style = PAM_PROMPT_ECHO_OFF;
        msg.msg = OLD_PASSWORD_PROMPT;
        resp = NULL;

        rc = appconv->conv(
                           1,
                           (CONST_ARG struct pam_message **)&pmsg,
                           &resp,
                           appconv->appdata_ptr
                           );
        
        if (rc != PAM_SUCCESS)
            return rc;
        
        curpass = resp->resp;
        free(resp);

        /* authenticate the old password */
        rc = _authenticate(session, username, curpass);
        if (rc != PAM_SUCCESS) {
            int abortme = 0;
            
            if (curpass != NULL && curpass[0] == '\0') {
                abortme = 1;
            }
            if (curpass) {
                memset(curpass, 0, strlen(curpass));                
                free(curpass);
            }
            curpass = NULL;
            if (abortme) {
                _conv_sendmsg(appconv, "Password change aborted", PAM_ERROR_MSG, no_warn);
                rc = PAM_AUTHTOK_ERR;
                return rc;
            } else {
                _conv_sendmsg(appconv, "LDAP Password incorrect: try again", PAM_ERROR_MSG, no_warn);
            }
        }
    }

    if (curpass == NULL) {
        rc = PAM_AUTHTOK_ERR;
        return rc;
    }

    pam_set_item(pamh, PAM_OLDAUTHTOK, (void *)curpass);

    if (try_first_pass || use_first_pass) {
        if (pam_get_item(pamh, PAM_AUTHTOK, (CONST_ARG void **)&newpass) != PAM_SUCCESS) {
            newpass = NULL;
        }
        if (use_first_pass && newpass == NULL) {
            rc = PAM_AUTHTOK_ERR;
            return rc;
        }
    }

    tries = 0;

    while ((newpass == NULL) && (tries++ < policy.password_max_failure)) {
        pmsg = &msg;
        msg.msg_style = PAM_PROMPT_ECHO_OFF;
        msg.msg = NEW_PASSWORD_PROMPT;
        resp = NULL;

        rc = appconv->conv(
                           1,
                           (CONST_ARG struct pam_message **)&pmsg,
                           &resp,
                           appconv->appdata_ptr
                           );
        
        if (rc != PAM_SUCCESS)
            return rc;
        
        newpass = resp->resp;
        free(resp);

        if (newpass[0] == '\0') {
            free(newpass);
            newpass = NULL;
        }

        if (newpass != NULL) {
            if (curpass != NULL && !strcmp(curpass, newpass)) {
                cmiscptr = "Passwords must differ";
                newpass = NULL;
            } else if (strlen(newpass) < policy.password_min_length) {
                cmiscptr = "Password too short";
                newpass = NULL;
            }
        } else {
            rc = PAM_AUTHTOK_ERR;
            return rc;
        }

        if (cmiscptr == NULL) {
            /* get password again */
            char *miscptr;
            
            pmsg = &msg;
            msg.msg_style = PAM_PROMPT_ECHO_OFF;
            msg.msg = AGAIN_PASSWORD_PROMPT;
            resp = NULL;

            rc = appconv->conv(
                               1,
                               (CONST_ARG struct pam_message **)&pmsg,
                               &resp,
                               appconv->appdata_ptr
                               );
            
            if (rc != PAM_SUCCESS)
                return rc;

            miscptr = resp->resp;
            free(resp);
            if (miscptr[0] == '\0') {
                free(miscptr);
                miscptr = NULL;
            }
            if (miscptr == NULL) {
                _conv_sendmsg(appconv, "Password change aborted", PAM_ERROR_MSG, no_warn);
                rc = PAM_AUTHTOK_ERR;
                return rc;
            }
            if (!strcmp(newpass, miscptr)) {
                miscptr = NULL;
                break;
            }
            _conv_sendmsg(appconv, "You must enter the same password", PAM_ERROR_MSG, no_warn);
            miscptr = NULL;
            newpass = NULL;
        } else {
            _conv_sendmsg(appconv, cmiscptr, PAM_ERROR_MSG, no_warn);
            cmiscptr = NULL;
            newpass = NULL;
        }
    }
    
    if (cmiscptr != NULL || newpass == NULL) {
        rc = PAM_AUTHTOK_ERR;
        return rc;
    }

    pam_set_item(pamh, PAM_AUTHTOK, (void *)newpass);
    rc = _update_authtok(session, username, curpass, newpass);
    if (rc != PAM_SUCCESS) {
        int lderr;
        char *reason;

#ifdef LDAP_VERSION3
        lderr = ldap_get_lderrno(session->ld, NULL, &reason);
#else
        lderr = session->ld->ld_errno;
        reason = session->ld->ld_error;
#endif /* LDAP_VERSION3 */
        if (reason != NULL) {
            snprintf(errmsg, sizeof errmsg, "LDAP password information update failed: %s\n%s", ldap_err2string(lderr), reason);
        } else {
            snprintf(errmsg, sizeof errmsg, "LDAP password information update failed: %s", ldap_err2string(lderr));
        }        
        _conv_sendmsg(appconv, errmsg, PAM_ERROR_MSG, no_warn);
    } else {
        snprintf(errmsg, sizeof errmsg, "LDAP password information changed for %s", username);
        _conv_sendmsg(appconv, errmsg, PAM_TEXT_INFO, (flags & PAM_SILENT) ? 1 : 0);
    }                    

    return rc;
}

PAM_EXTERN int pam_sm_acct_mgmt(
                                pam_handle_t *pamh,
                                int flags,
                                int argc,
                                const char **argv
                                )
{
    /*
     * check whether the user can login.
     */
    /* returns PAM_ACCT_EXPIRED
       PAM_AUTH_ERR
       PAM_AUTHTOKEN_REQD (expired)
       PAM_USER_UNKNOWN
     */
    int rc;
    const char *username;
    int no_warn = 0;
    int i, success = PAM_SUCCESS;
    struct pam_conv *appconv;
    pam_ldap_session_t *session = NULL;
    char buf[1024];

    for (i = 0; i < argc; i++) {
        if (!strcmp(argv[i], "use_first_pass"))
            ;
        else if (!strcmp(argv[i], "try_first_pass"))
            ;
        else if (!strcmp(argv[i], "no_warn"))
            no_warn = 1;
        else if (!strcmp(argv[i], "debug"))
            ;
        else
            syslog(LOG_DEBUG, "illegal option %s", argv[i]);
    }


    if (flags & PAM_SILENT)
        no_warn = 1;

    rc = pam_get_item(pamh, PAM_CONV, (CONST_ARG void **)&appconv);
    if (rc != PAM_SUCCESS)
        return rc;

    rc = pam_get_item(pamh, PAM_USER, (CONST_ARG void **)&username);
    if (rc != PAM_SUCCESS)
        return rc;

    if (username == NULL)
        return PAM_USER_UNKNOWN;

    rc = _pam_ldap_get_session(pamh, username, &session);
    if (rc != PAM_SUCCESS) {
        return rc;
    }

    if (session->info == NULL) {
        rc = _get_user_info(session, username);
        if (rc != PAM_SUCCESS) {
            return rc;
        }
    }

    /* check whether the password has expired */
    if (session->info->password_expired) {
        _conv_sendmsg(
                      appconv,
                      "You are required to change your LDAP password immediately.",
                      PAM_ERROR_MSG,
                      no_warn
                      );
#ifdef PAM_AUTHTOK_EXPIRED
        success = PAM_AUTHTOK_EXPIRED;
#else
        success = PAM_AUTHTOKEN_REQD;
#endif /* PAM_AUTHTOK_EXPIRED */        
    } else if (session->info->password_expiration_time) {
        if (session->info->password_expiration_time < (60*60*24)) {
            snprintf(buf, sizeof buf,
                     "Your LDAP password will expire within 24 hours.");
            /* override no_warn */
            _conv_sendmsg(appconv, buf, PAM_ERROR_MSG, 1);
        } else {
            int days = session->info->password_expiration_time / (60*60*24);
            snprintf(buf, sizeof buf,
                     "Your LDAP password will expire in %d day%s.",
                     days, (days == 1) ? "" : "s");
            _conv_sendmsg(appconv, buf, PAM_ERROR_MSG, no_warn);
        }
    }

    /* group auth, per Chris's pam_ldap_auth module */
    if (session->conf->groupdn != NULL) {
        rc = ldap_compare_s(
                            session->ld,
                            session->conf->groupdn,
                            session->conf->groupattr,
                            session->info->userdn
                            );
        if (rc != LDAP_COMPARE_TRUE) {
            snprintf(buf, sizeof buf, "You must be a %s of %s to login.", session->conf->groupattr, session->conf->groupdn);
            _conv_sendmsg(appconv, buf, PAM_ERROR_MSG, no_warn);           
            return PAM_AUTH_ERR;
        }
    }

    rc = _host_ok(session);
    if (rc == PAM_SUCCESS)
        rc = success;

    return rc;
}

/* static module data */
#ifdef PAM_STATIC
struct pam_module _modstruct = {
    "pam_ldap",
    pam_sm_authenticate,
    pam_sm_setcred,
    pam_sm_acct_mgmt,
    pam_sm_open_session,
    pam_sm_close_session,
    pam_sm_chauthtok
};
#endif /* PAM_STATIC */
