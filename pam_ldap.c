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
 * License along with the nss_ldap library; see the file COPYING.LIB.  If not,
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
 * Main coding by Elliot Lee <sopwith@redhat.com>, Red Hat Software.
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
#include <syslog.h>
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
#include <security/pam_appl.h>
#define PAM_EXTERN
#define CONST_ARG
#else
#define CONST_ARG const
#endif /* LINUX */
#include <security/pam_modules.h>

#ifdef LDAP_VERSION3
#define LDAP_MEMFREE(x)	ldap_memfree(x)
#else
#define LDAP_MEMFREE(x)	free(x)
#endif /* LDAP_VERSION3 */

static char rcsid[] = "$Id$";

void _release_config(
                         pam_ldap_config **pconfig
                         )
{
    pam_ldap_config *c;

    c = *pconfig;
    if (c == NULL)
        return;

    if (c->plc_host != NULL)
        free(c->plc_host);

    if (c->plc_base != NULL)
        free(c->plc_base);

    if (c->plc_binddn != NULL)
        free(c->plc_binddn);

    if (c->plc_bindpw != NULL) {
        memset(c->plc_bindpw, 0, strlen(c->plc_bindpw));
        free(c->plc_bindpw);
    }

    if (c->plc_sslpath != NULL) {
        free(c->plc_sslpath);
    }

    if (c->plc_attr != NULL) {
        free(c->plc_attr);
    }

    if (c->plc_objectclass != NULL) {
        free(c->plc_objectclass);
    }
    
    memset(c, 0, sizeof(*c));
    free(c);
    *pconfig = NULL;
    return;
}

void _release_session(
                            pam_ldap_session **session
                            )
{
    if (*session == NULL)
        return;

    ldap_unbind((*session)->pls_ld);
    _release_config(&(*session)->pls_conf);
    free(*session);
    *session = NULL;
    
    return;
}


#define CHECKPOINTER(ptr) do { if ((ptr) == NULL) { \
    fclose(fp); \
    return PAM_BUF_ERR; \
} \
} while (0)
int _allocconfig(
                 pam_ldap_config **presult
                 )
{
    pam_ldap_config *result;

    if (*presult == NULL) {
        *presult = (pam_ldap_config *)malloc(sizeof(*result));
        if (presult == NULL)
            return PAM_BUF_ERR;
    }

    result = *presult;

    result->plc_scope = LDAP_SCOPE_SUBTREE;
    result->plc_host = NULL;
    result->plc_base = NULL;
    result->plc_port = LDAP_PORT;
    result->plc_binddn = NULL;
    result->plc_bindpw = NULL;
    result->plc_sslpath = NULL;
    result->plc_objectclass = NULL;
    result->plc_attr = NULL;

    return PAM_SUCCESS;
}


#ifdef YPLDAPD
int _readconfig(
                        pam_ldap_config **presult
                        )
{
    pam_ldap_config *result;
    char *domain;
    int len;
    char *tmp;

    if (_allocconfig(presult) != PAM_SUCCESS) {
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
        return PAM_SERVICE_ERR;
    }

    result->plc_host = (char *)malloc(len + 1);
    if (result->plc_host == NULL)
        return PAM_BUF_ERR;
    
    memcpy(result->plc_host, tmp, len);
    result->plc_host[len] = '\0';
    free(tmp);

    if (yp_match(
                 domain,
                 "ypldapd.conf",
                 "basedn",
                 sizeof("basedn") - 1,
                 &tmp,
                 &len
                 )) {
        result->plc_base = NULL;
    } else {
        result->plc_base = (char *)malloc(len + 1);
        if (result->plc_base == NULL)
            return PAM_BUF_ERR;
        memcpy(result->plc_base, tmp, len);
        result->plc_base[len] = '\0';
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
        result->plc_port = LDAP_PORT;
    } else {
        result->plc_port = atoi(tmp);
        free(tmp);
    }
    
    yp_unbind(domain);

    result->plc_attr = strdup("uid");
    if (result->plc_attr == NULL) {
        return PAM_BUF_ERR;
    }

    return PAM_SUCCESS;
}
#else
int _readconfig(
                         pam_ldap_config **presult
                         )
{
    /* this is the same configuration file as nss_ldap */
    FILE *fp;
    char b[BUFSIZ];
    pam_ldap_config *result;

    if (_allocconfig(presult) != PAM_SUCCESS) {
        return PAM_BUF_ERR;
    }

    result = *presult;
    
    fp = fopen("/etc/ldap.conf", "r");
    if (fp == NULL) {
        return PAM_SERVICE_ERR;
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
            CHECKPOINTER(result->plc_host = strdup(v));
        } else if (!strcmp(k, "base")) {
            CHECKPOINTER(result->plc_base = strdup(v));
        } else if (!strcmp(k, "binddn")) {
            CHECKPOINTER(result->plc_binddn = strdup(v));
        } else if (!strcmp(k, "bindpw")) {
            CHECKPOINTER(result->plc_bindpw = strdup(v));
        } else if (!strcmp(k, "scope")) {
            if (!strcmp(v, "sub")) {
                result->plc_scope = LDAP_SCOPE_SUBTREE;
            } else if (!strcmp(v, "one")) {
                result->plc_scope = LDAP_SCOPE_ONELEVEL;
            } else if (!strcmp(v, "base")) {
                result->plc_scope = LDAP_SCOPE_BASE;
            }
        } else if (!strcmp(k, "port")) {
            result->plc_port = atoi(v);
        } else if (!strcmp(k, "sslpath")) {
            CHECKPOINTER(result->plc_sslpath = strdup(v));
        } else if (!strcmp(k, "pam_objectclass")) {
            CHECKPOINTER(result->plc_objectclass = strdup(v));
        } else if (!strcmp(k, "pam_attribute")) {
            CHECKPOINTER(result->plc_attr = strdup(v));
        }
    }

    fclose(fp);
    if (result->plc_host == NULL) {
        return PAM_SERVICE_ERR;
    }
    
    if (result->plc_attr == NULL) {
        CHECKPOINTER(result->plc_attr = strdup("uid"));
    }    
        
    return PAM_SUCCESS;
}
#endif

static int _open_session(
                                  pam_ldap_session *session
                                  )
{
    session->pls_ld = ldap_init(
                                session->pls_conf->plc_host,
                                session->pls_conf->plc_port
                                );
    if (session->pls_ld == NULL) {
        return PAM_SERVICE_ERR;
    }

#ifdef SSL
    if (session->pls_conf->plc_sslpath != NULL) {
        rc = ldapssl_client_init(session->pls_conf->plc_sslpath, NULL);
        if (rc != LDAP_SUCCESS) {
            syslog(LOG_ERR, "pam_ldap: ldapssl_client_init %s", ldap_err2string(rc));
            return PAM_SERVICE_ERR;
        }
        rc = ldapssl_install_routines(session->pls_ld);
        if (rc != LDAP_SUCCESS) {
            syslog(LOG_ERR, "pam_ldap: ldap_simple_bind_s %s", ldap_err2string(rc));
            return PAM_SERVICE_ERR;
        }
        rc = ldap_set_option(session->pls_ld, LDAP_OPT_SSL, LDAP_OPT_ON);
        if (rc != LDAP_SUCCESS) {
            return PAM_SERVICE_ERR;
        }
    }
#endif /* SSL */

#ifdef LDAP_VERSION3
    session->pls_ldapversion = LDAP_VERSION3;
    if (ldap_set_option(session->pls_ld, LDAP_OPT_PROTOCOL_VERSION, &session->pls_ldapversion) != LDAP_SUCCESS) {
        session->pls_ldapversion = LDAP_VERSION2;
    }
#endif /* LDAP_VERSION3 */

    return PAM_SUCCESS;

}

static int _uid2dn(
                            pam_ldap_session *session,
                            const char *user,
                            char **dn
                            )
{
    char filter[LDAP_FILT_MAXSIZ];
    int rc;
    LDAPMessage *res, *msg;

    if (dn != NULL)
        *dn = NULL;
    
    if (session->pls_ld == NULL) {
        rc = _open_session(session);
        if (rc != PAM_SUCCESS)
            return rc;
        /* need to bind first */
        rc = ldap_simple_bind_s(
                                session->pls_ld,
                                session->pls_conf->plc_binddn,
                                session->pls_conf->plc_bindpw
                                );
        if (rc != LDAP_SUCCESS) {
            syslog(LOG_ERR, "pam_ldap: ldap_simple_bind_s %s", ldap_err2string(rc));
            return PAM_CRED_INSUFFICIENT;
        }
    }

#ifdef LDAP_VERSION3
    rc = 1;
    (void) ldap_set_option(session->pls_ld, LDAP_OPT_SIZELIMIT, &rc);
#else
    session->pls_ld->ld_sizelimit = 1;
#endif /* LDAP_VERSION3 */

    if (session->pls_conf->plc_objectclass != NULL) {
        snprintf(filter, sizeof filter, "(&(objectclass=%s)(%s=%s))",
                 session->pls_conf->plc_objectclass,
                 session->pls_conf->plc_attr,
                 user);
    } else {
        snprintf(filter, sizeof filter, "(%s=%s)",
                 session->pls_conf->plc_attr,
                 user);
    }
    
    rc = ldap_search_s(
                       session->pls_ld,
                       session->pls_conf->plc_base,
                       session->pls_conf->plc_scope,
                       filter,
                       NULL,
                       0,
                       &res
                       );

    if (rc != LDAP_SUCCESS) {
        syslog(LOG_ERR, "pam_ldap: ldap_search_s %s", ldap_err2string(rc)); 
        return PAM_USER_UNKNOWN;
    }

    msg = ldap_first_entry(session->pls_ld, res);
    if (msg == NULL) {
        ldap_msgfree(res);
        return PAM_USER_UNKNOWN;
    }

    if (dn != NULL) {
        *dn = ldap_get_dn(session->pls_ld, msg);
    }

    ldap_msgfree(res);

    return (dn != NULL && *dn == NULL) ? PAM_SERVICE_ERR : PAM_SUCCESS;
}


static int _initialize(
                                pam_ldap_session **psession
                                )
{
    pam_ldap_session *session;
    int rc;

    session = (pam_ldap_session *)malloc(sizeof(*session));
    *psession = session;
    if (session == NULL) {
        return PAM_BUF_ERR;
    }

    session->pls_ld = NULL;
    session->pls_conf = NULL;
    session->pls_ldapversion = LDAP_VERSION2;

    rc = _readconfig(&session->pls_conf);
    if (rc != PAM_SUCCESS) {
        _release_session(psession);
        return rc;
    }

    return PAM_SUCCESS;
}

static int _reopen(
                            pam_ldap_session *session
                            )
{
    if (session->pls_ldapversion == LDAP_VERSION2) {
        ldap_unbind(session->pls_ld);
        return _open_session(session);
    }
    return PAM_SUCCESS;
}

static int _validate(
                              const char *user,
                              const char *password,
                              pam_ldap_session **psession
                              )
{
    int rc;
    char *dn = NULL;
    pam_ldap_session *session;

    if (psession != NULL) {
        if (*psession != NULL) {
            rc = _reopen(*psession);
        } else {
            rc = _initialize(psession);
        }
        session = *psession;
    } else {
        rc = _initialize(&session);
    }

    /* calling this ensures that pls_ld is set */
    rc = _uid2dn(session, user, &dn);
    if (rc != PAM_SUCCESS) {
        goto out;
    }

    if (session->pls_ldapversion == LDAP_VERSION2) {
        /* can't do another bind */
        ldap_unbind(session->pls_ld);
        rc = _open_session(session);
        if (rc != PAM_SUCCESS)
            goto out;
    }
    
    rc = ldap_simple_bind_s(
                            session->pls_ld,
                            dn,
                            password
                            );

    if (rc != LDAP_SUCCESS) {
        syslog(LOG_ERR, "pam_ldap: ldap_simple_bind_s %s", ldap_err2string(rc));
        rc = PAM_AUTH_ERR;
    } else {
        rc = PAM_SUCCESS;
    }
    
out:
    if (dn != NULL)
        LDAP_MEMFREE(dn);

    if (psession == NULL) {
        _release_session(&session);
    }

    return rc;
}

static int _change_password(
                                     char *user,
                                     char *old_password,
                                     char *new_password,
                                     pam_ldap_session **psession
                                     )
{
    char *dn = NULL;
    char *strvals[2];
    LDAPMod *mods[2], mod;
    int rc;
    pam_ldap_session *session;

    if (psession != NULL) {
        if (*psession != NULL) {           
            rc = _reopen(*psession);
        } else {
            rc = _initialize(psession);
        }
        session = *psession;
    } else {       
	rc = _initialize(&session);
    }
    
    if (rc != PAM_SUCCESS) {
        goto out;
    }

    /* calling this ensures that pls_ld is set */
    rc = _uid2dn(session, user, &dn);
    if (rc != PAM_SUCCESS) {
        goto out;
    }

    rc = _reopen(session);
    if (rc != PAM_SUCCESS) {
        goto out;
    }

    rc = ldap_simple_bind_s(
                            session->pls_ld,
                            dn,
                            old_password
                            );

    if (rc != LDAP_SUCCESS) {
        syslog(LOG_ERR, "pam_ldap: ldap_simple_bind_s %s", ldap_err2string(rc));
        rc = PAM_AUTH_ERR;
    } else
        rc = PAM_SUCCESS;

    /* note: this assumes that the server generates the password hash */
    strvals[0] = new_password;
    strvals[1] = NULL;

    mod.mod_vals.modv_strvals = strvals;
    mod.mod_type = "userPassword";
    mod.mod_op = LDAP_MOD_REPLACE;
#ifndef LDAP_VERSION3
    mod.mod_next = NULL;
#endif /* LDAP_VERSION3 */

    mods[0] = &mod;
    mods[1] = NULL;

    rc = ldap_modify_s(
                       session->pls_ld,
                       dn,
                       mods
                       );
    if (rc != LDAP_SUCCESS) {        
        syslog(LOG_ERR, "pam_ldap: ldap_modify_s %s", ldap_err2string(rc));
        rc = PAM_PERM_DENIED;
    } else {
        rc = PAM_SUCCESS;
    }
        

out:
    if (dn != NULL)
        LDAP_MEMFREE(dn);

    if (psession == NULL) {
        _release_session(&session);
    }

    return rc;        
}    

static int _set_auth_tok(
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

static int conv_sendmsg(
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
    const char *name;
    char *p;
    int use_first_pass = 0, try_first_pass = 0;
    int i;

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
            syslog(LOG_DEBUG, "unknown module option %s", argv[i]);
    }

    rc = pam_get_user(pamh, (CONST_ARG char **)&name, NULL);
    if (rc != PAM_SUCCESS)
        return rc;

    pam_get_item(pamh, PAM_AUTHTOK, (void *)&p);
    if (p != NULL && (use_first_pass || try_first_pass)) {
        rc = _validate(name, p, NULL);
        if (rc == PAM_SUCCESS || use_first_pass) {
            return rc;
        }
    }

    rc = _set_auth_tok(pamh, flags, (p == NULL) ? 1 : 0);
    if (rc != PAM_SUCCESS) {
        return rc;
    }
    
    pam_get_item(pamh, PAM_AUTHTOK, (void *)&p);
    if (p == NULL)
        return PAM_AUTH_ERR;

    return _validate(name, p, NULL);
}


PAM_EXTERN int pam_sm_chauthtok(
                                pam_handle_t *pamh,
                                int flags,
                                int argc,
                                const char **argv
                                )
{
    int rc = PAM_SUCCESS;
    char *usrname, *curpass = NULL, *newpass = NULL;
    struct pam_conv *appconv;
    struct pam_message msg, *pmsg;
    struct pam_response *resp;
    const char *cmiscptr = NULL;
    int tries = 0, i;
    pam_ldap_session *session = NULL;
    int use_first_pass = 0, try_first_pass = 0, no_warn = 0;
    char errmsg[1024];

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
            syslog(LOG_DEBUG, "unknown module option %s", argv[i]);
    }

    rc = pam_get_item(pamh, PAM_CONV, (CONST_ARG void **)&appconv);
    if (rc != PAM_SUCCESS)
        return rc;

    rc = pam_get_item(pamh, PAM_USER, (CONST_ARG void **)&usrname);
    if (rc != PAM_SUCCESS)
        return rc;

    if (usrname == NULL || strlen(usrname) < 1)
        return PAM_USER_UNKNOWN;
    
    if (flags & PAM_PRELIM_CHECK) {
        /* see whether the user exists */
        rc = _initialize(&session);
        if (rc != PAM_SUCCESS) {
            return rc;
        }

        rc = _uid2dn(session, usrname, NULL);
        _release_session(&session);
        return rc;
    }

    if (try_first_pass || use_first_pass) {
        if (pam_get_item(pamh, PAM_OLDAUTHTOK, (CONST_ARG void **)&curpass) == PAM_SUCCESS) {
            rc = _validate(usrname, curpass, &session);
            if (use_first_pass && rc != PAM_SUCCESS) {
                conv_sendmsg(appconv, "LDAP Password incorrect", PAM_ERROR_MSG, no_warn);
                goto out;
            } else {
                conv_sendmsg(appconv, "LDAP Password incorrect: try again", PAM_ERROR_MSG, no_warn);
            }
        } else {
            curpass = NULL;
        }
    }
    
    tries = 0;
    
    while ((curpass == NULL) && (tries++ < MAX_PASSWD_TRIES)) {
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
            goto out;
        
        curpass = resp->resp;
        free(resp);

        /* validate the old password */
        rc = _validate(usrname, curpass, &session);
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
                conv_sendmsg(appconv, "Password change aborted", PAM_ERROR_MSG, no_warn);
                rc = PAM_AUTHTOK_ERR;
                goto out;
            } else {
                conv_sendmsg(appconv, "LDAP Password incorrect: try again", PAM_ERROR_MSG, no_warn);
            }
        }
    }

    if (curpass == NULL) {
        rc = PAM_AUTHTOK_ERR;
        goto out;
    }

    pam_set_item(pamh, PAM_OLDAUTHTOK, (void *)curpass);

    if (try_first_pass || use_first_pass) {
        if (pam_get_item(pamh, PAM_AUTHTOK, (CONST_ARG void **)&newpass) != PAM_SUCCESS) {
            newpass = NULL;
        }
        if (use_first_pass && newpass == NULL) {
            rc = PAM_AUTHTOK_ERR;
            goto out;
        }
    }

    tries = 0;

    while ((newpass == NULL) && (tries++ < MAX_PASSWD_TRIES)) {
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
            goto out;
        
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
            }
        } else {
            rc = PAM_AUTHTOK_ERR;
            goto out;
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
                goto out;

            miscptr = resp->resp;
            free(resp);
            if (miscptr[0] == '\0') {
                free(miscptr);
                miscptr = NULL;
            }
            if (miscptr == NULL) {
                conv_sendmsg(appconv, "Password change aborted", PAM_ERROR_MSG, no_warn);
                rc = PAM_AUTHTOK_ERR;
                goto out;
            }
            if (!strcmp(newpass, miscptr)) {
                miscptr = NULL;
                break;
            }
            conv_sendmsg(appconv, "You must enter the same password", PAM_ERROR_MSG, no_warn);
            miscptr = NULL;
            newpass = NULL;
        } else {
            conv_sendmsg(appconv, cmiscptr, PAM_ERROR_MSG, no_warn);
            cmiscptr = NULL;
            newpass = NULL;
        }
    }
    
    if (cmiscptr != NULL || newpass == NULL) {
        rc = PAM_AUTHTOK_ERR;
        goto out;
    }

    pam_set_item(pamh, PAM_AUTHTOK, (void *)newpass);
    rc = _change_password(usrname, curpass, newpass, &session);
    if (rc != PAM_SUCCESS) {
        int lderr;        
#ifdef LDAP_VERSION3
        lderr = ldap_get_lderrno(session->pls_ld, NULL, NULL);
#else
        lderr = session->pls_ld->ld_errno;
#endif /* LDAP_VERSION3 */
        snprintf(errmsg, sizeof errmsg, "LDAP password information update failed (%s)", ldap_err2string(lderr));
        conv_sendmsg(appconv, errmsg, PAM_ERROR_MSG, no_warn);
    } else {
        snprintf(errmsg, sizeof errmsg, "LDAP password information changed for %s", usrname);
        conv_sendmsg(appconv, errmsg, PAM_TEXT_INFO, 0);
    }                    

out:

    _release_session(&session);
    
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

#if 0
PAM_EXTERN int pam_sm_acct_mgmt(
                                pam_handle_t *pamh,
                                int flags,
                                int argc
                                const char **argv
                                )
{
    /* check whether the user can login */
    /* returns PAM_ACCT_EXPIRED
       PAM_AUTH_ERR
       PAM_AUTHTOKEN_REQD (expired)
       PAM_USER_UNKNOWN
     */
}
#endif

/* static module data */
#ifdef PAM_STATIC
struct pam_module _modstruct = {
    "pam_ldap",
    pam_sm_authenticate,
    pam_sm_setcred,
    NULL,
    NULL,
    NULL,
    pam_sm_chauthtok
};
#endif /* PAM_STATIC */

#ifdef TESTING
main(int argc, char **argv)
{
	int rc;
   char *p = (argc > 1) ? argv[1] : "test";
	char *np = (argc > 2) ? argv[2] : "test2";
	fprintf(stderr, "%d\n", _validate("lukeh", p, NULL));
	fprintf(stderr, "%d\n", _change_password("lukeh", p, np, NULL));
	return rc;
}
#endif
