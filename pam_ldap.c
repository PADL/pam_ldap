/*
 * Copyright (C) 1998, 1999, 2000 Luke Howard.
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

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/param.h>
#include <unistd.h>
#include <syslog.h>
#include <netdb.h>
#include <errno.h>

#if defined(HAVE_CRYPT_H)
#include <crypt.h>
#elif defined(HAVE_DES_H)
#include <des.h>
#endif

#ifdef HAVE_LBER_H
#include <lber.h>
#endif
#ifdef HAVE_LDAP_H
#include <ldap.h>
#endif
#ifdef HAVE_LDAP_SSL_H
#include <ldap_ssl.h>
#endif

#ifdef YPLDAPD
#include <rpcsvc/yp_prot.h>
#include <rpcsvc/ypclnt.h>
#endif /* YPLDAPD */

#include "pam_ldap.h"
#include "md5.h"

#ifdef HAVE_SECURITY_PAM_MISC_H
 /* FIXME: is there something better to check? */
#define CONST_ARG const
#else
#define CONST_ARG
#endif

#ifndef HAVE_LDAP_MEMFREE
#define ldap_memfree(x)	free(x)
#endif

#ifdef __GNUC__
#define __UNUSED__ __attribute__ ((unused))
#else
#define __UNUSED__
#endif

static char rcsid[] __UNUSED__ =
  "$Id$";
#if HAVE_LDAP_SET_REBIND_PROC_ARGS < 3
static pam_ldap_session_t *global_session = 0;
#endif
static int pam_debug_level __UNUSED__ = 0;

#ifdef HAVE_LDAPSSL_INIT
static int ssl_initialized = 0;
#endif

#define DEBUG_MSG(level, fmt, args...)		\
	do {					\
		if (level >= pam_debug_level)	\
			syslog(LOG_DEBUG, "%s:%i " fmt , __FUNCTION__ , __LINE__ , ## args); \
	} while (0)


#ifdef HAVE_LIBPTHREAD
#include <dlfcn.h>

/*
 * on Linux at least, the pthread library registers an atexit
 * handler in it's constructor.  Since we are in a library and linking with
 * libpthread, if the client program is not linked with libpthread, it
 * segfaults on exit. So we open an extra reference to the library.
 * 
 * If there is a better way of doing this, let us know.
 */
void nasty_pthread_hack (void) __attribute__ ((constructor));

void
nasty_pthread_hack (void)
{
  (void) dlopen ("libpthread.so", RTLD_LAZY);
}
#endif /* HAVE_LIBPTHREAD */

#ifdef HAVE_LDAPSSL_INIT
/*
 * We need to keep ourselves loaded so that ssl_initialized
 * is set across PAM sessions.
 */
void nasty_ssl_hack (void) __attribute__ ((constructor));

void
nasty_ssl_hack (void)
{
  (void) dlopen ("/lib/security/pam_ldap.so", RTLD_LAZY);
}
#endif /* HAVE_LDAPSSL_INIT */

/* i64c - convert an integer to a radix 64 character */
static int
i64c (int i)
{
  const char *base64 =
    "./01234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
  if (i < 0)
    i = 0;
  else if (i > 63)
    i = 63;

  return base64[i];
}

#ifndef HAVE_LDAP_GET_LDERRNO
static int
ldap_get_lderrno (LDAP * ld, char **m, char **s)
{
  int rc;
  int lderrno;

#ifdef LDAP_OPT_ERROR_NUMBER
  /* is this needed? */
  rc = ldap_get_option (ld, LDAP_OPT_ERROR_NUMBER, &lderrno);
  if (rc != LDAP_SUCCESS)
    return rc;
#else
  lderrno = ld->ld_errno;
#endif

  if (s != NULL)
    {
#ifdef LDAP_OPT_ERROR_STRING
      rc = ldap_get_option (ld, LDAP_OPT_ERROR_STRING, &s);
      if (rc != LDAP_SUCCESS)
	return rc;
#else
      *s = ld->ld_error;
#endif
    }

  if (m != NULL)
    {
      *m = NULL;
    }

  return lderrno;
}
#endif

static void
_release_config (pam_ldap_config_t ** pconfig)
{
  pam_ldap_config_t *c;

  c = *pconfig;
  if (c == NULL)
    return;

  if (c->host != NULL)
    free (c->host);

  if (c->base != NULL)
    free (c->base);

  if (c->binddn != NULL)
    free (c->binddn);

  if (c->bindpw != NULL)
    {
      _pam_overwrite (c->bindpw);
      _pam_drop (c->bindpw);
    }

  if (c->rootbinddn != NULL)
    free (c->rootbinddn);

  if (c->rootbindpw != NULL)
    {
      _pam_overwrite (c->rootbindpw);
      _pam_drop (c->rootbindpw);
    }

  if (c->sslpath != NULL)
    {
      free (c->sslpath);
    }

  if (c->userattr != NULL)
    {
      free (c->userattr);
    }

  if (c->tmplattr != NULL)
    {
      free (c->tmplattr);
    }

  if (c->tmpluser != NULL)
    {
      free (c->tmpluser);
    }

  if (c->groupattr != NULL)
    {
      free (c->groupattr);
    }

  if (c->groupdn != NULL)
    {
      free (c->groupdn);
    }

  if (c->filter != NULL)
    {
      free (c->filter);
    }

  memset (c, 0, sizeof (*c));
  free (c);
  *pconfig = NULL;

  return;
}

static void
_release_user_info (pam_ldap_user_info_t ** info)
{
  if (*info == NULL)
    return;

  if ((*info)->userdn != NULL)
    {
      ldap_memfree ((void *) (*info)->userdn);
    }

  /*
   * Clobber the password.
   */
  _pam_overwrite ((*info)->userpw);
  _pam_drop ((*info)->userpw);

  if ((*info)->hosts_allow != NULL)
    {
      ldap_value_free ((*info)->hosts_allow);
    }

  if ((*info)->tmpluser != NULL)
    {
      free ((void *) (*info)->tmpluser);
    }

  free ((void *) (*info)->username);
  free (*info);

  *info = NULL;
  return;
}

static void
_pam_ldap_cleanup_session (pam_handle_t * pamh, void *data, int error_status)
{
  pam_ldap_session_t *session = (pam_ldap_session_t *) data;

  if (session == NULL)
    return;

  if (session->ld != NULL)
    {
      ldap_unbind (session->ld);
      session->ld = NULL;
    }

  _release_config (&session->conf);
  _release_user_info (&session->info);

  free (data);
#if HAVE_LDAP_SET_REBIND_PROC_ARGS < 3
  global_session = 0;
#endif

  return;
}

static void
_cleanup_data (pam_handle_t * pamh, void *data, int error_status)
{
  if (data != NULL)
    free (data);

  return;
}

static int
_alloc_config (pam_ldap_config_t ** presult)
{
  pam_ldap_config_t *result;

  if (*presult == NULL)
    {
      *presult = (pam_ldap_config_t *) calloc (1, sizeof (*result));
      if (*presult == NULL)
	return PAM_BUF_ERR;
    }

  result = *presult;

  result->scope = LDAP_SCOPE_SUBTREE;
  result->deref = LDAP_DEREF_NEVER;
  result->host = NULL;
  result->base = NULL;
  result->port = 0;
  result->binddn = NULL;
  result->bindpw = NULL;
  result->rootbinddn = NULL;
  result->rootbindpw = NULL;
  result->ssl_on = SSL_OFF;
  result->sslpath = NULL;
  result->filter = NULL;
  result->userattr = NULL;
  result->groupattr = NULL;
  result->groupdn = NULL;
  result->getpolicy = 0;
#ifdef LDAP_VERSION3
  result->version = LDAP_VERSION3;
#else
  result->version = LDAP_VERSION2;
#endif /* LDAP_VERSION2 */
  result->timelimit = LDAP_NO_LIMIT;
  result->bind_timelimit = 10;
  result->referrals = 1;
  result->restart = 1;
  result->password_type = PASSWORD_CLEAR;
  result->min_uid = 0;
  result->max_uid = 0;
  result->tmplattr = NULL;
  result->tmpluser = NULL;

  return PAM_SUCCESS;
}


#ifdef YPLDAPD
/*
 * Use the "internal" ypldapd.conf map to figure some things
 * out.
 */
static int
_ypldapd_read_config (pam_ldap_config_t ** presult)
{
  pam_ldap_config_t *result;
  char *domain;
  int len;
  char *tmp;

  if (_alloc_config (presult) != PAM_SUCCESS)
    {
      return PAM_BUF_ERR;
    }

  result = *presult;

  yp_get_default_domain (&domain);
  yp_bind (domain);
  if (yp_match (domain,
		"ypldapd.conf",
		"ldaphost", sizeof ("ldaphost") - 1, &tmp, &len))
    {
      return PAM_SYSTEM_ERR;
    }

  result->host = (char *) malloc (len + 1);
  if (result->host == NULL)
    return PAM_BUF_ERR;

  memcpy (result->host, tmp, len);
  result->host[len] = '\0';
  free (tmp);

  if (yp_match (domain,
		"ypldapd.conf", "basedn", sizeof ("basedn") - 1, &tmp, &len))
    {
      result->base = NULL;
    }
  else
    {
      result->base = (char *) malloc (len + 1);
      if (result->base == NULL)
	return PAM_BUF_ERR;
      memcpy (result->base, tmp, len);
      result->base[len] = '\0';
      free (tmp);
    }

  if (yp_match (domain,
		"ypldapd.conf",
		"ldapport", sizeof ("ldapport") - 1, &tmp, &len))
    {
      result->port = LDAP_PORT;
    }
  else
    {
      char *p = (char *) malloc (len + 1);
      if (p == NULL)
	return PAM_BUF_ERR;
      memcpy (p, tmp, len);
      result->port = atoi (p);
      free (tmp);
      free (p);
    }

  yp_unbind (domain);

  result->userattr = strdup ("uid");
  if (result->userattr == NULL)
    {
      return PAM_BUF_ERR;
    }

  /* turn on getting policies */
  result->getpolicy = 1;
#ifdef LDAP_VERSION3
  result->version = LDAP_VERSION3;
#endif

  return PAM_SUCCESS;
}
#endif /* YPLDAPD */

#define CHECKPOINTER(ptr) do { if ((ptr) == NULL) { \
    fclose(fp); \
    return PAM_BUF_ERR; \
} \
} while (0)

static int
_read_config (const char *configFile, pam_ldap_config_t ** presult)
{
  /* this is the same configuration file as nss_ldap */
  FILE *fp;
  char b[BUFSIZ];
  char *defaultBase, *passwdBase, *defaultFilter, *passwdFilter;
  int defaultScope, passwdScope;
  pam_ldap_config_t *result;
  char errmsg[MAXPATHLEN + 25];

  if (_alloc_config (presult) != PAM_SUCCESS)
    {
      return PAM_BUF_ERR;
    }

  result = *presult;

  /* configuration file location is configurable; default /etc/ldap.conf */
  if (configFile == NULL)
    configFile = "/etc/ldap.conf";

  fp = fopen (configFile, "r");

  if (fp == NULL)
    {
      /* 
       * According to PAM Documentation, such an error in a config file
       * SHOULD be logged at LOG_ALERT level
       */
      snprintf (errmsg, sizeof (errmsg), "pam_ldap: missing file \"%s\"",
		configFile);
      syslog (LOG_ALERT, errmsg);
      return PAM_SYSTEM_ERR;
    }

  defaultBase = NULL;
  defaultFilter = NULL;
  defaultScope = LDAP_SCOPE_SUBTREE;

  passwdBase = NULL;
  passwdFilter = NULL;
  passwdScope = -1;

  while (fgets (b, sizeof (b), fp) != NULL)
    {
      char *k, *v;
      int len;

      if (*b == '\n' || *b == '#')
	continue;

      k = b;
      v = k;
      while (*v != '\0' && *v != ' ' && *v != '\t')
	v++;

      if (*v == '\0')
	continue;

      *(v++) = '\0';

      /* skip all whitespaces between keyword and value */
      /* Lars Oergel <lars.oergel@innominate.de>, 05.10.2000 */
      while (*v == ' ' || *v == '\t')
	v++;

      len = strlen (v);
      v[--len] = '\0';

      if (!strcasecmp (k, "host"))
	{
	  CHECKPOINTER (result->host = strdup (v));
	}
      else if (!strcasecmp (k, "base"))
	{
	  CHECKPOINTER (defaultBase = strdup (v));
	}
      else if (!strcasecmp (k, "binddn"))
	{
	  CHECKPOINTER (result->binddn = strdup (v));
	}
      else if (!strcasecmp (k, "bindpw"))
	{
	  CHECKPOINTER (result->bindpw = strdup (v));
	}
      else if (!strcasecmp (k, "rootbinddn"))
	{
	  CHECKPOINTER (result->rootbinddn = strdup (v));
	}
      else if (!strcasecmp (k, "scope"))
	{
	  if (!strcasecmp (v, "sub"))
	    result->scope = LDAP_SCOPE_SUBTREE;
	  else if (!strcasecmp (v, "one"))
	    result->scope = LDAP_SCOPE_ONELEVEL;
	  else if (!strcasecmp (v, "base"))
	    result->scope = LDAP_SCOPE_BASE;
	}
      else if (!strcasecmp (k, "deref"))
	{
	  if (!strcasecmp (v, "never"))
	    result->deref = LDAP_DEREF_NEVER;
	  else if (!strcasecmp (v, "searching"))
	    result->deref = LDAP_DEREF_SEARCHING;
	  else if (!strcasecmp (v, "finding"))
	    result->deref = LDAP_DEREF_FINDING;
	  else if (!strcasecmp (v, "always"))
	    result->deref = LDAP_DEREF_ALWAYS;
	}
      else if (!strcasecmp (k, "pam_password"))
	{
	  if (!strcasecmp (v, "clear"))
	    result->password_type = PASSWORD_CLEAR;
	  else if (!strcasecmp (v, "crypt"))
	    result->password_type = PASSWORD_CRYPT;
	  else if (!strcasecmp (v, "md5"))
	    result->password_type = PASSWORD_MD5;
	  else if (!strcasecmp (v, "nds"))
	    result->password_type = PASSWORD_NDS;
	  else if (!strcasecmp (v, "ad"))
	    result->password_type = PASSWORD_AD;
	  else if (!strcasecmp (v, "exop"))
	    result->password_type = PASSWORD_EXOP;
	}
      else if (!strcasecmp (k, "pam_crypt"))
	{
	  /*
	   * we still support this even though it is 
	   * deprecated, as it could be a security
	   * hole to change this behaviour on 
	   * unsuspecting users of pam_ldap.
	   */
	  if (!strcasecmp (v, "local"))
	    result->password_type = PASSWORD_CRYPT;
	  else
	    result->password_type = PASSWORD_CLEAR;
	}
      else if (!strcasecmp (k, "port"))
	{
	  result->port = atoi (v);
	}
      else if (!strcasecmp (k, "timelimit"))
	{
	  result->timelimit = atoi (v);
	}
      else if (!strcasecmp (k, "bind_timelimit"))
	{
	  result->bind_timelimit = atoi (v);
	}
      else if (!strcasecmp (k, "nss_base_passwd"))
	{
	  char *s;

	  /* this doesn't do any escaping. XXX. */
	  CHECKPOINTER (passwdBase = strdup (v));
	  s = strchr (passwdBase, '?');
	  if (s != NULL)
	    {
	      *s = '\0';
	      s++;
	      if (!strcasecmp (s, "sub"))
		passwdScope = LDAP_SCOPE_SUBTREE;
	      else if (!strcasecmp (s, "one"))
		passwdScope = LDAP_SCOPE_ONELEVEL;
	      else if (!strcasecmp (s, "base"))
		passwdScope = LDAP_SCOPE_BASE;
	    }
	  s = strchr (s, '?');
	  if (s != NULL)
	    {
	      *s = '\0';
	      s++;
	      CHECKPOINTER (passwdFilter = strdup (s));
	    }
	}
      else if (!strcasecmp (k, "ldap_version"))
	{
	  result->version = atoi (v);
	}
      else if (!strcasecmp (k, "sslpath"))
	{
	  CHECKPOINTER (result->sslpath = strdup (v));
	}
      else if (!strcasecmp (k, "ssl"))
	{
	  if (!strcasecmp (v, "on") || !strcasecmp (v, "yes")
	      || !strcasecmp (v, "true"))
	    {
	      result->ssl_on = SSL_LDAPS;
	    }
	  else if (!strcasecmp (v, "start_tls"))
	    {
	      result->ssl_on = SSL_START_TLS;
	    }
	}
      else if (!strcasecmp (k, "referrals"))
	{
	  result->referrals = (!strcasecmp (v, "on") || !strcasecmp (v, "yes")
			       || !strcasecmp (v, "true"));
	}
      else if (!strcasecmp (k, "restart"))
	{
	  result->restart = (!strcasecmp (v, "on") || !strcasecmp (v, "yes")
			     || !strcasecmp (v, "true"));
	}
      else if (!strcasecmp (k, "pam_filter"))
	{
	  CHECKPOINTER (defaultFilter = strdup (v));
	}
      else if (!strcasecmp (k, "pam_login_attribute"))
	{
	  CHECKPOINTER (result->userattr = strdup (v));
	}
      else if (!strcasecmp (k, "pam_template_login_attribute"))
	{
	  CHECKPOINTER (result->tmplattr = strdup (v));
	}
      else if (!strcasecmp (k, "pam_template_login"))
	{
	  CHECKPOINTER (result->tmpluser = strdup (v));
	}
      else if (!strcasecmp (k, "pam_lookup_policy"))
	{
	  result->getpolicy = !strcasecmp (v, "yes");
	}
      else if (!strcasecmp (k, "pam_groupdn"))
	{
	  CHECKPOINTER (result->groupdn = strdup (v));
	}
      else if (!strcasecmp (k, "pam_member_attribute"))
	{
	  CHECKPOINTER (result->groupattr = strdup (v));
	}
      else if (!strcasecmp (k, "pam_min_uid"))
	{
	  result->min_uid = (uid_t) atol (v);
	}
      else if (!strcasecmp (k, "pam_max_uid"))
	{
	  result->max_uid = (uid_t) atol (v);
	}
    }

  if (passwdBase != NULL)
    {
      if (defaultBase != NULL)
	{
	  size_t len = strlen (passwdBase);

	  if (passwdBase[len - 1] == ',')
	    {
	      char *p;

	      p = (char *) malloc (len + strlen (defaultBase) + 1);
	      if (p == NULL)
		{
		  fclose (fp);
		  free (defaultBase);	/* leak the rest... */
		  return PAM_BUF_ERR;
		}

	      strcpy (p, passwdBase);
	      strcpy (&p[len], defaultBase);
	      free (passwdBase);
	      passwdBase = p;
	    }
	  free (defaultBase);
	}
      result->base = passwdBase;
    }
  else
    {
      result->base = defaultBase;
    }

  if (passwdFilter != NULL)
    {
      result->filter = passwdFilter;
      if (defaultFilter != NULL)
	free (defaultFilter);
    }
  else
    {
      result->filter = defaultFilter;
    }

  if (passwdScope != -1)
    {
      result->scope = passwdScope;
    }
  else
    {
      result->scope = defaultScope;
    }

  if (result->host == NULL)
    {
      /* 
       * According to PAM Documentation, such an error in a config file
       * SHOULD be logged at LOG_ALERT level
       */
      syslog (LOG_ALERT, "pam_ldap: missing \"host\" in file \"ldap.conf\"");
      return PAM_SYSTEM_ERR;
    }

  if (result->userattr == NULL)
    {
      CHECKPOINTER (result->userattr = strdup ("uid"));
    }

  if (result->groupattr == NULL)
    {
      CHECKPOINTER (result->groupattr = strdup ("uniquemember"));
    }

  if (result->port == 0)
    {
#if defined(HAVE_LDAPSSL_INIT) || defined(HAVE_LDAP_START_TLS_S)
      if (result->ssl_on == SSL_LDAPS)
	{
	  result->port = LDAPS_PORT;
	}
      else
#endif
	result->port = LDAP_PORT;
    }

  fclose (fp);

  if (result->rootbinddn != NULL)
    {
      fp = fopen ("/etc/ldap.secret", "r");
      if (fp != NULL)
	{
	  if (fgets (b, sizeof (b), fp) != NULL)
	    {
	      int len;
	      len = strlen (b);
	      if (len > 0 && b[len - 1] == '\n')
		len--;

	      b[len] = '\0';
	      result->rootbindpw = strdup (b);
	    }
	  fclose (fp);
	}
      else
	{
	  _pam_drop (result->rootbinddn);
	  syslog (LOG_WARNING,
		  "pam_ldap: could not open secret file /etc/ldap.secret (%s)",
		  strerror (errno));
	}
    }

  /* can't use _pam_overwrite because it only goes to end of string, 
   * not the buffer
   */
  memset (b, 0, BUFSIZ);
  return PAM_SUCCESS;
}

static int
_open_session (pam_ldap_session_t * session)
{
#ifdef LDAP_X_OPT_CONNECT_TIMEOUT
  int timeout;
#endif

#ifdef HAVE_LDAPSSL_INIT
  int rc;

  if (session->conf->ssl_on == SSL_LDAPS && ssl_initialized == 0)
    {
      rc = ldapssl_client_init (session->conf->sslpath, NULL);
      if (rc != LDAP_SUCCESS)
	{
	  syslog (LOG_ERR, "pam_ldap: ldapssl_client_init %s",
		  ldap_err2string (rc));
	  return PAM_SYSTEM_ERR;
	}
      ssl_initialized = 1;
    }

  if (session->conf->ssl_on)
    {
      session->ld = ldapssl_init (session->conf->host,
				  session->conf->port, TRUE);
    }
  else
#endif /* HAVE_LDAPSSL_INIT */
    {
#ifdef HAVE_LDAP_INIT
      session->ld = ldap_init (session->conf->host, session->conf->port);
#else
      session->ld = ldap_open (session->conf->host, session->conf->port);
#endif /* HAVE_LDAP_INIT */
    }

  if (session->ld == NULL)
    {
      return PAM_SYSTEM_ERR;
    }

#ifdef LDAP_OPT_X_TLS
  if (session->conf->ssl_on == SSL_LDAPS)
    {
      int tls = LDAP_OPT_X_TLS_HARD;
      int rc = ldap_set_option (session->ld, LDAP_OPT_X_TLS, &tls);
      if (rc != LDAP_SUCCESS)
	{
	  syslog (LOG_ERR, "pam_ldap: ldap_set_option(LDAP_OPT_X_TLS) %s",
		  ldap_err2string (rc));
	  return PAM_SYSTEM_ERR;
	}
    }
#endif /* LDAP_OPT_X_TLS */

#ifdef LDAP_OPT_PROTOCOL_VERSION
  (void) ldap_set_option (session->ld, LDAP_OPT_PROTOCOL_VERSION, &session->conf->version);
#else
  session->ld->ld_version = session->conf->version;
#endif

#if LDAP_SET_REBIND_PROC_ARGS == 3
  ldap_set_rebind_proc (session->ld, _rebind_proc, (void *) session);
#elif LDAP_SET_REBIND_PROC_ARGS == 2
  ldap_set_rebind_proc (session->ld, _rebind_proc);
#endif

#ifdef LDAP_OPT_DEREF
  (void) ldap_set_option (session->ld, LDAP_OPT_DEREF, &session->conf->deref);
#else
  session->ld->ld_deref = session->conf->deref;
#endif

#ifdef LDAP_OPT_TIMELIMIT
  (void) ldap_set_option (session->ld, LDAP_OPT_TIMELIMIT, &session->conf->timelimit);
#else
  session->ld->ld_timelimit = session->conf->timelimit;
#endif

#ifdef LDAP_X_OPT_CONNECT_TIMEOUT
  /*
   * This is a new option in the Netscape SDK which sets 
   * the TCP connect timeout. For want of a better value,
   * we use the bind_timelimit to control this.
   */
  timeout = session->conf->bind_timelimit * 1000;
  (void) ldap_set_option (session->ld, LDAP_X_OPT_CONNECT_TIMEOUT, &timeout);
#endif

#ifdef LDAP_OPT_REFERRALS
  (void) ldap_set_option (session->ld, LDAP_OPT_REFERRALS,
			  session->
			  conf->referrals ? LDAP_OPT_ON : LDAP_OPT_OFF);
#endif

#ifdef LDAP_OPT_RESTART
  (void) ldap_set_option (session->ld, LDAP_OPT_RESTART,
			  session->
			  conf->restart ? LDAP_OPT_ON : LDAP_OPT_OFF);
#endif

#ifdef HAVE_LDAP_START_TLS_S
  if (session->conf->ssl_on == SSL_START_TLS)
    {
      int version, rc;

      if (ldap_get_option (session->ld, LDAP_OPT_PROTOCOL_VERSION, &version)
	  == LDAP_SUCCESS)
	{
	  if (version < LDAP_VERSION3)
	    {
	      version = LDAP_VERSION3;
	      (void) ldap_set_option (session->ld, LDAP_OPT_PROTOCOL_VERSION, &version);
	    }

	  rc = ldap_start_tls_s (session->ld, NULL, NULL);
	  if (rc != LDAP_SUCCESS)
	    {
	      syslog (LOG_ERR, "pam_ldap: ldap_start_tls_s %s",
		      ldap_err2string (rc));
	      return PAM_SYSTEM_ERR;
	    }
	}
    }
#endif

  return PAM_SUCCESS;
}

static int
_connect_anonymously (pam_ldap_session_t * session)
{
  int rc;
  int msgid;
  struct timeval timeout;
  LDAPMessage *result;

  if (session->ld == NULL)
    {
      rc = _open_session (session);
      if (rc != PAM_SUCCESS)
	return rc;
    }

  if (session->conf->rootbinddn && geteuid () == 0)
    {
      msgid = ldap_simple_bind (session->ld,
				session->conf->rootbinddn,
				session->conf->rootbindpw);
    }
  else
    {
      msgid = ldap_simple_bind (session->ld,
				session->conf->binddn, session->conf->bindpw);
    }

  if (msgid == -1)
    {
      syslog (LOG_ERR, "pam_ldap: ldap_simple_bind %s",
	      ldap_err2string (ldap_get_lderrno (session->ld, 0, 0)));
      return PAM_SERVICE_ERR;
    }

  timeout.tv_sec = session->conf->bind_timelimit;	/* default 10 */
  timeout.tv_usec = 0;
  rc = ldap_result (session->ld, msgid, FALSE, &timeout, &result);
  if (rc == -1 || rc == 0)
    {
      syslog (LOG_ERR, "pam_ldap: ldap_result %s",
	      ldap_err2string (ldap_get_lderrno (session->ld, 0, 0)));
      return PAM_SERVICE_ERR;
    }

#ifdef HAVE_LDAP_PARSE_RESULT
  ldap_parse_result (session->ld, result, &rc, 0, 0, 0, 0, TRUE);
#else
  rc = ldap_result2error (session->ld, result, TRUE);
#endif

  if (rc != LDAP_SUCCESS)
    {
      syslog (LOG_ERR, "pam_ldap: error trying to bind (%s)",
	      ldap_err2string (rc));
      return PAM_CRED_INSUFFICIENT;
    }

  if (session->info != NULL)
    {
      session->info->bound_as_user = 0;
    }

  return PAM_SUCCESS;
}

#if defined(LDAP_API_FEATURE_X_OPENLDAP) && (LDAP_API_VERSION > 2000)
static int
_rebind_proc (LDAP * ld, LDAP_CONST char *url, int request, ber_int_t msgid)
{
  pam_ldap_session_t *session = global_session;
  char *who, *cred;

  if (session->info != NULL && session->info->bound_as_user == 1)
    {
      who = session->info->userdn;
      cred = session->info->userpw;
    }
  else
    {
      if (session->conf->rootbinddn != NULL && geteuid () == 0)
	{
	  who = session->conf->rootbinddn;
	  cred = session->conf->rootbindpw;
	}
      else
	{
	  who = session->conf->binddn;
	  cred = session->conf->bindpw;
	}
    }

  return ldap_simple_bind_s (ld, who, cred);
}
#else
# if HAVE_LDAP_SET_REBIND_PROC_ARGS == 3
static int
_rebind_proc (LDAP * ld,
	      char **whop, char **credp, int *methodp, int freeit, void *arg)
# else
static int
_rebind_proc (LDAP * ld, char **whop, char **credp, int *methodp, int freeit)
# endif
{
#if HAVE_LDAP_SET_REBIND_PROC_ARGS == 3
  pam_ldap_session_t *session = (pam_ldap_session_t *) arg;
#else
  /* ugly hack */
  pam_ldap_session_t *session = global_session;
#endif

  if (freeit)
    {
      _pam_drop (*whop);
      _pam_overwrite (*credp);
      _pam_drop (*credp);
      return LDAP_SUCCESS;
    }

  if (session->info != NULL && session->info->bound_as_user == 1)
    {
      /*
       * We're authenticating as a user.
       */
      *whop = strdup (session->info->userdn);
      *credp = strdup (session->info->userpw);
    }
  else
    {
      if (session->conf->rootbinddn != NULL && geteuid () == 0)
	{
	  *whop = strdup (session->conf->rootbinddn);
	  *credp = session->conf->rootbindpw != NULL ?
	    strdup (session->conf->rootbindpw) : NULL;
	}
      else
	{
	  *whop = session->conf->binddn != NULL ?
	    strdup (session->conf->binddn) : NULL;
	  *credp = session->conf->bindpw != NULL ?
	    strdup (session->conf->bindpw) : NULL;
	}
    }

  *methodp = LDAP_AUTH_SIMPLE;

  return LDAP_SUCCESS;
}
#endif


static int
_connect_as_user (pam_ldap_session_t * session, const char *password)
{
  int rc;
  int msgid, parserc;
  struct timeval timeout;
  LDAPMessage *result;
#ifdef HAVE_LDAP_CONTROLS_FREE
  LDAPControl **controls;
#endif

  /* avoid binding anonymously with a DN but no password */
  if (password == NULL || password[0] == '\0')
    return PAM_AUTH_ERR;

  /* this shouldn't ever happen */
  if (session->info == NULL)
    return PAM_SYSTEM_ERR;

  /* if we already bound as the user don't bother retrying */
  if (session->info->bound_as_user)
    return PAM_SUCCESS;

  if (session->ld == NULL)
    {
      rc = _open_session (session);
      if (rc != PAM_SUCCESS)
	return rc;
    }

  /*
   * We copy the password temporarily so that when referrals are
   * chased, the correct credentials are set by the rebind 
   * procedure.
   */
  if (session->info->userpw != NULL)
    {
      _pam_overwrite (session->info->userpw);
      _pam_drop (session->info->userpw);
    }

  session->info->userpw = strdup (password);
  if (session->info->userpw == NULL)
    return PAM_BUF_ERR;

  msgid =
    ldap_simple_bind (session->ld, session->info->userdn,
		      session->info->userpw);
  if (msgid == -1)
    {
      syslog (LOG_ERR, "pam_ldap: ldap_simple_bind %s",
	      ldap_err2string (ldap_get_lderrno (session->ld, 0, 0)));
      _pam_overwrite (session->info->userpw);
      _pam_drop (session->info->userpw);
      return PAM_AUTH_ERR;
    }

  timeout.tv_sec = 10;
  timeout.tv_usec = 0;
  rc = ldap_result (session->ld, msgid, FALSE, &timeout, &result);
  if (rc == -1 || rc == 0)
    {
      syslog (LOG_ERR, "pam_ldap: ldap_result %s",
	      ldap_err2string (ldap_get_lderrno (session->ld, 0, 0)));
      _pam_overwrite (session->info->userpw);
      _pam_drop (session->info->userpw);
      return PAM_SERVICE_ERR;
    }

#if defined(HAVE_LDAP_PARSE_RESULT) && defined(HAVE_LDAP_CONTROLS_FREE)
  controls = 0;
  parserc =
    ldap_parse_result (session->ld, result, &rc, 0, 0, 0, &controls, TRUE);
  if (parserc != LDAP_SUCCESS)
    {
      syslog (LOG_ERR, "pam_ldap: ldap_parse_result %s",
	      ldap_err2string (parserc));
      _pam_overwrite (session->info->userpw);
      _pam_drop (session->info->userpw);
      return PAM_SYSTEM_ERR;
    }
#else
  rc = ldap_result2error (session->ld, result, TRUE);
#endif

  if (rc != LDAP_SUCCESS)
    {
      syslog (LOG_ERR, "pam_ldap: error trying to bind as user \"%s\" (%s)",
	      session->info->userdn, ldap_err2string (rc));
      _pam_overwrite (session->info->userpw);
      _pam_drop (session->info->userpw);
      return PAM_AUTH_ERR;
    }

#if defined(HAVE_LDAP_CONTROLS_FREE)
  if (controls != NULL)
    {
      LDAPControl **ctlp;
      for (ctlp = controls; *ctlp != NULL; ctlp++)
	{
	  if (!strcmp ((*ctlp)->ldctl_oid, LDAP_CONTROL_PWEXPIRING))
	    {
	      char seconds[32];
	      snprintf (seconds, sizeof seconds, "%.*s",
			(int) (*ctlp)->ldctl_value.bv_len,
			(*ctlp)->ldctl_value.bv_val);
	      session->info->password_expiration_time = atol (seconds);
	    }
	  else if (!strcmp ((*ctlp)->ldctl_oid, LDAP_CONTROL_PWEXPIRED))
	    {
	      session->info->password_expired = 1;
	    }
	}
      ldap_controls_free (controls);
    }
#endif

  session->info->bound_as_user = 1;
  /* userpw is now set. Be sure to clobber it later. */

  return PAM_SUCCESS;
}

static int
_get_integer_value (LDAP * ld, LDAPMessage * e, const char *attr, int *ptr)
{
  char **vals;

  vals = ldap_get_values (ld, e, (char *) attr);
  if (vals == NULL)
    {
      return PAM_SYSTEM_ERR;
    }
  *ptr = atol (vals[0]);
  ldap_value_free (vals);

  return PAM_SUCCESS;
}

#ifdef notdef
static int
_oc_check (LDAP * ld, LDAPMessage * e, const char *oc)
{
  char **vals, **p;
  int rc = 0;

  vals = ldap_get_values (ld, e, "objectClass");
  if (vals == NULL)
    {
      return PAM_SYSTEM_ERR;
    }

  for (p = vals; *p != NULL; p++)
    {
      if (!strcasecmp (*p, oc))
	{
	  rc = 1;
	  break;
	}
    }

  ldap_value_free (vals);

  return rc;
}
#endif /* notdef */

static int
_get_string_value (LDAP * ld, LDAPMessage * e, const char *attr, char **ptr)
{
  char **vals;
  int rc;

  vals = ldap_get_values (ld, e, (char *) attr);
  if (vals == NULL)
    {
      return PAM_SYSTEM_ERR;
    }
  *ptr = strdup (vals[0]);
  if (*ptr == NULL)
    {
      rc = PAM_BUF_ERR;
    }
  else
    {
      rc = PAM_SUCCESS;
    }

  ldap_value_free (vals);

  return rc;
}

static int
_get_string_values (LDAP * ld, LDAPMessage * e, const char *attr, char ***ptr)
{
  char **vals;

  vals = ldap_get_values (ld, e, (char *) attr);
  if (vals == NULL)
    {
      return PAM_SYSTEM_ERR;
    }
  *ptr = vals;

  return PAM_SUCCESS;
}

static int
_has_value (char **src, const char *tgt)
{
  char **p;

  for (p = src; *p != NULL; p++)
    {
      if (!strcasecmp (*p, tgt))
	{
	  return 1;
	}
    }

  return 0;
}

static int
_host_ok (pam_ldap_session_t * session)
{
  char hostname[MAXHOSTNAMELEN];
  struct hostent *h;
#ifdef HAVE_GETHOSTBYNAME_R
  int herr;
  struct hostent hbuf;
  char buf[1024];
#endif
  char **q;

  /* simple host based access authorization */
  if (session->info->hosts_allow == NULL)
    {
      return PAM_SUCCESS;
    }

  if (gethostname (hostname, sizeof hostname) < 0)
    {
      return PAM_SYSTEM_ERR;
    }

#if defined(HAVE_GETHOSTBYNAME_R)
#if GETHOSTBYNAME_R_ARGS == 6
  if (gethostbyname_r (hostname, &hbuf, buf, sizeof buf, &h, &herr) != 0)
    {
      return PAM_SYSTEM_ERR;
    }
#else
  h = gethostbyname_r (hostname, &hbuf, buf, sizeof buf, &herr);
  if (h == NULL)
    {
      return PAM_SYSTEM_ERR;
    }
#endif
#else
  h = gethostbyname (hostname);
  if (h == NULL)
    {
      return PAM_SYSTEM_ERR;
    }
#endif

  if (_has_value (session->info->hosts_allow, h->h_name))
    {
      return PAM_SUCCESS;
    }

  if (h->h_aliases != NULL)
    {
      for (q = h->h_aliases; *q != NULL; q++)
	{
	  if (_has_value (session->info->hosts_allow, *q))
	    {
	      return PAM_SUCCESS;
	    }
	}
    }

  return PAM_AUTH_ERR;
}

static char *
_get_md5_salt (char saltbuf[16])
{
  md5_state_t state;
  md5_byte_t digest[16];
  struct timeval tv;
  int i;

  md5_init (&state);
  gettimeofday (&tv, NULL);
  md5_append (&state, (unsigned char *) &tv, sizeof (tv));
  i = getpid ();
  md5_append (&state, (unsigned char *) &i, sizeof (i));
  i = clock ();
  md5_append (&state, (unsigned char *) &i, sizeof (i));
  md5_append (&state, (unsigned char *) saltbuf, sizeof (saltbuf));
  md5_finish (&state, digest);

  strcpy (saltbuf, "$1$");
  for (i = 0; i < 8; i++)
    saltbuf[i + 3] = i64c (digest[i] & 0x3f);

  saltbuf[i + 3] = '\0';

  return saltbuf;
}

static char *
_get_salt (char salt[16])
{
  int i;
  int j;

  srand (time (NULL));

  for (j = 0; j < 2; j++)
    {
      i = rand () % 3;
      switch (i)
	{
	case 0:
	  i = (rand () % (57 - 46)) + 46;
	  break;
	case 1:
	  i = (rand () % (90 - 65)) + 65;
	  break;
	case 2:
	  i = (rand () % (122 - 97)) + 97;
	  break;
	}
      salt[j] = i;
    }
  salt[2] = '\0';
  return salt;
}

static int
_get_user_info (pam_ldap_session_t * session, const char *user)
{
  char filter[LDAP_FILT_MAXSIZ];
  int rc;
  LDAPMessage *res, *msg;

  rc = _connect_anonymously (session);
  if (rc != PAM_SUCCESS)
    return rc;

#ifdef LDAP_OPT_SIZELIMIT
  rc = 1;
  (void) ldap_set_option (session->ld, LDAP_OPT_SIZELIMIT, &rc);
#else
  session->ld->ld_sizelimit = 1;
#endif

  if (session->conf->filter != NULL)
    {
      snprintf (filter, sizeof filter, "(&(%s)(%s=%s))",
		session->conf->filter, session->conf->userattr, user);
    }
  else
    {
      snprintf (filter, sizeof filter, "(%s=%s)",
		session->conf->userattr, user);
    }

  rc = ldap_search_s (session->ld,
		      session->conf->base,
		      session->conf->scope, filter, NULL, 0, &res);

  if (rc != LDAP_SUCCESS)
    {
      syslog (LOG_ERR, "pam_ldap: ldap_search_s %s", ldap_err2string (rc));
      return PAM_USER_UNKNOWN;
    }

  msg = ldap_first_entry (session->ld, res);
  if (msg == NULL)
    {
      ldap_msgfree (res);
      return PAM_USER_UNKNOWN;
    }

  if (session->info != NULL)
    {
      _release_user_info (&session->info);
    }

  session->info =
    (pam_ldap_user_info_t *) calloc (1, sizeof (pam_ldap_user_info_t));
  if (session->info == NULL)
    {
      ldap_msgfree (res);
      return PAM_BUF_ERR;
    }

  session->info->username = strdup (user);
  if (session->info->username == NULL)
    {
      ldap_msgfree (res);
      _release_user_info (&session->info);
      return PAM_BUF_ERR;
    }

  session->info->userdn = ldap_get_dn (session->ld, msg);
  if (session->info->userdn == NULL)
    {
      ldap_msgfree (res);
      _release_user_info (&session->info);
      return PAM_SYSTEM_ERR;
    }

  session->info->bound_as_user = 0;

  /*
   * it might be better to do a compare later, that way we can
   * avoid fetching any attributes at all
   */
  _get_string_values (session->ld, msg, "host", &session->info->hosts_allow);

  /* get UID */
#ifdef UID_NOBODY
  session->info->uid = UID_NOBODY;
#else
  session->info->uid = (uid_t) - 2;
#endif /* UID_NOBODY */
  _get_integer_value (session->ld, msg, "uidNumber",
		      (uid_t *) & session->info->uid);

  /*
   * get mapped user; some PAM host applications let PAM_USER be reset
   * by the user (such as some of those provided with FreeBSD).
   */
  session->info->tmpluser = NULL;
  if (session->conf->tmplattr != NULL)
    {
      if (_get_string_value (session->ld,
			     msg,
			     session->conf->tmplattr,
			     &session->info->tmpluser) != PAM_SUCCESS)
	{
	  /* set to default template user */
	  session->info->tmpluser =
	    session->conf->tmpluser ? strdup (session->conf->tmpluser) : NULL;
	}
    }

  /* Assume shadow controls.  Allocate shadow structure and link to session. */
  session->info->shadow.lstchg = 0;
  session->info->shadow.min = 0;
  session->info->shadow.max = 0;
  session->info->shadow.warn = 0;
  session->info->shadow.inact = 0;
  session->info->shadow.expire = 0;
  session->info->shadow.flag = 0;

  _get_integer_value (session->ld, msg, "shadowLastChange",
		      &session->info->shadow.lstchg);
  _get_integer_value (session->ld, msg, "shadowMin",
		      &session->info->shadow.min);
  _get_integer_value (session->ld, msg, "shadowMax",
		      &session->info->shadow.max);
  _get_integer_value (session->ld, msg, "shadowWarning",
		      &session->info->shadow.warn);
  _get_integer_value (session->ld, msg, "shadowInactive",
		      &session->info->shadow.inact);
  _get_integer_value (session->ld, msg, "shadowExpire",
		      &session->info->shadow.expire);
  _get_integer_value (session->ld, msg, "shadowFlag",
		      &session->info->shadow.flag);

  ldap_msgfree (res);

  return PAM_SUCCESS;
}

static int
_pam_ldap_get_session (pam_handle_t * pamh, const char *username,
		       const char *configFile, pam_ldap_session_t ** psession)
{
  pam_ldap_session_t *session;
  int rc;

  if (pam_get_data
      (pamh, PADL_LDAP_SESSION_DATA, (const void **) &session) == PAM_SUCCESS)
    {
      /*
       * we cache the information retrieved from the LDAP server, however
       * we need to flush this if the application has changed the user on us.
       * For template users, note that pam_ldap may _RESET_ the username!
       */
      if (session->info != NULL &&
	  (strcmp (username, session->info->username) != 0))
	{
	  _release_user_info (&session->info);
	}

      *psession = session;
#if HAVE_LDAP_SET_REBIND_PROC_ARGS < 3
      global_session = *psession;
#endif
      return PAM_SUCCESS;
    }

  *psession = NULL;

  session = (pam_ldap_session_t *) calloc (1, sizeof (*session));
#if HAVE_LDAP_SET_REBIND_PROC_ARGS < 3
  global_session = session;
#endif
  if (session == NULL)
    {
      return PAM_BUF_ERR;
    }

  session->ld = NULL;
  session->conf = NULL;
  session->info = NULL;

#ifdef YPLDAPD
  rc = _ypldapd_read_config (&session->conf);
  if (rc != PAM_SUCCESS)
    {
      _release_config (&session->conf);
#endif /* YPLDAPD */
      rc = _read_config (configFile, &session->conf);
      if (rc != PAM_SUCCESS)
	{
	  _release_config (&session->conf);
	  free (session);
	  return rc;
	}
#ifdef YPLDAPD
    }
#endif /* YPLDAPD */

  rc =
    pam_set_data (pamh, PADL_LDAP_SESSION_DATA, (void *) session,
		  _pam_ldap_cleanup_session);
  if (rc != PAM_SUCCESS)
    {
      _release_config (&session->conf);
      free (session);
      return rc;
    }

  *psession = session;

  return PAM_SUCCESS;
}

static int
_reopen (pam_ldap_session_t * session)
{
  /* FYI: V3 lets us avoid five unneeded binds in a password change */
  if (session->conf->version == LDAP_VERSION2)
    {
      if (session->ld != NULL)
	{
	  ldap_unbind (session->ld);
	  session->ld = NULL;
	}
      if (session->info != NULL)
	{
	  session->info->bound_as_user = 0;
	}
      return _open_session (session);
    }
  return PAM_SUCCESS;
}

static int
_get_password_policy (pam_ldap_session_t * session,
		      pam_ldap_password_policy_t * policy)
{
  int rc = PAM_SUCCESS;
  LDAPMessage *res, *msg;

  /* set some reasonable defaults */
  memset (policy, 0, sizeof (*policy));
  policy->password_min_length = 6;
  policy->password_max_failure = 3;

  if (session->conf->getpolicy == 0)
    {
      return PAM_SUCCESS;
    }

  rc = _connect_anonymously (session);
  if (rc != PAM_SUCCESS)
    {
      return rc;
    }

#ifdef LDAP_OPT_SIZELIMIT
  rc = 1;
  (void) ldap_set_option (session->ld, LDAP_OPT_SIZELIMIT, &rc);
#else
  session->ld->ld_sizelimit = 1;
#endif /* LDAP_VERSION3_API */

  rc = ldap_search_s (session->ld,
		      "",
		      LDAP_SCOPE_BASE,
		      "(objectclass=passwordPolicy)", NULL, 0, &res);

  if (rc == LDAP_SUCCESS)
    {
      msg = ldap_first_entry (session->ld, res);
      if (msg != NULL)
	{
	  _get_integer_value (session->ld, msg, "passwordMaxFailure",
			      &policy->password_max_failure);
	  _get_integer_value (session->ld, msg, "passwordMinLength",
			      &policy->password_min_length);
	}
      ldap_msgfree (res);
    }

  return PAM_SUCCESS;
}

static int
_do_authentication (pam_ldap_session_t * session,
		    const char *user, const char *password)
{
  int rc = PAM_SUCCESS;

  if (session->info == NULL)
    {
      rc = _get_user_info (session, user);
      if (rc != PAM_SUCCESS)
	return rc;
    }

  rc = _reopen (session);
  if (rc != PAM_SUCCESS)
    return rc;

  rc = _connect_as_user (session, password);
  _reopen (session);
  _connect_anonymously (session);
  return rc;
}

static int
_update_authtok (pam_ldap_session_t * session,
		 const char *user,
		 const char *old_password, const char *new_password)
{
  char *strvalsold[2];
  char *strvalsnew[2];
  LDAPMod mod, mod2;
  LDAPMod *mods[3];
  char buf[64], saltbuf[16];
  int rc = PAM_SUCCESS, i;

  /* for Active Directory */

  struct berval bvalold;
  struct berval bvalnew;
  struct berval *bvalsold[2];
  struct berval *bvalsnew[2];
  char old_password_with_quotes[17], new_password_with_quotes[17];
  char old_unicode_password[34], new_unicode_password[34];

#ifdef LDAP_EXOP_X_MODIFY_PASSWD
  /* for OpenLDAP password change extended operation */
  BerElement *ber;
  struct berval *bv;
  char *retoid;
  struct berval *retdata;
#endif /* LDAP_EXOP_X_MODIFY_PASSWD */

  if (session->info == NULL)
    {
      rc = _get_user_info (session, user);
      if (rc != PAM_SUCCESS)
	{
	  return rc;
	}
    }

  if (!session->conf->rootbinddn || geteuid () != 0)
    {
      /* We're not root or don't have a rootbinddn so
       * let's try binding as the user.
       * 
       * FIXME:
       * Do we really want to do this? It allows the
       * system to be configured in such a way that the
       * user can bypass local password policy
       */
      rc = _reopen (session);
      if (rc != PAM_SUCCESS)
	return rc;

      rc = _connect_as_user (session, old_password);
      if (rc != PAM_SUCCESS)
	return rc;
    }

  switch (session->conf->password_type)
    {
    case PASSWORD_CLEAR:
      strvalsnew[0] = (char *) new_password;
      strvalsnew[1] = NULL;

      mod.mod_op = LDAP_MOD_REPLACE;
      mod.mod_type = (char *) "userPassword";
      mod.mod_values = strvalsnew;

      mods[0] = &mod;
      mods[1] = NULL;

      break;

    case PASSWORD_CRYPT:
      _get_salt (saltbuf);
      snprintf (buf, sizeof buf, "{crypt}%s", crypt (new_password, saltbuf));
      strvalsnew[0] = buf;
      strvalsnew[1] = NULL;

      mod.mod_op = LDAP_MOD_REPLACE;
      mod.mod_type = (char *) "userPassword";
      mod.mod_values = strvalsnew;

      mods[0] = &mod;
      mods[1] = NULL;

      break;

    case PASSWORD_MD5:
      _get_md5_salt (saltbuf);
      snprintf (buf, sizeof buf, "{crypt}%s", crypt (new_password, saltbuf));
      strvalsnew[0] = buf;
      strvalsnew[1] = NULL;

      mod.mod_op = LDAP_MOD_REPLACE;
      mod.mod_type = (char *) "userPassword";
      mod.mod_values = strvalsnew;

      mods[0] = &mod;
      mods[1] = NULL;

      break;

    case PASSWORD_NDS:
      /* NDS requires that the old password is first removed */
      strvalsold[0] = (char *) old_password;
      strvalsold[1] = NULL;
      strvalsnew[0] = (char *) new_password;
      strvalsnew[1] = NULL;

      mod.mod_vals.modv_strvals = strvalsold;
      mod.mod_type = (char *) "userPassword";
      mod.mod_op = LDAP_MOD_DELETE;

      mod2.mod_vals.modv_strvals = strvalsnew;
      mod2.mod_type = (char *) "userPassword";
      mod2.mod_op = LDAP_MOD_REPLACE;

      mods[0] = &mod;
      mods[1] = &mod2;
      mods[2] = NULL;

      break;

    case PASSWORD_AD:
      /*
       * Patch from Norbert Klasen <klasen@zdv.uni-tuebingen.de>:
       *
       * To be able to change a password in AD via LDAP, an SSL connection
       * with a cipher strength of at least 128 bit must be established.
       * http://support.microsoft.com/support/kb/articles/q264/4/80.ASP
       * http://support.microsoft.com/support/kb/articles/Q247/0/78.ASP
       *
       * The password attribute used by AD is unicodePwd. Its syntax is octect
       * string. The actual value is the password surrounded by quotes in 
       * Unicode (LSBFirst).
       *
       * NT passwords can have max. 14 characters. 
       *
       * FIXME:
       * The conversion to Unicode only works if the locale is 
       * ISO-8859-1 (aka Latin-1) [of which ASCII is a subset]. 
       */

      snprintf (new_password_with_quotes, sizeof (new_password_with_quotes),
		"\"%s\"", new_password);
      memset (new_unicode_password, 0, sizeof (new_unicode_password));
      for (i = 0; i < strlen (new_password_with_quotes); i++)
	new_unicode_password[i * 2] = new_password_with_quotes[i];
      bvalnew.bv_val = new_unicode_password;
      bvalnew.bv_len = strlen (new_password_with_quotes) * 2;

      bvalsnew[0] = &bvalnew;
      bvalsnew[1] = NULL;
      mod.mod_vals.modv_bvals = bvalsnew;
      mod.mod_type = (char *) "unicodePwd";
      mod.mod_op = LDAP_MOD_ADD | LDAP_MOD_BVALUES;

      if (!session->conf->rootbinddn || geteuid () != 0)
	{
	  /* user must supply old password */
	  snprintf (old_password_with_quotes,
		    sizeof (old_password_with_quotes), "\"%s\"",
		    old_password);
	  memset (old_unicode_password, 0, sizeof (old_unicode_password));
	  for (i = 0; i < strlen (old_password_with_quotes); i++)
	    old_unicode_password[i * 2] = old_password_with_quotes[i];
	  bvalold.bv_val = old_unicode_password;
	  bvalold.bv_len = strlen (old_password_with_quotes) * 2;

	  bvalsold[0] = &bvalold;
	  bvalsold[1] = NULL;
	  mod2.mod_vals.modv_bvals = bvalsold;
	  mod2.mod_type = (char *) "unicodePwd";
	  mod2.mod_op = LDAP_MOD_DELETE | LDAP_MOD_BVALUES;

	  mods[0] = &mod;
	  mods[1] = &mod2;
	  mods[2] = NULL;
	}
      else
	{
	  mods[0] = &mod;
	  mods[1] = NULL;
	}

      break;

    case PASSWORD_EXOP:
#ifdef LDAP_EXOP_X_MODIFY_PASSWD
      ber = ber_alloc_t (LBER_USE_DER);

      if (ber == NULL)
	{
	  return PAM_BUF_ERR;
	}

      ber_printf (ber, "{");
      ber_printf (ber, "ts", LDAP_TAG_EXOP_X_MODIFY_PASSWD_ID,
		  session->info->userdn);
      ber_printf (ber, "ts", LDAP_TAG_EXOP_X_MODIFY_PASSWD_OLD, old_password);
      ber_printf (ber, "ts", LDAP_TAG_EXOP_X_MODIFY_PASSWD_NEW, new_password);
      ber_printf (ber, "N}");

      rc = ber_flatten (ber, &bv);
      if (rc < 0)
	{
	  return PAM_BUF_ERR;
	}

      ber_free (ber, 1);

      rc =
	ldap_extended_operation_s (session->ld, LDAP_EXOP_X_MODIFY_PASSWD, bv,
				   NULL, NULL, &retoid, &retdata);
      ber_bvfree (bv);

      if (rc != LDAP_SUCCESS)
	{
	  syslog (LOG_ERR, "pam_ldap: ldap_extended_operation_s %s",
		  ldap_err2string (rc));
	  rc = PAM_PERM_DENIED;
	}
      else
	{
	  ber_bvfree (retdata);
	  ber_memfree (retoid);
	  rc = PAM_SUCCESS;
	}
#else
      rc = PAM_SYSTEM_ERR;
#endif /* LDAP_EXOP_X_MODIFY_PASSWD */

      break;
    }				/* end switch */

  if (session->conf->password_type != PASSWORD_EXOP)
    {
      rc = ldap_modify_s (session->ld, session->info->userdn, mods);
      if (rc != LDAP_SUCCESS)
	{
	  syslog (LOG_ERR, "pam_ldap: ldap_modify_s %s",
		  ldap_err2string (rc));
	  rc = PAM_PERM_DENIED;
	}
      else
	{
	  rc = PAM_SUCCESS;
	}
    }

  return rc;
}

static int
_get_authtok (pam_handle_t * pamh, int flags, int first)
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

  rc = pam_get_item (pamh, PAM_CONV, (CONST_ARG void **) &conv);
  if (rc == PAM_SUCCESS)
    {
      rc = conv->conv (1,
		       (CONST_ARG struct pam_message **) pmsg,
		       &resp, conv->appdata_ptr);
    }
  else
    {
      return rc;
    }

  if (resp != NULL)
    {
      if ((flags & PAM_DISALLOW_NULL_AUTHTOK) && resp[0].resp == NULL)
	{
	  free (resp);
	  return PAM_AUTH_ERR;
	}

      p = resp[0].resp;
      /* leak if resp[0].resp is malloced. */
      resp[0].resp = NULL;
    }
  else
    {
      return PAM_CONV_ERR;
    }

  free (resp);
  pam_set_item (pamh, PAM_AUTHTOK, p);

  return PAM_SUCCESS;
}

static int
_conv_sendmsg (struct pam_conv *aconv,
	       const char *message, int style, int no_warn)
{
  struct pam_message msg, *pmsg;
  struct pam_response *resp;

  if (no_warn)
    return PAM_SUCCESS;

  pmsg = &msg;

  msg.msg_style = style;
  msg.msg = (char *) message;
  resp = NULL;

  return aconv->conv (1,
		      (CONST_ARG struct pam_message **) &pmsg,
		      &resp, aconv->appdata_ptr);
}

PAM_EXTERN int
pam_sm_authenticate (pam_handle_t * pamh,
		     int flags, int argc, const char **argv)
{
  int rc;
  const char *username;
  char *p;
  int use_first_pass = 0, try_first_pass = 0;
  int i;
  pam_ldap_session_t *session = NULL;
  const char *configFile = NULL;

  for (i = 0; i < argc; i++)
    {
      if (!strcmp (argv[i], "use_first_pass"))
	use_first_pass = 1;
      else if (!strcmp (argv[i], "try_first_pass"))
	try_first_pass = 1;
      else if (!strncmp (argv[i], "config=", 7))
	configFile = argv[i] + 7;
      else if (!strcmp (argv[i], "no_warn"))
	;
      else if (!strcmp (argv[i], "debug"))
	;
      else
	syslog (LOG_ERR, "illegal option %s", argv[i]);
    }

  rc = pam_get_user (pamh, (CONST_ARG char **) &username, "login: ");
  if (rc != PAM_SUCCESS)
    return rc;

  rc = _pam_ldap_get_session (pamh, username, configFile, &session);
  if (rc != PAM_SUCCESS)
    return rc;

  rc = pam_get_item (pamh, PAM_AUTHTOK, (CONST_ARG void **) &p);
  if (rc == PAM_SUCCESS && (use_first_pass || try_first_pass))
    {
      rc = _do_authentication (session, username, p);
      if (rc == PAM_SUCCESS || use_first_pass)
	{
	  return rc;
	}
    }

  /* can prompt for authentication token */
  rc = _get_authtok (pamh, flags, (p == NULL) ? 1 : 0);
  if (rc != PAM_SUCCESS)
    return rc;

  rc = pam_get_item (pamh, PAM_AUTHTOK, (CONST_ARG void **) &p);
  if (rc == PAM_SUCCESS)
    rc = _do_authentication (session, username, p);

  /*
   * reset username to template user if necessary
   * FreeBSD pam_radius does this in pam_sm_authenticate() but
   * I think pam_sm_acct_mgmt() is the right place.
   */
  if (rc == PAM_SUCCESS && session->info->tmpluser != NULL)
    {
      /* keep original username for posterity */

      (void) pam_set_data (pamh, PADL_LDAP_AUTH_DATA,
			   (void *) strdup (session->info->username),
			   _cleanup_data);
      rc = pam_set_item (pamh, PAM_USER, (void *) session->info->tmpluser);
    }

  return rc;
}

PAM_EXTERN int
pam_sm_setcred (pam_handle_t * pamh, int flags, int argc, const char **argv)
{
  return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_open_session (pam_handle_t * pamh,
		     int flags, int argc, const char **argv)
{
  return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_close_session (pam_handle_t * pamh,
		      int flags, int argc, const char **argv)
{
  return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_chauthtok (pam_handle_t * pamh, int flags, int argc, const char **argv)
{
  int rc = PAM_SUCCESS;
  char *username, *curpass = NULL, *newpass = NULL, *expuser = NULL;
  char buf[32], *strvals[2];
  struct pam_conv *appconv;
  struct pam_message msg, *pmsg;
  struct pam_response *resp;
  const char *cmiscptr = NULL;
  int tries = 0, i, canabort = 1;
  pam_ldap_session_t *session = NULL;
  int use_first_pass = 0, try_first_pass = 0, no_warn = 0;
  int use_authtok = 0;
  char errmsg[1024];
  pam_ldap_password_policy_t policy;
  LDAPMod *mods[2], mod;
  const char *configFile = NULL;

  for (i = 0; i < argc; i++)
    {
      if (!strcmp (argv[i], "use_first_pass"))
	use_first_pass = 1;
      else if (!strcmp (argv[i], "try_first_pass"))
	try_first_pass = 1;
      else if (!strncmp (argv[i], "config=", 7))
	configFile = argv[i] + 7;
      else if (!strcmp (argv[i], "no_warn"))
	no_warn = 1;
      else if (!strcmp (argv[i], "debug"))
	;
      else if (!strcmp (argv[i], "use_authtok"))
	use_authtok = 1;
      else
	syslog (LOG_ERR, "illegal option %s", argv[i]);
    }

  if (flags & PAM_SILENT)
    no_warn = 1;

  rc = pam_get_item (pamh, PAM_CONV, (CONST_ARG void **) &appconv);
  if (rc != PAM_SUCCESS)
    return rc;

  /*
   * Call pam_get_data() to see whether the pre-mapped
   * (non-template) user is available to us. If so,
   * use that instead.
   */
  rc = pam_get_data (pamh, PADL_LDAP_AUTH_DATA, (const void **) &username);
  if (rc != PAM_SUCCESS)
    {
      rc = pam_get_user (pamh, (CONST_ARG char **) &username, "login: ");
      if (rc != PAM_SUCCESS)
	return rc;
    }

  if (username == NULL)
    return PAM_USER_UNKNOWN;

  rc = pam_get_data (pamh, PADL_LDAP_AUTHTOK_DATA, (const void **) &expuser);
  if (rc == PAM_SUCCESS && expuser != NULL)
    canabort = (strcmp (username, expuser) == 0) ? 0 : 1;

  rc = _pam_ldap_get_session (pamh, username, configFile, &session);
  if (rc != PAM_SUCCESS)
    return rc;

  if (flags & PAM_PRELIM_CHECK)
    {
      /* see whether the user exists */
      rc = _get_user_info (session, username);
      if (rc != PAM_SUCCESS)
	return rc;

      if (!(session->conf->rootbinddn && getuid () == 0))
	{
	  /* we are not root, authenticate old password */
	  if (try_first_pass || use_first_pass)
	    {
	      if (pam_get_item
		  (pamh, PAM_OLDAUTHTOK,
		   (CONST_ARG void **) &curpass) == PAM_SUCCESS)
		{
		  rc = _do_authentication (session, username, curpass);
		  if (rc != PAM_SUCCESS)
		    {
		      if (use_first_pass)
			{
			  _conv_sendmsg (appconv, "LDAP Password incorrect",
					 PAM_ERROR_MSG, no_warn);
			}
		      else
			{
			  _conv_sendmsg (appconv,
					 "LDAP Password incorrect: try again",
					 PAM_ERROR_MSG, no_warn);
			}
		      return rc;
		    }
		}
	      else
		{
		  curpass = NULL;
		}
	    }

	  tries = 0;

	  /* support Netscape Directory Server's password policy */
	  rc = _get_password_policy (session, &policy);
	  if (rc != PAM_SUCCESS)
	    return rc;

	  while ((curpass == NULL) && (tries++ < policy.password_max_failure))
	    {
	      pmsg = &msg;
	      msg.msg_style = PAM_PROMPT_ECHO_OFF;
	      msg.msg = OLD_PASSWORD_PROMPT;
	      resp = NULL;

	      rc = appconv->conv (1, (CONST_ARG struct pam_message **) &pmsg,
				  &resp, appconv->appdata_ptr);

	      if (rc != PAM_SUCCESS)
		return rc;

	      curpass = resp->resp;
	      free (resp);

	      /* authenticate the old password */
	      rc = _do_authentication (session, username, curpass);
	      if (rc != PAM_SUCCESS)
		{
		  int abortme = 0;

		  if (curpass != NULL && curpass[0] == '\0')
		    abortme = 1;

		  _pam_overwrite (curpass);
		  _pam_drop (curpass);

		  if (canabort && abortme)
		    {
		      _conv_sendmsg (appconv, "Password change aborted",
				     PAM_ERROR_MSG, no_warn);
#ifdef PAM_AUTHTOK_RECOVERY_ERR
		      return PAM_AUTHTOK_RECOVERY_ERR;
#else
		      return PAM_AUTHTOK_RECOVER_ERR;
#endif /* PAM_AUTHTOK_RECOVERY_ERR */
		    }
		  else
		    {
		      _conv_sendmsg (appconv,
				     "LDAP Password incorrect: try again",
				     PAM_ERROR_MSG, no_warn);
		    }
		}
	    }			/* while */

	  if (curpass == NULL)
	    return PAM_MAXTRIES;	/* maximum tries exceeded */
	}
      else
	{
	  /* we are root */
	  curpass = NULL;
	}

      pam_set_item (pamh, PAM_OLDAUTHTOK, (void *) curpass);
      return rc;
    }				/* prelim */

  if (use_authtok)
    use_first_pass = 1;

  rc = pam_get_item (pamh, PAM_OLDAUTHTOK, (CONST_ARG void **) &curpass);
  if (rc != PAM_SUCCESS)
    {
      syslog (LOG_ERR, "pam_ldap: error getting PAM_OLDAUTHTOK (%s)",
	      pam_strerror (pamh, rc));
#ifdef PAM_AUTHTOK_RECOVERY_ERR
      return PAM_AUTHTOK_RECOVERY_ERR;
#else
      return PAM_AUTHTOK_RECOVER_ERR;
#endif /* PAM_AUTHTOK_RECOVERY_ERR */
    }

  if (try_first_pass || use_first_pass)
    {
      if (pam_get_item (pamh, PAM_AUTHTOK, (CONST_ARG void **) &newpass) !=
	  PAM_SUCCESS)
	newpass = NULL;

      if (use_first_pass && newpass == NULL)
#ifdef PAM_AUTHTOK_RECOVERY_ERR
	return PAM_AUTHTOK_RECOVERY_ERR;
#else
	return PAM_AUTHTOK_RECOVER_ERR;
#endif /* PAM_AUTHTOK_RECOVERY_ERR */
    }

  tries = 0;

  while ((newpass == NULL) && (tries++ < policy.password_max_failure))
    {
      pmsg = &msg;
      msg.msg_style = PAM_PROMPT_ECHO_OFF;
      msg.msg = NEW_PASSWORD_PROMPT;
      resp = NULL;

      rc = appconv->conv (1, (CONST_ARG struct pam_message **) &pmsg,
			  &resp, appconv->appdata_ptr);

      if (rc != PAM_SUCCESS)
	return rc;

      newpass = resp->resp;
      free (resp);

      if (newpass[0] == '\0')
	{
	  free (newpass);
	  newpass = NULL;
	}

      if (newpass != NULL)
	{
	  if (getuid () != 0)
	    {
	      if (curpass != NULL && !strcmp (curpass, newpass))
		{
		  cmiscptr = "Passwords must differ";
		  newpass = NULL;
		}
	      else if (strlen (newpass) < policy.password_min_length)
		{
		  cmiscptr = "Password too short";
		  newpass = NULL;
		}
	    }
	}
      else
	{
#ifdef PAM_AUTHTOK_RECOVERY_ERR
	  return PAM_AUTHTOK_RECOVERY_ERR;
#else
	  return PAM_AUTHTOK_RECOVER_ERR;
#endif /* PAM_AUTHTOK_RECOVERY_ERR */
	}

      if (cmiscptr == NULL)
	{
	  /* get password again */
	  char *miscptr;

	  pmsg = &msg;
	  msg.msg_style = PAM_PROMPT_ECHO_OFF;
	  msg.msg = AGAIN_PASSWORD_PROMPT;
	  resp = NULL;

	  rc = appconv->conv (1, (CONST_ARG struct pam_message **) &pmsg,
			      &resp, appconv->appdata_ptr);

	  if (rc != PAM_SUCCESS)
	    return rc;

	  miscptr = resp->resp;
	  free (resp);
	  if (miscptr[0] == '\0')
	    {
	      free (miscptr);
	      miscptr = NULL;
	    }
	  if (miscptr == NULL)
	    {
	      if (canabort)
		{
		  _conv_sendmsg (appconv, "Password change aborted",
				 PAM_ERROR_MSG, no_warn);
#ifdef PAM_AUTHTOK_RECOVERY_ERR
		  return PAM_AUTHTOK_RECOVERY_ERR;
#else
		  return PAM_AUTHTOK_RECOVER_ERR;
#endif /* PAM_AUTHTOK_RECOVERY_ERR */
		}
	    }
	  else if (!strcmp (newpass, miscptr))
	    {
	      miscptr = NULL;
	      break;
	    }

	  _conv_sendmsg (appconv, "You must enter the same password",
			 PAM_ERROR_MSG, no_warn);
	  miscptr = NULL;
	  newpass = NULL;
	}
      else
	{
	  _conv_sendmsg (appconv, cmiscptr, PAM_ERROR_MSG, no_warn);
	  cmiscptr = NULL;
	  newpass = NULL;
	}
    }				/* while */

  if (cmiscptr != NULL || newpass == NULL)
    return PAM_MAXTRIES;

  pam_set_item (pamh, PAM_AUTHTOK, (void *) newpass);
  rc = _update_authtok (session, username, curpass, newpass);
  if (rc != PAM_SUCCESS)
    {
      int lderr;
      char *reason = NULL;

      lderr = ldap_get_lderrno (session->ld, NULL, &reason);
      if (reason != NULL)
	snprintf (errmsg, sizeof errmsg,
		  "LDAP password information update failed: %s\n%s",
		  ldap_err2string (lderr), reason);
      else
	snprintf (errmsg, sizeof errmsg,
		  "LDAP password information update failed: %s",
		  ldap_err2string (lderr));

      _conv_sendmsg (appconv, errmsg, PAM_ERROR_MSG, no_warn);
    }
  else
    {
      /* update shadowLastChange; may fail if not shadowAccount */
      snprintf (buf, sizeof buf, "%ld", time (NULL) / (60 * 60 * 24));
      strvals[0] = buf;
      strvals[1] = NULL;

      mod.mod_values = strvals;
      mod.mod_type = (char *) "shadowLastChange";
      mod.mod_op = LDAP_MOD_REPLACE;

      mods[0] = &mod;
      mods[1] = NULL;

      /* do this silently because it may fail */
      (void) ldap_modify_s (session->ld, session->info->userdn, mods);

      snprintf (errmsg, sizeof errmsg,
		"LDAP password information changed for %s", username);
      _conv_sendmsg (appconv, errmsg, PAM_TEXT_INFO,
		     (flags & PAM_SILENT) ? 1 : 0);
    }

  return rc;
}

PAM_EXTERN int
pam_sm_acct_mgmt (pam_handle_t * pamh, int flags, int argc, const char **argv)
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
  time_t currenttime;
  int expirein = 0;		/* seconds until password expires */
  const char *configFile = NULL;

  for (i = 0; i < argc; i++)
    {
      if (!strcmp (argv[i], "use_first_pass"))
	;
      else if (!strcmp (argv[i], "try_first_pass"))
	;
      else if (!strncmp (argv[i], "config=", 7))
	configFile = argv[i] + 7;
      else if (!strcmp (argv[i], "no_warn"))
	no_warn = 1;
      else if (!strcmp (argv[i], "debug"))
	;
      else
	syslog (LOG_ERR, "illegal option %s", argv[i]);
    }


  if (flags & PAM_SILENT)
    no_warn = 1;

  rc = pam_get_item (pamh, PAM_CONV, (CONST_ARG void **) &appconv);
  if (rc != PAM_SUCCESS)
    return rc;

  /*
   * Call pam_get_data() to see whether the pre-mapped
   * (non-template) user is available to us. If so,
   * use that instead.
   */
  rc = pam_get_data (pamh, PADL_LDAP_AUTH_DATA, (const void **) &username);
  if (rc != PAM_SUCCESS)
    {
      rc = pam_get_user (pamh, (CONST_ARG char **) &username, "login: ");
      if (rc != PAM_SUCCESS)
	return rc;
    }

  if (username == NULL)
    return PAM_USER_UNKNOWN;

  rc = _pam_ldap_get_session (pamh, username, configFile, &session);
  if (rc != PAM_SUCCESS)
    {
      return rc;
    }

  if (session->info == NULL)
    {
      rc = _get_user_info (session, username);
      if (rc != PAM_SUCCESS)
	{
	  return rc;
	}
    }

  /* Grab the current time */
  time (&currenttime);

  /* Check shadow expire conditions */
  /* Do we have an absolute expiry date? */
  if (session->info->shadow.expire > 0)
    {
      if (currenttime >= (session->info->shadow.expire * SECSPERDAY))
	{
	  return PAM_ACCT_EXPIRED;
	}
    }

  /*
   * Also check if user hasn't changed password for the inactive
   * amount of time.  This also counts as an expired account.
   */
  if ((session->info->shadow.lstchg > 0) &&
      (session->info->shadow.max > 0) && (session->info->shadow.inact > 0))
    {
      if (currenttime >= ((session->info->shadow.lstchg +
			   session->info->shadow.max +
			   session->info->shadow.inact) * SECSPERDAY))
	{
	  return PAM_ACCT_EXPIRED;
	}
    }

  /* Our shadow information should be populated, so do some calculations */
  if ((session->info->shadow.lstchg > 0) && (session->info->shadow.max > 0))
    {
      if (currenttime >= ((session->info->shadow.lstchg +
			   session->info->shadow.max) * SECSPERDAY))
	{
	  session->info->password_expired = 1;
	}
    }

  /* check whether the password has expired */
  if (session->info->password_expired)
    {
      _conv_sendmsg (appconv,
		     "You are required to change your LDAP password immediately.",
		     PAM_ERROR_MSG, no_warn);
#ifdef LINUX
      success = PAM_AUTHTOKEN_REQD;
#else
      success = PAM_NEW_AUTHTOK_REQD;
#endif /* LINUX */

#ifdef notdef			/* ?????? */
#ifdef PAM_AUTHTOK_EXPIRED
      success = PAM_AUTHTOK_EXPIRED;
#else
      success = PAM_AUTHTOKEN_REQD;
#endif
#endif /* notdef */
    }

  /*
   * Warnings.  First, check if we've got a non-zero warning time
   * in the shadow struct.  If so, we're a shadow account, and set
   * things accordingly.  Otherwise, check the Netscape controls.
   */

  /*
   * If the password's expired, no sense warning
   */

  if (!session->info->password_expired)
    {
      if (session->info->shadow.warn > 0)	/* shadowAccount */
	{
	  /*
	   * Are we within warning period?
	   */

	  expirein = ((session->info->shadow.lstchg +
		       session->info->shadow.max) * SECSPERDAY) - currenttime;

	  if ((session->info->shadow.warn * SECSPERDAY) <= expirein)
	    {
	      expirein = 0;	/* Not within warning period yet */
	    }
	}
      else
	{
	  expirein = session->info->password_expiration_time;
	}

      if (expirein > 0)
	{
	  if (expirein < SECSPERDAY)
	    {
	      snprintf (buf, sizeof buf,
			"Your LDAP password will expire within 24 hours.");
	      /* override no_warn */
	      _conv_sendmsg (appconv, buf, PAM_ERROR_MSG, 0);
	    }
	  else
	    {
	      int days = expirein / SECSPERDAY;
	      snprintf (buf, sizeof buf,
			"Your LDAP password will expire in %d day%s.",
			days, (days == 1) ? "" : "s");
	      _conv_sendmsg (appconv, buf, PAM_ERROR_MSG, no_warn);
	    }
	  /* we set this to make sure that user can't abort a password change */

	  (void) pam_set_data (pamh, PADL_LDAP_AUTHTOK_DATA,
			       (void *) strdup (username), _cleanup_data);
	}
    }				/* password expired */

  /* group auth, per Chris's pam_ldap_auth module */
  if (session->conf->groupdn != NULL)
    {
      rc = ldap_compare_s (session->ld,
			   session->conf->groupdn,
			   session->conf->groupattr, session->info->userdn);
      if (rc != LDAP_COMPARE_TRUE)
	{
	  snprintf (buf, sizeof buf, "You must be a %s of %s to login.",
		    session->conf->groupattr, session->conf->groupdn);
	  _conv_sendmsg (appconv, buf, PAM_ERROR_MSG, no_warn);
	  return PAM_AUTH_ERR;
	}
    }

  rc = _host_ok (session);
  if (rc == PAM_SUCCESS)
    rc = success;

  if (session->conf->min_uid && session->info->uid < session->conf->min_uid)
    {
      snprintf (buf, sizeof buf, "UID must be greater than %ld",
		(long) session->conf->min_uid);
      _conv_sendmsg (appconv, buf, PAM_ERROR_MSG, no_warn);
      return PAM_AUTH_ERR;
    }

  if (session->conf->max_uid && session->info->uid > session->conf->max_uid)
    {
      snprintf (buf, sizeof buf, "UID must be less than %ld",
		(long) session->conf->max_uid);
      _conv_sendmsg (appconv, buf, PAM_ERROR_MSG, no_warn);
      return PAM_AUTH_ERR;
    }

  return rc;
}

/* static module data */
#ifdef PAM_STATIC
struct pam_module _modstruct = {
  "pam_ldap",
  pam_sm_authenticate,
  pam_sm_setcred,
  pam_sm_acct_mgmt,
  pam_sm_open_session, pam_sm_close_session, pam_sm_chauthtok
};
#endif /* PAM_STATIC */
