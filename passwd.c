/*
 * ProFTPD - mod_passwd_update passwords
 * Copyright (c) 2021 TJ Saunders
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Suite 500, Boston, MA 02110-1335, USA.
 *
 * As a special exemption, TJ Saunders and other respective copyright holders
 * give permission to link this program with OpenSSL, and distribute the
 * resulting executable, without including the source code for OpenSSL in the
 * source distribution.
 */

#include "mod_passwd_update.h"
#include "salt.h"
#include "passwd.h"

/* Number of fields in a passwd(5) line. */
#define PASSWD_UPDATE_NFIELDS	7

static const char *trace_channel = "passwd_update.passwd";

static int hash_is_usable(pool *p, const char *hash, unsigned int algo_id) {
  int res = 0;

  switch (algo_id) {
    case PASSWD_UPDATE_ALGO_SHA256:
      if (strncmp(hash, "$5$", 3) != 0) {
        pr_trace_msg(trace_channel, 9,
          "unexpected prefix '%*s' for SHA256 salt", 3, hash);
        res = -1;
      }
      break;

    case PASSWD_UPDATE_ALGO_SHA512:
      if (strncmp(hash, "$6$", 3) != 0) {
        pr_trace_msg(trace_channel, 9,
          "unexpected prefix '%*s' for SHA512 salt", 3, hash);
        res = -1;
      }
      break;

    default:
      errno = EINVAL;
      res = -1;
  }

  return res;
}

const char *passwd_update_get_hash(pool *p, const char *plaintext,
    unsigned int algo_id) {
  const char *salt;
  char *hash;

  if (p == NULL ||
      plaintext == NULL) {
    errno = EINVAL;
    return NULL;
  }

  salt = passwd_update_get_salt(p, algo_id);
  if (salt == NULL) {
    return NULL;
  }

  hash = crypt(plaintext, salt);
  if (hash == NULL) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 3, "crypt(3) error: %s", strerror(xerrno));

    errno = xerrno;
    return NULL;
  }

  if (hash_is_usable(p, hash, algo_id) < 0) {
    return NULL;
  }

  return hash;
}

/* Borrowed from mod_auth_file.'s af_getpasswd(). */
struct passwd *passwd_update_from_text(pool *p, const char *text,
    size_t text_len) {
  unsigned int nfields;
  char buf[PR_TUNABLE_BUFFER_SIZE], *fields[PASSWD_UPDATE_NFIELDS], *ptr;
  struct passwd *pwd;

  if (p == NULL ||
      text == NULL ||
      text_len == 0) {
    errno = EINVAL;
    return NULL;
  }

  sstrncpy(buf, text, sizeof(buf)-1);
  buf[sizeof(buf)-1] = '\0';

  for (ptr = buf, nfields = 0;
       nfields < PASSWD_UPDATE_NFIELDS && ptr != NULL;
       nfields++) {
    fields[nfields] = ptr;

    while (*ptr &&
           *ptr != ':') {
      ptr++;
    }

    if (*ptr) {
      *ptr++ = '\0';

    } else {
      ptr = NULL;
    }
  }

  if (nfields != PASSWD_UPDATE_NFIELDS) {
    pr_trace_msg(trace_channel, 2,
      "malformed passwd(5) text (field count %u != %d)", nfields,
      PASSWD_UPDATE_NFIELDS);
    errno = EPERM;
    return NULL;
  }

  pwd = pcalloc(p, sizeof(struct passwd));
  pwd->pw_name = fields[0];
  pwd->pw_passwd = fields[1];

  if (*fields[2] == '\0' ||
      *fields[3] == '\0') {
    pr_trace_msg(trace_channel, 2,
      "missing UID/GID fields for user '%.100s'", pwd->pw_name);
    errno = EPERM;
    return NULL;
  }

  if (pr_str2uid(fields[2], &(pwd->pw_uid)) < 0) {
    pr_trace_msg(trace_channel, 2,
      "invalid UID field '%s' for user '%.100s'", fields[2], pwd->pw_name);
    errno = EPERM;
    return NULL;
  }

  if (pr_str2gid(fields[3], &(pwd->pw_gid)) < 0) {
    pr_trace_msg(trace_channel, 2,
      "invalid GID field '%s' for user '%.100s'", fields[3], pwd->pw_name);
    errno = EPERM;
    return NULL;
  }

  pw->pw_gecos = pstrdup(p, fields[4]);
  pw->pw_dir = pstrdup(p, fields[5]);
  pw->pw_shell = pstrdup(p, fields[6]);

  return pwd;
}

const char *passwd_update_to_text(pool *p, struct passwd *pwd) {
  const char *uid_text, *gid_text, *gecos, *home, *shell, *text;

  if (p == NULL ||
      pwd == NULL) {
    errno = EINVAL;
    return NULL;
  }

  /* Assert the required fields:
   *
   *  pw_name
   *  pw_passwd
   */

  if (pwd->pw_name == NULL ||
      pwd->pw_passwd == NULL) {
    errno = EINVAL;
    return NULL;
  }

  uid_text = pr_uid2str(p, pwd->pw_uid);
  if (uid_text == NULL) {
    return NULL;
  }

  gid_text = pr_gid2str(p, pwd->pw_gid);
  if (gid_text == NULL) {
    return NULL;
  }

  gecos = pwd->pw_gecos;
  if (gecos == NULL) {
    gecos = "";
  }

  home = pwd->pw_dir;
  if (home == NULL) {
    home = "";
  }

  shell = pwd->pw_shell;
  if (shell == NULL) {
    shell = "";
  }

  text = pstrcat(p, pwd->pw_name, ":", pwd->pw_passwd, ":",
    uid_text, ":", gid_text, ":", gecos, ":", home, ":", shell, NULL);
  return text;
}
