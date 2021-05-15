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
