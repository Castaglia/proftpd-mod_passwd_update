/*
 * ProFTPD - mod_passwd_update salts
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

static const char *trace_channel = "passwd_update.salt";

static const char *salt_text = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
static size_t salt_textlen = 62;

static long next_random(long min, long max) {
#if PROFTPD_VERSION_NUMBER < 0x0001030705
  long r, scaled;

# if defined(HAVE_RANDOM)
  r = random();
# else
  r = (long) rand();
# endif /* HAVE_RANDOM */

  scaled = r % (max - min + 1) + min;
  return scaled;
#else
  return pr_random_next();
#endif /* Prior to ProFTPD 1.3.7 */
}

const char *passwd_update_get_salt(pool *p, unsigned int algo_id) {
  register unsigned int i;
  char *salt = NULL;
  size_t salt_len;

  if (p == NULL) {
    errno = EINVAL;
    return NULL;
  }

  switch (algo_id) {
    case PASSWD_UPDATE_ALGO_SHA256: {
      /* SHA256 salts have a "$5$" (3) prefix, followed by 16 characters. */
      salt_len = 20;
      salt = pcalloc(p, salt_len);
      salt[0] = '$';
      salt[1] = '5';
      salt[2] = '$';

      for (i = 3; i < salt_len; i++) {
        long idx;

        idx = next_random(0, salt_textlen);
        salt[i] = salt_text[idx];
      }

      pr_trace_msg(trace_channel, 19, "generated SHA256 salt: '%s'", salt);
      break;
    }

    case PASSWD_UPDATE_ALGO_SHA512: {
      /* SHA512 salts have a "$6$" (3) prefix, followed by 16 characters. */
      salt_len = 20;
      salt = pcalloc(p, salt_len);
      salt[0] = '$';
      salt[1] = '6';
      salt[2] = '$';

      for (i = 3; i < salt_len; i++) {
        long idx;

        idx = next_random(0, salt_textlen);
        salt[i] = salt_text[idx];
      }

      pr_trace_msg(trace_channel, 19, "generated SHA512 salt: '%s'", salt);
      break;
    }

    default:
      pr_trace_msg(trace_channel, 3, "unknown algorithm ID %u requested",
        algo_id);
      errno = EINVAL;
      return NULL;
  }

  return salt;
}

int passwd_update_init_salt(void) {
#if PROFTPD_VERSION_NUMBER < 0x0001030705
# if defined(HAVE_RANDOM)
  struct timeval tv;

  gettimeofday(&tv, NULL);
  srandom(getpid() ^ tv.tv_usec);
# else
  srand((unsigned int) (getpid() * time(NULL)));
# endif /* HAVE_RANDOM */

#else
  return pr_random_init();
#endif /* Prior to ProFTPD 1.3.7 */
}
