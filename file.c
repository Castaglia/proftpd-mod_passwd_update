/*
 * ProFTPD - mod_passwd_update files
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
#include "lock.h"
#include "passwd.h"
#include "file.h"

static const char *trace_channel = "passwd_update.file";

struct passwd *passwd_update_file_get_entry(pool *p, pr_fh_t *fh,
    const char *user, int flags) {
  int res;
  char buf[PR_TUNABLE_BUFFER_SIZE];
  struct passwd *pwd = NULL;

  if (p == NULL ||
      fh == NULL ||
      user == NULL) {
    errno = EINVAL;
    return NULL;
  }

  if (flags & PASSWD_UPDATE_FILE_FL_USE_LOCK) {
    res = passwd_update_rlock(p, PR_FH_FD(fh));
    if (res < 0) {
      return NULL;
    }
  }

  (void) pr_fsio_lseek(fh, 0, SEEK_SET);

  memset(buf, '\0', sizeof(buf));
  while (pr_fsio_gets(buf, sizeof(buf)-1, fh) != NULL) {
    size_t buflen;

    pr_signals_handle();

    /* Ignore comments, empty lines. */
    if (buf[0] == '\0' ||
        buf[0] == '#') {
      memset(buf, '\0', sizeof(buf));
      continue;
    }

    buflen = strlen(buf);
    buf[buflen-1] = '\0';
    buflen--;

    pwd = passwd_update_from_text(p, buf, buflen);
    if (pwd == NULL) {
      memset(buf, '\0', sizeof(buf));
      continue;
    }

    if (strcmp(pwd->pw_name, user) == 0) {
      break;
    }

    /* Not this entry; keep looking. */
    pwd = NULL;
  }

  if (pwd == NULL) {
    if (flags & PASSWD_UPDATE_FILE_FL_USE_LOCK) {
      (void) passwd_update_ulock(p, PR_FH_FD(fh));
    }

    errno = ENOENT;
    return NULL;
  }

  if (flags & PASSWD_UPDATE_FILE_FL_USE_LOCK) {
    (void) passwd_update_ulock(p, PR_FH_FD(fh));
  }

  return pwd;
}

int passwd_update_file_add_entry(pool *p, pr_fh_t *fh, struct passwd *pwd) {
  int res;
  const char *text;
  size_t text_len;
  struct stat st;
  ssize_t nwritten;

  if (p == NULL ||
      fh == NULL ||
      pwd == NULL) {
    errno = EINVAL;
    return -1;
  }

  text = passwd_update_to_text(p, pwd);
  if (text == NULL) {
    return -1;
  }

  /* Don't forget the trailing newline. */
  text = pstrcat(p, text, "\n", NULL);
  text_len = strlen(text);

  res = passwd_update_wlock(p, PR_FH_FD(fh));
  if (res < 0) {
    return -1;
  }

  (void) pr_fs_clear_cache2(fh->fh_path);

  res = pr_fsio_fstat(fh, &st);
  if (res < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 3, "error checking fd %d (%s): %s",
      PR_FH_FD(fh), fh->fh_path, strerror(xerrno));

    (void) passwd_update_ulock(p, PR_FH_FD(fh));
    errno = xerrno;
    return -1;
  }

  nwritten = pr_fsio_pwrite(fh, text, text_len, st.st_size);
  if (nwritten < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 3, "error writing %lu bytes to fd %d (%s): %s",
      (unsigned long) text_len, PR_FH_FD(fh), fh->fh_path, strerror(xerrno));

    (void) passwd_update_ulock(p, PR_FH_FD(fh));
    errno = xerrno;
    return -1;
  }

  /* Make sure these bytes are flushed to disk, for the next stat(2). */
  res = pr_fsio_fsync(fh);
  if (res < 0) {
    pr_trace_msg(trace_channel, 3, "error flushing fd %d (%s): %s",
      PR_FH_FD(fh), fh->fh_path, strerror(errno));
  }

  (void) passwd_update_ulock(p, PR_FH_FD(fh));
  return 0;
}
