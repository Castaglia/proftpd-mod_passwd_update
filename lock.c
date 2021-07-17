/*
 * ProFTPD - mod_passwd_update locks
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

static const char *trace_channel = "passwd_update.lock";

int passwd_update_rlock(pool *p, int fd) {
  int res, xerrno;
#if !defined(HAVE_FLOCK)
  struct flock lock;
#endif /* HAVE_FLOCK */

  if (p == NULL) {
    errno = EINVAL;
    return -1;
  }

#if defined(HAVE_FLOCK)
  res = flock(fd, LOCK_SH);
  xerrno = errno;

  if (res < 0) {
    pr_trace_msg(trace_channel, 7, "error read-locking fd %d: %s", fd,
      strerror(xerrno));
  }
#else
  lock.l_type = F_RDLCK;
  lock.l_whence = 0;
  lock.l_start = lock.l_len = 0;
 
  res = fcnctl(fd, F_SETLKW, &lock);
  xerrno = errno;

  while (res < 0) {
    if (xerrno == EINTR) {
      pr_signals_handle();

      res = fcnctl(fd, F_SETLKW, &lock);
      continue;
    }

    pr_trace_msg(trace_channel, 7, "error read-locking fd %d: %s", fd,
      strerror(xerrno));
    break;
  }
#endif /* HAVE_FLOCK */

  errno = xerrno;
  return res;
}

int passwd_update_wlock(pool *p, int fd) {
  int res, xerrno;
#if !defined(HAVE_FLOCK)
  struct flock lock;
#endif /* HAVE_FLOCK */

  if (p == NULL) {
    errno = EINVAL;
    return -1;
  }

#if defined(HAVE_FLOCK)
  res = flock(fd, LOCK_EX);
  xerrno = errno;

  if (res < 0) {
    pr_trace_msg(trace_channel, 7, "error write-locking fd %d: %s", fd,
      strerror(xerrno));
  }
#else
  lock.l_type = F_WRLCK;
  lock.l_whence = 0;
  lock.l_start = lock.l_len = 0;
 
  res = fcnctl(fd, F_SETLKW, &lock);
  xerrno = errno;

  while (res < 0) {
    if (xerrno == EINTR) {
      pr_signals_handle();

      res = fcnctl(fd, F_SETLKW, &lock);
      continue;
    }

    pr_trace_msg(trace_channel, 7, "error write-locking fd %d: %s",
      fd, strerror(xerrno));
    break;
  }
#endif /* HAVE_FLOCK */

  errno = xerrno;
  return res;
}

int passwd_update_ulock(pool *p, int fd) {
  int res, xerrno;
#if !defined(HAVE_FLOCK)
  struct flock lock;
#endif /* HAVE_FLOCK */

  if (p == NULL) {
    errno = EINVAL;
    return -1;
  }

#if defined(HAVE_FLOCK)
  res = flock(fd, LOCK_UN);
  xerrno = errno;

  if (res < 0) {
    pr_trace_msg(trace_channel, 7, "error unlocking fd %d: %s", fd,
      strerror(xerrno));
  }
#else
  lock.l_type = F_UNLCK;
  lock.l_whence = 0;
  lock.l_start = lock.l_len = 0;

  res = fcnctl(fd, F_SETLKW, &lock);
  while (res < 0) {
    xerrno = errno;

    if (xerrno == EINTR) {
      pr_signals_handle();

      res = fcnctl(fd, F_SETLKW, &lock);
      continue;
    }

    pr_trace_msg(trace_channel, 7, "error unlocking fd %d: %s", fd,
      strerror(xerrno));
    break;
  }
#endif /* HAVE_FLOCK */

  errno = xerrno;
  return res;
}
