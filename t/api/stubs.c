/*
 * ProFTPD - mod_passwd_update API testsuite
 * Copyright (c) 2021 TJ Saunders <tj@castaglia.org>
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

#include "tests.h"

/* Stubs */

session_t session;
int ServerUseReverseDNS = FALSE;
server_rec *main_server = NULL;
pid_t mpid = 1;
unsigned char is_master = TRUE;
volatile unsigned int recvd_signal_flags = 0;
module *static_modules[] = { NULL };
module *loaded_modules = NULL;
xaset_t *server_list = NULL;

int passwd_update_logfd = -1;
module passwd_update_module;
pool *passwd_update_pool = NULL;

void pr_log_auth(int priority, const char *fmt, ...) {
  if (getenv("TEST_VERBOSE") != NULL) {
    va_list msg;

    fprintf(stderr, "AUTH: ");

    va_start(msg, fmt);
    vfprintf(stderr, fmt, msg);
    va_end(msg);

    fprintf(stderr, "\n");
  }
}

void pr_log_debug(int level, const char *fmt, ...) {
  if (getenv("TEST_VERBOSE") != NULL) {
    va_list msg;

    fprintf(stderr, "DEBUG%d: ", level);

    va_start(msg, fmt);
    vfprintf(stderr, fmt, msg);
    va_end(msg);

    fprintf(stderr, "\n");
  }
}

int pr_log_event_generate(unsigned int log_type, int log_fd, int log_level,
    const char *log_msg, size_t log_msglen) {
  errno = ENOSYS;
  return -1;
}

int pr_log_event_listening(unsigned int log_type) {
  return FALSE;
}

int pr_log_openfile(const char *log_file, int *log_fd, mode_t log_mode) {
  int res;
  struct stat st;

  if (log_file == NULL ||
      log_fd == NULL) {
    errno = EINVAL;
    return -1;
  }

  res = stat(log_file, &st);
  if (res < 0) {
    if (errno != ENOENT) {
      return -1;
    }

  } else {
    if (S_ISDIR(st.st_mode)) {
      errno = EISDIR;
      return -1;
    }
  }

  *log_fd = STDERR_FILENO;
  return 0;
}

void pr_log_pri(int prio, const char *fmt, ...) {
  if (getenv("TEST_VERBOSE") != NULL) {
    va_list msg;

    fprintf(stderr, "PRI%d: ", prio);

    va_start(msg, fmt);
    vfprintf(stderr, fmt, msg);
    va_end(msg);

    fprintf(stderr, "\n");
  }
}

void pr_log_stacktrace(int fd, const char *name) {
}

int pr_log_writefile(int fd, const char *name, const char *fmt, ...) {
  if (getenv("TEST_VERBOSE") != NULL) {
    va_list msg;

    fprintf(stderr, "%s: ", name);

    va_start(msg, fmt);
    vfprintf(stderr, fmt, msg);
    va_end(msg);

    fprintf(stderr, "\n");
  }

  return 0;
}

void pr_session_disconnect(module *m, int reason_code, const char *details) {
}

const char *pr_session_get_protocol(int flags) {
  return "ftp";
}

void pr_signals_handle(void) {
}

/* Module-specific stubs */

module passwd_update_module = {
  /* Always NULL */
  NULL, NULL,

  /* Module API version */
  0x20,

  /* Module name */
  "passwd_update",

  /* Module configuration handler table */
  NULL,

  /* Module command handler table */
  NULL,

  /* Module authentication handler table */
  NULL,

  /* Module initialization */
  NULL,

  /* Session initialization */
  NULL,

  /* Module version */
  MOD_PASSWD_UPDATE_VERSION
};
