/*
 * ProFTPD - mod_passwd_update API testsuite
 * Copyright (c) 2021-2022 TJ Saunders <tj@castaglia.org>
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

/* Lock tests. */

#include "tests.h"

static pool *p = NULL;

static void set_up(void) {
  if (p == NULL) {
    p = permanent_pool = make_sub_pool(NULL);
  }

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("passwd_update.lock", 1, 20);
  }

  mark_point();
}

static void tear_down(void) {
  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("passwd_update.lock", 0, 0);
  }

  if (p != NULL) {
    destroy_pool(p);
    p = permanent_pool = NULL;
  }
}

START_TEST (lock_ulock_test) {
  int fd, res;

  mark_point();
  res = passwd_update_ulock(NULL, -1);
  ck_assert_msg(res < 0, "Failed to handle null pool");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  fd = -1;

  mark_point();
  res = passwd_update_ulock(p, fd);
  ck_assert_msg(res < 0, "Failed to handle bad fd");
  ck_assert_msg(errno == EBADF, "Expected EBADF (%d), got %s (%d)", EBADF,
    strerror(errno), errno);

  fd = 0;

  mark_point();
  res = passwd_update_ulock(p, fd);
  ck_assert_msg(res == 0, "Failed to unlock fd %d: %s", fd, strerror(errno));
}
END_TEST

START_TEST (lock_rlock_test) {
  int fd, res;

  mark_point();
  res = passwd_update_rlock(NULL, -1);
  ck_assert_msg(res < 0, "Failed to handle null pool");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  fd = -1;

  mark_point();
  res = passwd_update_rlock(p, fd);
  ck_assert_msg(res < 0, "Failed to handle bad fd");
  ck_assert_msg(errno == EBADF, "Expected EBADF (%d), got %s (%d)", EBADF,
    strerror(errno), errno);

  fd = 0;

  mark_point();
  res = passwd_update_rlock(p, fd);
  ck_assert_msg(res == 0, "Failed to unlock fd %d: %s", fd, strerror(errno));
  (void) passwd_update_ulock(p, fd);
}
END_TEST

START_TEST (lock_wlock_test) {
  int fd, res;

  mark_point();
  res = passwd_update_wlock(NULL, -1);
  ck_assert_msg(res < 0, "Failed to handle null pool");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  fd = -1;

  mark_point();
  res = passwd_update_wlock(p, fd);
  ck_assert_msg(res < 0, "Failed to handle bad fd");
  ck_assert_msg(errno == EBADF, "Expected EBADF (%d), got %s (%d)", EBADF,
    strerror(errno), errno);

  fd = 0;

  mark_point();
  res = passwd_update_wlock(p, fd);
  ck_assert_msg(res == 0, "Failed to unlock fd %d: %s", fd, strerror(errno));
  (void) passwd_update_ulock(p, fd);
}
END_TEST

Suite *tests_get_lock_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("lock");
  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, lock_ulock_test);
  tcase_add_test(testcase, lock_rlock_test);
  tcase_add_test(testcase, lock_wlock_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
