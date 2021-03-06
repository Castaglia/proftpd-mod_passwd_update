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

/* Salt tests. */

#include "tests.h"

static pool *p = NULL;

static void set_up(void) {
  if (p == NULL) {
    p = permanent_pool = make_sub_pool(NULL);
  }

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("passwd_update.salt", 1, 20);
  }

  mark_point();
  passwd_update_init_salt();
}

static void tear_down(void) {
  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("passwd_update.salt", 0, 0);
  }

  if (p != NULL) {
    destroy_pool(p);
    p = permanent_pool = NULL;
  }
}

START_TEST (salt_invalid_args_test) {
  const char *salt;

  mark_point();
  salt = passwd_update_get_salt(NULL, 0);
  ck_assert_msg(salt == NULL, "Failed to handle null pool");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  salt = passwd_update_get_salt(p, 0);
  ck_assert_msg(salt == NULL, "Failed to handle unknown algorithm ID");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);
}
END_TEST

START_TEST (salt_sha256_test) {
  const char *salt, *prefix = "$5$";

  mark_point();
  salt = passwd_update_get_salt(p, PASSWD_UPDATE_ALGO_SHA256);
  ck_assert_msg(salt != NULL, "Failed to generate SHA256 salt: %s",
    strerror(errno));
  ck_assert_msg(strncmp(salt, prefix, 3) == 0,
    "Missing expected '%s' SHA256 salt prefix", prefix);
}
END_TEST

START_TEST (salt_sha512_test) {
  const char *salt;

  mark_point();
  salt = passwd_update_get_salt(p, PASSWD_UPDATE_ALGO_DES);
  ck_assert_msg(salt != NULL, "Failed to generate DES salt: %s",
    strerror(errno));
}
END_TEST

START_TEST (salt_des_test) {
  const char *salt, *prefix = "$6$";

  mark_point();
  salt = passwd_update_get_salt(p, PASSWD_UPDATE_ALGO_SHA512);
  ck_assert_msg(salt != NULL, "Failed to generate SHA512 salt: %s",
    strerror(errno));
  ck_assert_msg(strncmp(salt, prefix, 3) == 0,
    "Missing expected '%s' SHA512 salt prefix", prefix);
}
END_TEST

Suite *tests_get_salt_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("salt");
  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, salt_invalid_args_test);
  tcase_add_test(testcase, salt_sha256_test);
  tcase_add_test(testcase, salt_sha512_test);
  tcase_add_test(testcase, salt_des_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
