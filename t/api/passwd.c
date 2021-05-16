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

/* Password tests. */

#include "tests.h"

static pool *p = NULL;

static void set_up(void) {
  if (p == NULL) {
    p = permanent_pool = make_sub_pool(NULL);
  }

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("passwd_update.passwd", 1, 20);
  }

  mark_point();
  passwd_update_init_salt();
}

static void tear_down(void) {
  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("passwd_update.passwd", 0, 0);
  }

  if (p != NULL) {
    destroy_pool(p);
    p = permanent_pool = NULL;
  }
}

START_TEST (passwd_get_hash_test) {
  const char *hash, *plaintext;

  mark_point();
  hash = passwd_update_get_hash(NULL, NULL, 0);
  fail_unless(hash == NULL, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  hash = passwd_update_get_hash(p, NULL, 0);
  fail_unless(hash == NULL, "Failed to handle null plaintext");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  plaintext = "password";

  mark_point();
  hash = passwd_update_get_hash(p, plaintext, 0);
  fail_unless(hash == NULL, "Failed to handle unknown algorithm ID");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  hash = passwd_update_get_hash(p, plaintext, PASSWD_UPDATE_ALGO_SHA256);
  fail_unless(hash != NULL, "Failed to get SHA256 password hash: %s",
    strerror(errno));

  mark_point();
  hash = passwd_update_get_hash(p, plaintext, PASSWD_UPDATE_ALGO_SHA512);
  fail_unless(hash != NULL, "Failed to get SHA512 password hash: %s",
    strerror(errno));
}
END_TEST

START_TEST (passwd_to_text_test) {
  const char *text, *expected;
  struct passwd pwd;

  mark_point();
  text = passwd_update_to_text(NULL, NULL);
  fail_unless(text == NULL, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  text = passwd_update_to_text(p, NULL);
  fail_unless(text == NULL, "Failed to handle null passwd");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  memset(&pwd, 0, sizeof(pwd));

  mark_point();
  text = passwd_update_to_text(p, &pwd);
  fail_unless(text == NULL, "Failed to handle null pw_name");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  pwd.pw_name = "test";

  mark_point();
  text = passwd_update_to_text(p, &pwd);
  fail_unless(text == NULL, "Failed to handle null pw_passwd");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  /* All other fields are largely optional. */

  pwd.pw_passwd = "enterpasswordhashhere";
  pwd.pw_uid = 1;
  pwd.pw_gid = 1;
  pwd.pw_dir = "/home/test";
  pwd.pw_shell = "/bin/bash";

  expected = "test:enterpasswordhashhere:1:1::/home/test:/bin/bash";

  mark_point();
  text = passwd_update_to_text(p, &pwd);
  fail_unless(text != NULL, "Failed to handle pwd: %s", strerror(errno));
  fail_unless(strcmp(text, expected) == 0, "Expected '%s', got '%s'",
    expected, text);
}
END_TEST

Suite *tests_get_passwd_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("passwd");
  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, passwd_get_hash_test);
  tcase_add_test(testcase, passwd_to_text_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
