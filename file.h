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

#ifndef MOD_PASSWD_UPDATE_FILE_H
#define MOD_PASSWD_UPDATE_FILE_H

#include "mod_passwd_update.h"

struct passwd *passwd_update_file_get_entry(pool *p, pr_fh_t *fh,
  const char *user, int flags);
#define PASSWD_UPDATE_FILE_FL_USE_LOCK	0x001

int passwd_update_file_add_entry(pool *p, struct passwd *pwd);

#endif /* MOD_PASSWD_UPDATE_FILE_H */
