/* -*- c-basic-offset: 2; coding: utf-8 -*- */
/*
  Copyright (C) 2015  Kouhei Sutou <kou@clear-code.com>

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License version 2.1 as published by the Free Software Foundation.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

#include <groonga.h>

#include <gcutter.h>
#include <glib/gstdio.h>

#include "../lib/grn-assertions.h"

#define get(name) grn_ctx_get(context, name, strlen(name))

void data_exec_equal_true(void);
void test_exec_equal_true(gconstpointer data);
void data_exec_equal_false(void);
void test_exec_equal_false(gconstpointer data);
void data_exec_not_equal_true(void);
void test_exec_not_equal_true(gconstpointer data);
void data_exec_not_equal_false(void);
void test_exec_not_equal_false(gconstpointer data);

static gchar *tmp_directory;

static grn_ctx *context;
static grn_obj *database;

static grn_obj lhs;
static grn_obj rhs;

void
cut_startup(void)
{
  tmp_directory = g_build_filename(grn_test_get_tmp_dir(),
                                   "operator",
                                   NULL);
}

void
cut_shutdown(void)
{
  g_free(tmp_directory);
}

static void
remove_tmp_directory(void)
{
  cut_remove_path(tmp_directory, NULL);
}

void
cut_setup(void)
{
  const gchar *database_path;

  remove_tmp_directory();
  g_mkdir_with_parents(tmp_directory, 0700);

  context = g_new0(grn_ctx, 1);
  grn_ctx_init(context, 0);

  database_path = cut_build_path(tmp_directory, "database.groonga", NULL);
  database = grn_db_create(context, database_path, NULL);

  GRN_VOID_INIT(&lhs);
  GRN_VOID_INIT(&rhs);
}

void
cut_teardown(void)
{
  GRN_OBJ_FIN(context, &lhs);
  GRN_OBJ_FIN(context, &rhs);

  grn_obj_close(context, database);
  grn_ctx_fin(context);
  g_free(context);

  remove_tmp_directory();
}

static void
set_one(grn_obj *value, const gchar *type)
{
  if (strcmp(type, "text") == 0) {
    grn_obj_reinit(context, value, GRN_DB_TEXT, 0);
    GRN_TEXT_SETS(context, value, "1");
  } else if (strcmp(type, "int32") == 0) {
    grn_obj_reinit(context, value, GRN_DB_INT32, 0);
    GRN_INT32_SET(context, value, 1);
  }
}

static void
set_two(grn_obj *value, const gchar *type)
{
  if (strcmp(type, "text") == 0) {
    grn_obj_reinit(context, value, GRN_DB_TEXT, 0);
    GRN_TEXT_SETS(context, value, "2");
  } else if (strcmp(type, "int32") == 0) {
    grn_obj_reinit(context, value, GRN_DB_INT32, 0);
    GRN_INT32_SET(context, value, 2);
  }
}

void
data_exec_equal_true(void)
{
#define ADD_DATA(lhs_type, rhs_type)                            \
  gcut_add_datum(lhs_type " == " rhs_type,                      \
                 "lhs_type", G_TYPE_STRING, lhs_type,           \
                 "rhs_type", G_TYPE_STRING, rhs_type,           \
                 NULL)

  ADD_DATA("text", "text");
  ADD_DATA("text", "int32");
  ADD_DATA("int32", "text");

#undef ADD_DATA
}

void
test_exec_equal_true(gconstpointer data)
{
  const gchar *lhs_type;
  const gchar *rhs_type;

  lhs_type = gcut_data_get_string(data, "lhs_type");
  rhs_type = gcut_data_get_string(data, "rhs_type");

  set_one(&lhs, lhs_type);
  set_one(&rhs, rhs_type);

  cut_assert_true(grn_operator_exec_equal(context, &lhs, &rhs));
}

void
data_exec_equal_false(void)
{
#define ADD_DATA(lhs_type, rhs_type)                            \
  gcut_add_datum(lhs_type " == " rhs_type,                      \
                 "lhs_type", G_TYPE_STRING, lhs_type,           \
                 "rhs_type", G_TYPE_STRING, rhs_type,           \
                 NULL)

  ADD_DATA("text", "text");
  ADD_DATA("text", "int32");
  ADD_DATA("int32", "text");

#undef ADD_DATA
}

void
test_exec_equal_false(gconstpointer data)
{
  const gchar *lhs_type;
  const gchar *rhs_type;

  lhs_type = gcut_data_get_string(data, "lhs_type");
  rhs_type = gcut_data_get_string(data, "rhs_type");

  set_one(&lhs, lhs_type);
  set_two(&rhs, rhs_type);

  cut_assert_false(grn_operator_exec_equal(context, &lhs, &rhs));
}

void
data_exec_not_equal_true(void)
{
#define ADD_DATA(lhs_type, rhs_type)                            \
  gcut_add_datum(lhs_type " != " rhs_type,                      \
                 "lhs_type", G_TYPE_STRING, lhs_type,           \
                 "rhs_type", G_TYPE_STRING, rhs_type,           \
                 NULL)

  ADD_DATA("text", "text");
  ADD_DATA("text", "int32");
  ADD_DATA("int32", "text");

#undef ADD_DATA
}

void
test_exec_not_equal_true(gconstpointer data)
{
  const gchar *lhs_type;
  const gchar *rhs_type;

  lhs_type = gcut_data_get_string(data, "lhs_type");
  rhs_type = gcut_data_get_string(data, "rhs_type");

  set_one(&lhs, lhs_type);
  set_two(&rhs, rhs_type);

  cut_assert_true(grn_operator_exec_not_equal(context, &lhs, &rhs));
}

void
data_exec_not_equal_false(void)
{
#define ADD_DATA(lhs_type, rhs_type)                            \
  gcut_add_datum(lhs_type " != " rhs_type,                      \
                 "lhs_type", G_TYPE_STRING, lhs_type,           \
                 "rhs_type", G_TYPE_STRING, rhs_type,           \
                 NULL)

  ADD_DATA("text", "text");
  ADD_DATA("text", "int32");
  ADD_DATA("int32", "text");

#undef ADD_DATA
}

void
test_exec_not_equal_false(gconstpointer data)
{
  const gchar *lhs_type;
  const gchar *rhs_type;

  lhs_type = gcut_data_get_string(data, "lhs_type");
  rhs_type = gcut_data_get_string(data, "rhs_type");

  set_one(&lhs, lhs_type);
  set_one(&rhs, rhs_type);

  cut_assert_false(grn_operator_exec_not_equal(context, &lhs, &rhs));
}