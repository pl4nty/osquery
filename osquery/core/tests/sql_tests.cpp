/**
 * Copyright (c) 4-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>
#include <osquery/sql/sql.h>
#include <osquery/core/sql/query_data.h>
#include <osquery/utils/status/status.h>

namespace osquery {

class SQLTests : public testing::Test {
 protected:
  void SetUp() override {
    sql_plugin_ = std::make_shared<SQLPlugin>();
    kql_plugin_ = std::make_shared<KQLPlugin>();
  }

  std::shared_ptr<SQLPlugin> sql_plugin_;
  std::shared_ptr<KQLPlugin> kql_plugin_;
};

TEST_F(SQLTests, testSQLQuery) {
  QueryData results;
  auto status = sql_plugin_->query("SELECT * FROM test_table", results, false);
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(results.size(), 1U);
  EXPECT_EQ(results[0]["column1"], "value1");
  EXPECT_EQ(results[0]["column2"], "value2");

  results.clear();
  status = sql_plugin_->query("INVALID QUERY", results, false);
  EXPECT_FALSE(status.ok());
  EXPECT_EQ(results.size(), 0U);
}

TEST_F(SQLTests, testKQLQuery) {
  QueryData results;
  auto status = kql_plugin_->query("valid_query", results, false);
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(results.size(), 1U);
  EXPECT_EQ(results[0]["column1"], "value1");
  EXPECT_EQ(results[0]["column2"], "value2");

  results.clear();
  status = kql_plugin_->query("invalid_query", results, false);
  EXPECT_FALSE(status.ok());
  EXPECT_EQ(results.size(), 0U);
}

TEST_F(SQLTests, testSQLGetQueryColumns) {
  TableColumns columns;
  auto status = sql_plugin_->getQueryColumns("SELECT * FROM test_table", columns);
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(columns.size(), 2U);
  EXPECT_EQ(std::get<0>(columns[0]), "column1");
  EXPECT_EQ(std::get<1>(columns[0]), ColumnType::TEXT_TYPE);
  EXPECT_EQ(std::get<2>(columns[0]), ColumnOptions::DEFAULT);
  EXPECT_EQ(std::get<0>(columns[1]), "column2");
  EXPECT_EQ(std::get<1>(columns[1]), ColumnType::TEXT_TYPE);
  EXPECT_EQ(std::get<2>(columns[1]), ColumnOptions::DEFAULT);

  columns.clear();
  status = sql_plugin_->getQueryColumns("INVALID QUERY", columns);
  EXPECT_FALSE(status.ok());
  EXPECT_EQ(columns.size(), 0U);
}

TEST_F(SQLTests, testKQLGetQueryColumns) {
  TableColumns columns;
  auto status = kql_plugin_->getQueryColumns("valid_query", columns);
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(columns.size(), 2U);
  EXPECT_EQ(std::get<0>(columns[0]), "column1");
  EXPECT_EQ(std::get<1>(columns[0]), ColumnType::TEXT_TYPE);
  EXPECT_EQ(std::get<2>(columns[0]), ColumnOptions::DEFAULT);
  EXPECT_EQ(std::get<0>(columns[1]), "column2");
  EXPECT_EQ(std::get<1>(columns[1]), ColumnType::TEXT_TYPE);
  EXPECT_EQ(std::get<2>(columns[1]), ColumnOptions::DEFAULT);

  columns.clear();
  status = kql_plugin_->getQueryColumns("invalid_query", columns);
  EXPECT_FALSE(status.ok());
  EXPECT_EQ(columns.size(), 0U);
}

TEST_F(SQLTests, testSQLGetQueryTables) {
  std::vector<std::string> tables;
  auto status = sql_plugin_->getQueryTables("SELECT * FROM test_table", tables);
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(tables.size(), 1U);
  EXPECT_EQ(tables[0], "test_table");

  tables.clear();
  status = sql_plugin_->getQueryTables("INVALID QUERY", tables);
  EXPECT_FALSE(status.ok());
  EXPECT_EQ(tables.size(), 0U);
}

TEST_F(SQLTests, testKQLGetQueryTables) {
  std::vector<std::string> tables;
  auto status = kql_plugin_->getQueryTables("valid_query", tables);
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(tables.size(), 2U);
  EXPECT_EQ(tables[0], "table1");
  EXPECT_EQ(tables[1], "table2");

  tables.clear();
  status = kql_plugin_->getQueryTables("invalid_query", tables);
  EXPECT_FALSE(status.ok());
  EXPECT_EQ(tables.size(), 0U);
}

TEST_F(SQLTests, testSQLConstructor) {
  SQL sql("SELECT * FROM test_table", false);
  EXPECT_TRUE(sql.ok());
  EXPECT_EQ(sql.rows().size(), 1U);
  EXPECT_EQ(sql.rows()[0]["column1"], "value1");
  EXPECT_EQ(sql.rows()[0]["column2"], "value2");
  EXPECT_EQ(sql.columns().size(), 2U);
  EXPECT_EQ(sql.columns()[0], "column1");
  EXPECT_EQ(sql.columns()[1], "column2");

  SQL invalid_sql("INVALID QUERY", false);
  EXPECT_FALSE(invalid_sql.ok());
  EXPECT_EQ(invalid_sql.rows().size(), 0U);
}

TEST_F(SQLTests, testKQLConstructor) {
  SQL kql("valid_query", false, true);
  EXPECT_TRUE(kql.ok());
  EXPECT_EQ(kql.rows().size(), 1U);
  EXPECT_EQ(kql.rows()[0]["column1"], "value1");
  EXPECT_EQ(kql.rows()[0]["column2"], "value2");
  EXPECT_EQ(kql.columns().size(), 2U);
  EXPECT_EQ(kql.columns()[0], "column1");
  EXPECT_EQ(kql.columns()[1], "column2");

  SQL invalid_kql("invalid_query", false, true);
  EXPECT_FALSE(invalid_kql.ok());
  EXPECT_EQ(invalid_kql.rows().size(), 0U);
}

} // namespace osquery
