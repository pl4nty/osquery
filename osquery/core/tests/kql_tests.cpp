/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>
#include <osquery/core/plugins/kql.h>
#include <osquery/core/sql/query_data.h>
#include <osquery/utils/status/status.h>

namespace osquery {

class MockKQLPlugin : public KQLPlugin {
 public:
  Status query(const std::string& query,
               QueryData& results,
               bool use_cache) const override {
    // Mock implementation for testing
    if (query == "valid_query") {
      results.push_back({{"column1", "value1"}, {"column2", "value2"}});
      return Status::success();
    }
    return Status(1, "Invalid query");
  }

  Status getQueryColumns(const std::string& query,
                         TableColumns& columns) const override {
    // Mock implementation for testing
    if (query == "valid_query") {
      columns.push_back(std::make_tuple("column1", ColumnType::TEXT_TYPE, ColumnOptions::DEFAULT));
      columns.push_back(std::make_tuple("column2", ColumnType::TEXT_TYPE, ColumnOptions::DEFAULT));
      return Status::success();
    }
    return Status(1, "Invalid query");
  }

  Status getQueryTables(const std::string& query,
                        std::vector<std::string>& tables) const override {
    // Mock implementation for testing
    if (query == "valid_query") {
      tables.push_back("table1");
      tables.push_back("table2");
      return Status::success();
    }
    return Status(1, "Invalid query");
  }
};

class KQLPluginTests : public testing::Test {
 protected:
  void SetUp() override {
    plugin_ = std::make_shared<MockKQLPlugin>();
  }

  std::shared_ptr<MockKQLPlugin> plugin_;
};

TEST_F(KQLPluginTests, testQuery) {
  QueryData results;
  auto status = plugin_->query("valid_query", results, false);
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(results.size(), 1U);
  EXPECT_EQ(results[0]["column1"], "value1");
  EXPECT_EQ(results[0]["column2"], "value2");

  results.clear();
  status = plugin_->query("invalid_query", results, false);
  EXPECT_FALSE(status.ok());
  EXPECT_EQ(results.size(), 0U);
}

TEST_F(KQLPluginTests, testGetQueryColumns) {
  TableColumns columns;
  auto status = plugin_->getQueryColumns("valid_query", columns);
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(columns.size(), 2U);
  EXPECT_EQ(std::get<0>(columns[0]), "column1");
  EXPECT_EQ(std::get<1>(columns[0]), ColumnType::TEXT_TYPE);
  EXPECT_EQ(std::get<2>(columns[0]), ColumnOptions::DEFAULT);
  EXPECT_EQ(std::get<0>(columns[1]), "column2");
  EXPECT_EQ(std::get<1>(columns[1]), ColumnType::TEXT_TYPE);
  EXPECT_EQ(std::get<2>(columns[1]), ColumnOptions::DEFAULT);

  columns.clear();
  status = plugin_->getQueryColumns("invalid_query", columns);
  EXPECT_FALSE(status.ok());
  EXPECT_EQ(columns.size(), 0U);
}

TEST_F(KQLPluginTests, testGetQueryTables) {
  std::vector<std::string> tables;
  auto status = plugin_->getQueryTables("valid_query", tables);
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(tables.size(), 2U);
  EXPECT_EQ(tables[0], "table1");
  EXPECT_EQ(tables[1], "table2");

  tables.clear();
  status = plugin_->getQueryTables("invalid_query", tables);
  EXPECT_FALSE(status.ok());
  EXPECT_EQ(tables.size(), 0U);
}

} // namespace osquery
