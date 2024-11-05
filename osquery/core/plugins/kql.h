/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <osquery/core/plugins/plugin.h>
#include <osquery/core/sql/column.h>
#include <osquery/core/sql/query_data.h>
#include <osquery/utils/status/status.h>

namespace osquery {

class KQLPlugin : public Plugin {
 public:
  /// Run a KQL query string against the KQL implementation.
  virtual Status query(const std::string& query,
                       QueryData& results,
                       bool use_cache) const = 0;

  /// Use the KQL implementation to parse a query string and return details
  /// (name, type) about the columns.
  virtual Status getQueryColumns(const std::string& query,
                                 TableColumns& columns) const = 0;

  /// Given a query, return the list of scanned tables.
  virtual Status getQueryTables(const std::string& query,
                                std::vector<std::string>& tables) const = 0;

  /**
   * @brief Attach a table at runtime.
   *
   * The KQL implementation plugin may need to manage how virtual tables are
   * attached at run time. In the case of KQL where a single DB object is
   * managed, tables are enumerated and attached during initialization.
   */
  virtual Status attach(const std::string& /*name*/) {
    return Status::success();
  }

  /// Tables may be detached by name.
  virtual Status detach(const std::string& /*name*/) {
    return Status::success();
  }

 public:
  Status call(const PluginRequest& request, PluginResponse& response) override;
};

} // namespace osquery
