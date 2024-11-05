/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "kql.h"

namespace osquery {

Status KQLPlugin::query(const std::string& query,
                        QueryData& results,
                        bool use_cache) const {
  // Implement the KQL query execution logic here
  // This is a placeholder implementation
  return Status(1, "KQL query execution not implemented");
}

Status KQLPlugin::getQueryColumns(const std::string& query,
                                  TableColumns& columns) const {
  // Implement the KQL query column extraction logic here
  // This is a placeholder implementation
  return Status(1, "KQL query column extraction not implemented");
}

Status KQLPlugin::getQueryTables(const std::string& query,
                                 std::vector<std::string>& tables) const {
  // Implement the KQL query table extraction logic here
  // This is a placeholder implementation
  return Status(1, "KQL query table extraction not implemented");
}

Status KQLPlugin::call(const PluginRequest& request, PluginResponse& response) {
  response.clear();
  if (request.count("action") == 0) {
    return Status(1, "KQL plugin must include a request action");
  }

  if (request.at("action") == "query") {
    bool use_cache = (request.count("cache") && request.at("cache") == "1");
    return this->query(request.at("query"), response, use_cache);
  } else if (request.at("action") == "columns") {
    TableColumns columns;
    auto status = this->getQueryColumns(request.at("query"), columns);
    // Convert columns to response
    for (const auto& column : columns) {
      response.push_back(
          {{"n", std::get<0>(column)},
           {"t", columnTypeName(std::get<1>(column))},
           {"o", INTEGER(static_cast<size_t>(std::get<2>(column)))}});
    }
    return status;
  } else if (request.at("action") == "attach") {
    // Attach a virtual table name using an optional included definition.
    return this->attach(request.at("table"));
  } else if (request.at("action") == "detach") {
    return this->detach(request.at("table"));
  } else if (request.at("action") == "tables") {
    std::vector<std::string> tables;
    auto status = this->getQueryTables(request.at("query"), tables);
    if (status.ok()) {
      for (const auto& table : tables) {
        response.push_back({{"t", table}});
      }
    }
    return status;
  }
  return Status(1, "Unknown action");
}

REGISTER(KQLPlugin, "sql", "kql");

} // namespace osquery
