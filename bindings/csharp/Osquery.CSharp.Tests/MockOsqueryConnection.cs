// Copyright (c) 2014-present, The osquery authors
//
// This source code is licensed as defined by the LICENSE file found in the
// root directory of this source tree.
//
// SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

namespace Osquery.Tests;

/// <summary>
/// Mock connection for unit testing without a real osquery instance.
/// </summary>
internal class MockOsqueryConnection : IOsqueryConnection
{
    public List<string> ExecutedQueries { get; } = new();
    public List<Dictionary<string, string>> MockRows { get; set; } = new();
    public ExtensionStatus MockStatus { get; set; } = new(0, "OK");

    public Task EnsureConnectedAsync()
    {
        return Task.CompletedTask;
    }

    public Task<QueryResult> QueryAsync(string sql)
    {
        ExecutedQueries.Add(sql);
        return Task.FromResult(new QueryResult(MockStatus, MockRows.ToList()));
    }

    public void Dispose() { }
}
