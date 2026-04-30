// Copyright (c) 2014-present, The osquery authors
//
// This source code is licensed as defined by the LICENSE file found in the
// root directory of this source tree.
//
// SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

using Osquery.Tables;

namespace Osquery.Tests;

/// <summary>
/// Tests for query execution and row mapping.
/// </summary>
public class QueryExecutionTests : IDisposable
{
    private readonly MockOsqueryConnection _connection;
    private readonly OsqueryClient _client;

    public QueryExecutionTests()
    {
        _connection = new MockOsqueryConnection();
        _client = new OsqueryClient(_connection);
    }

    [Fact]
    public async Task Query_ReturnsResult()
    {
        _connection.MockRows = new List<Dictionary<string, string>>
        {
            new() { ["pid"] = "1", ["name"] = "init" }
        };

        var result = await _client.QueryAsync("SELECT * FROM processes WHERE pid = 1");

        Assert.True(result.Status.IsSuccess);
        Assert.Single(result.Rows);
        Assert.Equal("1", result.Rows[0]["pid"]);
        Assert.Equal("init", result.Rows[0]["name"]);
    }

    [Fact]
    public void LinqQuery_MapsRowsToObjects()
    {
        _connection.MockRows = new List<Dictionary<string, string>>
        {
            new() { ["pid"] = "1", ["name"] = "init", ["path"] = "/sbin/init", ["uid"] = "0" },
            new() { ["pid"] = "42", ["name"] = "sshd", ["path"] = "/usr/sbin/sshd", ["uid"] = "0" }
        };

        var processes = _client.Table<Process>().Where(p => p.Uid == 0).ToList();

        Assert.Equal(2, processes.Count);
        Assert.Equal(1, processes[0].Pid);
        Assert.Equal("init", processes[0].Name);
        Assert.Equal(42, processes[1].Pid);
        Assert.Equal("sshd", processes[1].Name);
    }

    [Fact]
    public void LinqQuery_ExecutesCorrectSql()
    {
        _connection.MockRows = new List<Dictionary<string, string>>();

        _ = _client.Table<Process>().Where(p => p.Pid == 1).ToList();

        Assert.Single(_connection.ExecutedQueries);
        Assert.Equal("SELECT * FROM processes WHERE pid = 1", _connection.ExecutedQueries[0]);
    }

    [Fact]
    public void LinqQuery_MapsUserCorrectly()
    {
        _connection.MockRows = new List<Dictionary<string, string>>
        {
            new() { ["uid"] = "0", ["gid"] = "0", ["username"] = "root", ["shell"] = "/bin/bash" }
        };

        var users = _client.Table<User>().Where(u => u.Uid == 0).ToList();

        Assert.Single(users);
        Assert.Equal("root", users[0].Username);
        Assert.Equal("/bin/bash", users[0].Shell);
    }

    [Fact]
    public void Query_FailedStatus_ThrowsException()
    {
        _connection.MockStatus = new ExtensionStatus(1, "Table not found");
        _connection.MockRows = new List<Dictionary<string, string>>();

        var ex = Assert.Throws<OsqueryException>(() =>
            _client.Table<Process>().ToList());
        Assert.Contains("Table not found", ex.Message);
    }

    [Fact]
    public void SyncQuery_Works()
    {
        _connection.MockRows = new List<Dictionary<string, string>>
        {
            new() { ["pid"] = "1", ["name"] = "systemd" }
        };

        var result = _client.Query("SELECT * FROM processes LIMIT 1");

        Assert.True(result.Status.IsSuccess);
        Assert.Single(result.Rows);
    }

    public void Dispose()
    {
        _client.Dispose();
    }
}
