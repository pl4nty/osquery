// Copyright (c) 2014-present, The osquery authors
//
// This source code is licensed as defined by the LICENSE file found in the
// root directory of this source tree.
//
// SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

using Osquery.Tables;

namespace Osquery.Tests;

/// <summary>
/// Tests for the LINQ-to-osquery SQL translation.
/// </summary>
public class LinqTranslationTests : IDisposable
{
    private readonly MockOsqueryConnection _connection;
    private readonly OsqueryClient _client;

    public LinqTranslationTests()
    {
        _connection = new MockOsqueryConnection();
        _client = new OsqueryClient(_connection);
    }

    [Fact]
    public void SelectAll_GeneratesCorrectSql()
    {
        var query = _client.Table<Process>();
        var sql = GetGeneratedSql(query.Expression);
        Assert.Equal("SELECT * FROM processes", sql);
    }

    [Fact]
    public void Where_Equal_GeneratesCorrectSql()
    {
        var query = _client.Table<Process>().Where(p => p.Pid == 1);
        var sql = GetGeneratedSql(query.Expression);
        Assert.Equal("SELECT * FROM processes WHERE pid = 1", sql);
    }

    [Fact]
    public void Where_StringEqual_GeneratesCorrectSql()
    {
        var query = _client.Table<Process>().Where(p => p.Name == "osqueryd");
        var sql = GetGeneratedSql(query.Expression);
        Assert.Equal("SELECT * FROM processes WHERE name = 'osqueryd'", sql);
    }

    [Fact]
    public void Where_GreaterThan_GeneratesCorrectSql()
    {
        var query = _client.Table<Process>().Where(p => p.Uid > 1000);
        var sql = GetGeneratedSql(query.Expression);
        Assert.Equal("SELECT * FROM processes WHERE uid > 1000", sql);
    }

    [Fact]
    public void Where_And_GeneratesCorrectSql()
    {
        var query = _client.Table<Process>().Where(p => p.Uid == 0 && p.Name == "init");
        var sql = GetGeneratedSql(query.Expression);
        Assert.Equal("SELECT * FROM processes WHERE (uid = 0 AND name = 'init')", sql);
    }

    [Fact]
    public void Where_Or_GeneratesCorrectSql()
    {
        var query = _client.Table<Process>().Where(p => p.Pid == 1 || p.Pid == 2);
        var sql = GetGeneratedSql(query.Expression);
        Assert.Equal("SELECT * FROM processes WHERE (pid = 1 OR pid = 2)", sql);
    }

    [Fact]
    public void Where_Contains_GeneratesLikeSql()
    {
        var query = _client.Table<Process>().Where(p => p.Name.Contains("query"));
        var sql = GetGeneratedSql(query.Expression);
        Assert.Equal("SELECT * FROM processes WHERE name LIKE '%query%'", sql);
    }

    [Fact]
    public void Where_StartsWith_GeneratesLikeSql()
    {
        var query = _client.Table<Process>().Where(p => p.Path.StartsWith("/usr"));
        var sql = GetGeneratedSql(query.Expression);
        Assert.Equal("SELECT * FROM processes WHERE path LIKE '/usr%'", sql);
    }

    [Fact]
    public void Where_EndsWith_GeneratesLikeSql()
    {
        var query = _client.Table<Process>().Where(p => p.Path.EndsWith(".exe"));
        var sql = GetGeneratedSql(query.Expression);
        Assert.Equal("SELECT * FROM processes WHERE path LIKE '%.exe'", sql);
    }

    [Fact]
    public void OrderBy_GeneratesCorrectSql()
    {
        var query = _client.Table<Process>().OrderBy(p => p.Pid);
        var sql = GetGeneratedSql(query.Expression);
        Assert.Equal("SELECT * FROM processes ORDER BY pid ASC", sql);
    }

    [Fact]
    public void OrderByDescending_GeneratesCorrectSql()
    {
        var query = _client.Table<Process>().OrderByDescending(p => p.StartTime);
        var sql = GetGeneratedSql(query.Expression);
        Assert.Equal("SELECT * FROM processes ORDER BY start_time DESC", sql);
    }

    [Fact]
    public void Take_GeneratesLimitSql()
    {
        var query = _client.Table<Process>().Take(10);
        var sql = GetGeneratedSql(query.Expression);
        Assert.Equal("SELECT * FROM processes LIMIT 10", sql);
    }

    [Fact]
    public void CombinedQuery_GeneratesCorrectSql()
    {
        var query = _client.Table<Process>()
            .Where(p => p.Uid == 0)
            .OrderByDescending(p => p.StartTime)
            .Take(5);
        var sql = GetGeneratedSql(query.Expression);
        Assert.Equal("SELECT * FROM processes WHERE uid = 0 ORDER BY start_time DESC LIMIT 5", sql);
    }

    [Fact]
    public void MultipleWheres_GeneratesAndSql()
    {
        var query = _client.Table<Process>()
            .Where(p => p.Uid == 0)
            .Where(p => p.Name == "init");
        var sql = GetGeneratedSql(query.Expression);
        Assert.Equal("SELECT * FROM processes WHERE uid = 0 AND name = 'init'", sql);
    }

    [Fact]
    public void UserTable_UsesCorrectTableName()
    {
        var query = _client.Table<User>().Where(u => u.Username == "root");
        var sql = GetGeneratedSql(query.Expression);
        Assert.Equal("SELECT * FROM users WHERE username = 'root'", sql);
    }

    [Fact]
    public void OsVersionTable_UsesCorrectTableName()
    {
        var query = _client.Table<OsVersion>();
        var sql = GetGeneratedSql(query.Expression);
        Assert.Equal("SELECT * FROM os_version", sql);
    }

    [Fact]
    public void Where_NotEqual_GeneratesCorrectSql()
    {
        var query = _client.Table<Process>().Where(p => p.State != "zombie");
        var sql = GetGeneratedSql(query.Expression);
        Assert.Equal("SELECT * FROM processes WHERE state != 'zombie'", sql);
    }

    [Fact]
    public void Where_LessThanOrEqual_GeneratesCorrectSql()
    {
        var query = _client.Table<Process>().Where(p => p.Nice <= 10);
        var sql = GetGeneratedSql(query.Expression);
        Assert.Equal("SELECT * FROM processes WHERE nice <= 10", sql);
    }

    [Fact]
    public void Where_VariableCapture_GeneratesCorrectSql()
    {
        var targetPid = 42L;
        var query = _client.Table<Process>().Where(p => p.Pid == targetPid);
        var sql = GetGeneratedSql(query.Expression);
        Assert.Equal("SELECT * FROM processes WHERE pid = 42", sql);
    }

    [Fact]
    public void Where_SqlInjection_IsEscaped()
    {
        var malicious = "'; DROP TABLE processes; --";
        var query = _client.Table<Process>().Where(p => p.Name == malicious);
        var sql = GetGeneratedSql(query.Expression);
        Assert.Equal("SELECT * FROM processes WHERE name = '''; DROP TABLE processes; --'", sql);
    }

    [Fact]
    public void Select_SingleColumn_GeneratesCorrectSql()
    {
        var query = _client.Table<Process>().Select(p => p.Name);
        var sql = GetGeneratedSql(query.Expression);
        Assert.Equal("SELECT name FROM processes", sql);
    }

    private static string GetGeneratedSql(System.Linq.Expressions.Expression expression)
    {
        return OsqueryExpressionVisitor.Translate(expression, out _);
    }

    public void Dispose()
    {
        _client.Dispose();
    }
}
