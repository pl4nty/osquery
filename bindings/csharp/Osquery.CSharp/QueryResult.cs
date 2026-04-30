// Copyright (c) 2014-present, The osquery authors
//
// This source code is licensed as defined by the LICENSE file found in the
// root directory of this source tree.
//
// SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

namespace Osquery;

/// <summary>
/// Represents the result of an osquery SQL query.
/// </summary>
public class QueryResult
{
    /// <summary>
    /// The status of the query execution.
    /// </summary>
    public ExtensionStatus Status { get; }

    /// <summary>
    /// The rows returned by the query, each as a dictionary of column name to string value.
    /// </summary>
    public IReadOnlyList<Dictionary<string, string>> Rows { get; }

    public QueryResult(ExtensionStatus status, List<Dictionary<string, string>> rows)
    {
        Status = status;
        Rows = rows;
    }
}

/// <summary>
/// Represents the status returned by osquery for a request.
/// </summary>
public class ExtensionStatus
{
    public int Code { get; }
    public string Message { get; }

    public ExtensionStatus(int code = 0, string message = "")
    {
        Code = code;
        Message = message;
    }

    public bool IsSuccess => Code == 0;
}
