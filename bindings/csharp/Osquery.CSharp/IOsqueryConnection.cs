// Copyright (c) 2014-present, The osquery authors
//
// This source code is licensed as defined by the LICENSE file found in the
// root directory of this source tree.
//
// SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

namespace Osquery;

/// <summary>
/// Abstraction for the connection to osquery's extension manager.
/// </summary>
public interface IOsqueryConnection : IDisposable
{
    Task EnsureConnectedAsync();
    Task<QueryResult> QueryAsync(string sql);
}
