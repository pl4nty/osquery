// Copyright (c) 2014-present, The osquery authors
//
// This source code is licensed as defined by the LICENSE file found in the
// root directory of this source tree.
//
// SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

namespace Osquery.Tables;

/// <summary>
/// Represents the osquery 'users' table.
/// Local user accounts (including combos from various account types).
/// </summary>
[OsqueryTable("users")]
public class User
{
    [OsqueryColumn("uid")]
    public long Uid { get; set; }

    [OsqueryColumn("gid")]
    public long Gid { get; set; }

    [OsqueryColumn("uid_signed")]
    public long UidSigned { get; set; }

    [OsqueryColumn("gid_signed")]
    public long GidSigned { get; set; }

    [OsqueryColumn("username")]
    public string Username { get; set; } = "";

    [OsqueryColumn("description")]
    public string Description { get; set; } = "";

    [OsqueryColumn("directory")]
    public string Directory { get; set; } = "";

    [OsqueryColumn("shell")]
    public string Shell { get; set; } = "";

    [OsqueryColumn("uuid")]
    public string Uuid { get; set; } = "";
}
