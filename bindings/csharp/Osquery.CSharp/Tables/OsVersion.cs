// Copyright (c) 2014-present, The osquery authors
//
// This source code is licensed as defined by the LICENSE file found in the
// root directory of this source tree.
//
// SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

namespace Osquery.Tables;

/// <summary>
/// Represents the osquery 'os_version' table.
/// A single row containing the operating system name and version.
/// </summary>
[OsqueryTable("os_version")]
public class OsVersion
{
    [OsqueryColumn("name")]
    public string Name { get; set; } = "";

    [OsqueryColumn("version")]
    public string Version { get; set; } = "";

    [OsqueryColumn("major")]
    public int Major { get; set; }

    [OsqueryColumn("minor")]
    public int Minor { get; set; }

    [OsqueryColumn("patch")]
    public int Patch { get; set; }

    [OsqueryColumn("build")]
    public string Build { get; set; } = "";

    [OsqueryColumn("platform")]
    public string Platform { get; set; } = "";

    [OsqueryColumn("platform_like")]
    public string PlatformLike { get; set; } = "";

    [OsqueryColumn("codename")]
    public string Codename { get; set; } = "";

    [OsqueryColumn("arch")]
    public string Arch { get; set; } = "";
}
