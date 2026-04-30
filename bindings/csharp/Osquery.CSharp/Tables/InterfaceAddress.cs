// Copyright (c) 2014-present, The osquery authors
//
// This source code is licensed as defined by the LICENSE file found in the
// root directory of this source tree.
//
// SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

namespace Osquery.Tables;

/// <summary>
/// Represents the osquery 'interface_addresses' table.
/// Network interfaces and relevant metadata.
/// </summary>
[OsqueryTable("interface_addresses")]
public class InterfaceAddress
{
    [OsqueryColumn("interface")]
    public string Interface { get; set; } = "";

    [OsqueryColumn("address")]
    public string Address { get; set; } = "";

    [OsqueryColumn("mask")]
    public string Mask { get; set; } = "";

    [OsqueryColumn("broadcast")]
    public string Broadcast { get; set; } = "";

    [OsqueryColumn("point_to_point")]
    public string PointToPoint { get; set; } = "";

    [OsqueryColumn("type")]
    public string Type { get; set; } = "";

    [OsqueryColumn("friendly_name")]
    public string FriendlyName { get; set; } = "";
}
