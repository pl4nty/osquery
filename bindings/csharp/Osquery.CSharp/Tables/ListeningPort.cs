// Copyright (c) 2014-present, The osquery authors
//
// This source code is licensed as defined by the LICENSE file found in the
// root directory of this source tree.
//
// SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

namespace Osquery.Tables;

/// <summary>
/// Represents the osquery 'listening_ports' table.
/// Processes with listening (bound) network sockets/ports.
/// </summary>
[OsqueryTable("listening_ports")]
public class ListeningPort
{
    [OsqueryColumn("pid")]
    public long Pid { get; set; }

    [OsqueryColumn("port")]
    public int Port { get; set; }

    [OsqueryColumn("protocol")]
    public int Protocol { get; set; }

    [OsqueryColumn("family")]
    public int Family { get; set; }

    [OsqueryColumn("address")]
    public string Address { get; set; } = "";

    [OsqueryColumn("fd")]
    public long Fd { get; set; }

    [OsqueryColumn("socket")]
    public long Socket { get; set; }

    [OsqueryColumn("path")]
    public string Path { get; set; } = "";

    [OsqueryColumn("net_namespace")]
    public string NetNamespace { get; set; } = "";
}
