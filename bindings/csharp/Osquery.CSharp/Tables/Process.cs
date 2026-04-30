// Copyright (c) 2014-present, The osquery authors
//
// This source code is licensed as defined by the LICENSE file found in the
// root directory of this source tree.
//
// SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

namespace Osquery.Tables;

/// <summary>
/// Represents the osquery 'processes' table.
/// All running processes on the host system.
/// </summary>
[OsqueryTable("processes")]
public class Process
{
    [OsqueryColumn("pid")]
    public long Pid { get; set; }

    [OsqueryColumn("name")]
    public string Name { get; set; } = "";

    [OsqueryColumn("path")]
    public string Path { get; set; } = "";

    [OsqueryColumn("cmdline")]
    public string Cmdline { get; set; } = "";

    [OsqueryColumn("state")]
    public string State { get; set; } = "";

    [OsqueryColumn("cwd")]
    public string Cwd { get; set; } = "";

    [OsqueryColumn("root")]
    public string Root { get; set; } = "";

    [OsqueryColumn("uid")]
    public long Uid { get; set; }

    [OsqueryColumn("gid")]
    public long Gid { get; set; }

    [OsqueryColumn("euid")]
    public long Euid { get; set; }

    [OsqueryColumn("egid")]
    public long Egid { get; set; }

    [OsqueryColumn("suid")]
    public long Suid { get; set; }

    [OsqueryColumn("sgid")]
    public long Sgid { get; set; }

    [OsqueryColumn("on_disk")]
    public int OnDisk { get; set; }

    [OsqueryColumn("wired_size")]
    public long WiredSize { get; set; }

    [OsqueryColumn("resident_size")]
    public long ResidentSize { get; set; }

    [OsqueryColumn("total_size")]
    public long TotalSize { get; set; }

    [OsqueryColumn("user_time")]
    public long UserTime { get; set; }

    [OsqueryColumn("system_time")]
    public long SystemTime { get; set; }

    [OsqueryColumn("disk_bytes_read")]
    public long DiskBytesRead { get; set; }

    [OsqueryColumn("disk_bytes_written")]
    public long DiskBytesWritten { get; set; }

    [OsqueryColumn("start_time")]
    public long StartTime { get; set; }

    [OsqueryColumn("parent")]
    public long Parent { get; set; }

    [OsqueryColumn("pgroup")]
    public long Pgroup { get; set; }

    [OsqueryColumn("threads")]
    public int Threads { get; set; }

    [OsqueryColumn("nice")]
    public int Nice { get; set; }
}
