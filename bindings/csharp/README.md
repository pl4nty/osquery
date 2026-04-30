# Osquery C# Bindings

C# bindings for [osquery](https://osquery.io/) with full LINQ support. Query your osquery tables using familiar C# LINQ syntax that gets translated into optimized osquery SQL.

## Features

- **LINQ Provider**: Write type-safe queries using LINQ that are translated into osquery SQL
- **Strongly-typed table models**: Pre-built models for common tables (processes, users, etc.)
- **Raw SQL support**: Execute raw SQL queries when needed
- **Async/await**: Full async support for non-blocking queries
- **Thrift binary protocol**: Native implementation communicating directly with osquery's extension manager socket

## Quick Start

```csharp
using Osquery;
using Osquery.Tables;

// Connect to osquery's extension socket
using var client = new OsqueryClient("/var/osquery/osquery.em");

// Use LINQ to query the processes table
var rootProcesses = client.Table<Process>()
    .Where(p => p.Uid == 0)
    .OrderByDescending(p => p.StartTime)
    .Take(10)
    .ToList();

foreach (var proc in rootProcesses)
{
    Console.WriteLine($"PID {proc.Pid}: {proc.Name} ({proc.Path})");
}

// String operations
var sshProcesses = client.Table<Process>()
    .Where(p => p.Name.Contains("ssh"))
    .ToList();

// Query users
var shellUsers = client.Table<User>()
    .Where(u => u.Shell.EndsWith("bash"))
    .ToList();

// Raw SQL queries
var result = await client.QueryAsync("SELECT * FROM os_version");
foreach (var row in result.Rows)
{
    Console.WriteLine($"{row["name"]} {row["version"]}");
}
```

## Supported LINQ Operations

| Operation | Example | Generated SQL |
|-----------|---------|---------------|
| `Where` (equality) | `.Where(p => p.Pid == 1)` | `WHERE pid = 1` |
| `Where` (comparison) | `.Where(p => p.Uid > 1000)` | `WHERE uid > 1000` |
| `Where` (AND) | `.Where(p => p.Uid == 0 && p.Name == "init")` | `WHERE (uid = 0 AND name = 'init')` |
| `Where` (OR) | `.Where(p => p.Pid == 1 \|\| p.Pid == 2)` | `WHERE (pid = 1 OR pid = 2)` |
| `Where` (Contains) | `.Where(p => p.Name.Contains("ssh"))` | `WHERE name LIKE '%ssh%'` |
| `Where` (StartsWith) | `.Where(p => p.Path.StartsWith("/usr"))` | `WHERE path LIKE '/usr%'` |
| `Where` (EndsWith) | `.Where(p => p.Path.EndsWith(".exe"))` | `WHERE path LIKE '%.exe'` |
| `Select` | `.Select(p => p.Name)` | `SELECT name` |
| `OrderBy` | `.OrderBy(p => p.Pid)` | `ORDER BY pid ASC` |
| `OrderByDescending` | `.OrderByDescending(p => p.StartTime)` | `ORDER BY start_time DESC` |
| `Take` | `.Take(10)` | `LIMIT 10` |
| `First` / `FirstOrDefault` | `.First(p => p.Pid == 1)` | `WHERE pid = 1 LIMIT 1` |

## Custom Table Models

You can define your own table models using attributes:

```csharp
[OsqueryTable("listening_ports")]
public class ListeningPort
{
    [OsqueryColumn("pid")]
    public long Pid { get; set; }

    [OsqueryColumn("port")]
    public int Port { get; set; }

    [OsqueryColumn("address")]
    public string Address { get; set; } = "";
}

// Use your custom model
var openPorts = client.Table<ListeningPort>()
    .Where(p => p.Port == 443)
    .ToList();
```

If you don't specify `[OsqueryColumn]`, property names are automatically converted to snake_case. If you don't specify `[OsqueryTable]`, the class name is converted to snake_case.

## Available Table Models

The library includes **auto-generated** models for all 287 osquery tables, generated from the `.table` spec files in the osquery source. Every table supports full LINQ querying out of the box.

To regenerate the table models after updating osquery specs:

```bash
cd bindings/csharp
python3 generate_tables.py --specs ../../specs --output Osquery.CSharp/Tables
```

You can also generate models for specific tables only:

```bash
python3 generate_tables.py --specs ../../specs --output Osquery.CSharp/Tables --tables processes users os_version
```

## Requirements

- .NET 8.0 or later
- A running osquery instance with the extensions socket enabled

## Building

```bash
cd bindings/csharp
dotnet build
dotnet test
```

## Architecture

The library communicates with osquery using the Thrift binary protocol over Unix domain sockets. The LINQ provider translates expression trees into SQL queries that are sent to osquery's `ExtensionManager.query()` endpoint.

```
C# LINQ Expression → Expression Visitor → SQL String → Thrift Protocol → osquery socket
```
