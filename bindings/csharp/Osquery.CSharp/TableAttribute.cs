// Copyright (c) 2014-present, The osquery authors
//
// This source code is licensed as defined by the LICENSE file found in the
// root directory of this source tree.
//
// SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

namespace Osquery;

/// <summary>
/// Maps a C# class to an osquery virtual table.
/// </summary>
[AttributeUsage(AttributeTargets.Class)]
public class OsqueryTableAttribute : Attribute
{
    /// <summary>
    /// The name of the osquery table.
    /// </summary>
    public string Name { get; }

    public OsqueryTableAttribute(string name)
    {
        Name = name;
    }
}

/// <summary>
/// Maps a C# property to an osquery table column.
/// </summary>
[AttributeUsage(AttributeTargets.Property)]
public class OsqueryColumnAttribute : Attribute
{
    /// <summary>
    /// The name of the column in the osquery table.
    /// If not specified, the property name is converted to snake_case.
    /// </summary>
    public string? Name { get; }

    public OsqueryColumnAttribute() { }

    public OsqueryColumnAttribute(string name)
    {
        Name = name;
    }
}
