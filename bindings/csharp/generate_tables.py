#!/usr/bin/env python3

# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

"""
Code generator that reads osquery .table spec files and produces C# model
classes with [OsqueryTable] and [OsqueryColumn] attributes for LINQ support.

Usage:
    python generate_tables.py --specs ../../specs --output Osquery.CSharp/Tables
"""

import argparse
import os
import sys
import re
import keyword

# ---------------------------------------------------------------------------
# Minimal reimplementation of the table-spec DSL so we can exec() spec files
# ---------------------------------------------------------------------------

class DataType:
    def __init__(self, affinity, csharp_type):
        self.affinity = affinity
        self.csharp_type = csharp_type

    def __repr__(self):
        return self.affinity


# Map osquery types to C# types
TEXT = DataType("TEXT_TYPE", "string")
DATE = DataType("TEXT_TYPE", "string")
DATETIME = DataType("TEXT_TYPE", "string")
INTEGER = DataType("INTEGER_TYPE", "int")
BIGINT = DataType("BIGINT_TYPE", "long")
UNSIGNED_BIGINT = DataType("UNSIGNED_BIGINT_TYPE", "long")
DOUBLE = DataType("DOUBLE_TYPE", "double")
BLOB = DataType("BLOB_TYPE", "string")

# Platform constants (we include all columns regardless of platform)
WINDOWS = ["windows", "win32", "cygwin"]
LINUX = ["linux"]
POSIX = ["linux", "darwin"]
DARWIN = ["darwin"]

# Table attribute constants
UNKNOWN = "UNKNOWN"
UTILITY = "UTILITY"
SYSTEM = "SYSTEM"
NETWORK = "NETWORK"
EVENTS = "EVENTS"
APPLICATION = "APPLICATION"


class Column:
    def __init__(self, name, col_type, description="", aliases=[], platforms=[], notes="", **kwargs):
        self.name = name
        self.type = col_type
        self.description = description
        self.aliases = aliases
        self.platforms = platforms
        self.notes = notes
        self.options = kwargs


class ForeignKey:
    def __init__(self, **kwargs):
        self.column = kwargs.get("column", "")
        self.table = kwargs.get("table", "")


class TableSpec:
    """Accumulates table spec data from exec'd .table files."""

    def __init__(self):
        self.table_name = ""
        self.description = ""
        self.columns = []
        self.attributes = {}
        self.examples = []
        self.aliases = []


def parse_table_spec(spec_path):
    """Parse a .table spec file and return a TableSpec."""
    spec = TableSpec()

    def table_name(name, aliases=[]):
        spec.table_name = name
        spec.aliases = aliases

    def description(desc):
        spec.description = desc

    def schema(schema_list):
        for item in schema_list:
            if isinstance(item, Column):
                spec.columns.append(item)

    def extended_schema(platforms, schema_list):
        for item in schema_list:
            if isinstance(item, Column):
                item.platforms = platforms
                spec.columns.append(item)

    def attributes(**kwargs):
        spec.attributes = kwargs

    def implementation(impl, **kwargs):
        pass

    def examples(ex):
        spec.examples = ex

    def fuzz_paths(paths):
        pass

    def notes(n):
        pass

    # Build the execution namespace
    exec_globals = {
        "Column": Column,
        "ForeignKey": ForeignKey,
        "TEXT": TEXT,
        "DATE": DATE,
        "DATETIME": DATETIME,
        "INTEGER": INTEGER,
        "BIGINT": BIGINT,
        "UNSIGNED_BIGINT": UNSIGNED_BIGINT,
        "DOUBLE": DOUBLE,
        "BLOB": BLOB,
        "WINDOWS": WINDOWS,
        "LINUX": LINUX,
        "POSIX": POSIX,
        "DARWIN": DARWIN,
        "UNKNOWN": UNKNOWN,
        "UTILITY": UTILITY,
        "SYSTEM": SYSTEM,
        "NETWORK": NETWORK,
        "EVENTS": EVENTS,
        "APPLICATION": APPLICATION,
        "table_name": table_name,
        "description": description,
        "schema": schema,
        "extended_schema": extended_schema,
        "attributes": attributes,
        "implementation": implementation,
        "examples": examples,
        "fuzz_paths": fuzz_paths,
        "notes": notes,
    }

    with open(spec_path, "r") as f:
        content = f.read()

    try:
        exec(content, exec_globals)
    except Exception as e:
        print(f"Warning: Failed to parse {spec_path}: {e}", file=sys.stderr)
        return None

    if not spec.table_name or not spec.columns:
        return None

    return spec


# ---------------------------------------------------------------------------
# C# code generation
# ---------------------------------------------------------------------------

# C# reserved keywords that need @ prefix
CSHARP_KEYWORDS = {
    "abstract", "as", "base", "bool", "break", "byte", "case", "catch",
    "char", "checked", "class", "const", "continue", "decimal", "default",
    "delegate", "do", "double", "else", "enum", "event", "explicit",
    "extern", "false", "finally", "fixed", "float", "for", "foreach",
    "goto", "if", "implicit", "in", "int", "interface", "internal", "is",
    "lock", "long", "namespace", "new", "null", "object", "operator",
    "out", "override", "params", "private", "protected", "public",
    "readonly", "ref", "return", "sbyte", "sealed", "short", "sizeof",
    "stackalloc", "static", "string", "struct", "switch", "this", "throw",
    "true", "try", "typeof", "uint", "ulong", "unchecked", "unsafe",
    "ushort", "using", "virtual", "void", "volatile", "while",
}


def to_pascal_case(snake_case_name):
    """Convert snake_case to PascalCase."""
    components = snake_case_name.split("_")
    return "".join(x.title() for x in components)


def sanitize_property_name(name, class_name):
    """Make a valid C# property name from an osquery column name."""
    pascal = to_pascal_case(name)
    if pascal.lower() in CSHARP_KEYWORDS or pascal in CSHARP_KEYWORDS:
        return "@" + pascal
    # Property name cannot be the same as the enclosing class name
    if pascal == class_name:
        return pascal + "Value"
    return pascal


def get_class_name(table_name):
    """Convert a table name to a C# class name (singular PascalCase)."""
    pascal = to_pascal_case(table_name)
    # Simple singularization for common patterns
    if pascal.endswith("sses"):
        # e.g. "Addresses" -> "Address" (but keep "Classes" -> "Class" etc.)
        pascal = pascal[:-2]
    elif pascal.endswith("ses"):
        # e.g. "Processes" -> "Process"
        pascal = pascal[:-2]
    elif pascal.endswith("ies"):
        # e.g. "Batteries" -> "Battery"
        pascal = pascal[:-3] + "y"
    elif pascal.endswith("s") and not pascal.endswith("ss") and not pascal.endswith("us") and not pascal.endswith("is"):
        # e.g. "Users" -> "User", "Ports" -> "Port"
        pascal = pascal[:-1]
    return pascal


def get_csharp_type(col_type):
    """Get the C# type for a column type."""
    return col_type.csharp_type


def get_default_value(csharp_type):
    """Get default value initializer for a type."""
    if csharp_type == "string":
        return ' = "";'
    return ""


def generate_class(spec):
    """Generate a C# class string from a TableSpec."""
    class_name = get_class_name(spec.table_name)
    lines = []

    lines.append("// <auto-generated>")
    lines.append("// This file was generated by generate_tables.py from the osquery table specs.")
    lines.append("// Do not edit manually. Re-run the generator to update.")
    lines.append("// </auto-generated>")
    lines.append("")
    lines.append("// Copyright (c) 2014-present, The osquery authors")
    lines.append("//")
    lines.append("// This source code is licensed as defined by the LICENSE file found in the")
    lines.append("// root directory of this source tree.")
    lines.append("//")
    lines.append("// SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)")
    lines.append("")
    lines.append("namespace Osquery.Tables;")
    lines.append("")

    # XML doc
    desc = spec.description or f"Represents the osquery '{spec.table_name}' table."
    lines.append("/// <summary>")
    lines.append(f"/// {desc}")
    lines.append("/// </summary>")
    lines.append(f'[OsqueryTable("{spec.table_name}")]')
    lines.append(f"public class {class_name}")
    lines.append("{")

    # Track property names to avoid duplicates
    seen_names = set()

    for col in spec.columns:
        prop_name = sanitize_property_name(col.name, class_name)
        if prop_name in seen_names:
            continue
        seen_names.add(prop_name)

        csharp_type = get_csharp_type(col.type)
        default = get_default_value(csharp_type)

        # Add description as XML comment if available
        if col.description:
            lines.append(f"    /// <summary>{col.description}</summary>")

        lines.append(f'    [OsqueryColumn("{col.name}")]')
        lines.append(f"    public {csharp_type} {prop_name} {{ get; set; }}{default}")
        lines.append("")

    # Remove trailing empty line inside class
    if lines and lines[-1] == "":
        lines.pop()

    lines.append("}")
    lines.append("")

    return "\n".join(lines)


def find_table_specs(specs_dir):
    """Recursively find all .table files."""
    table_files = []
    for root, dirs, files in os.walk(specs_dir):
        for f in files:
            if f.endswith(".table"):
                table_files.append(os.path.join(root, f))
    return sorted(table_files)


def main():
    parser = argparse.ArgumentParser(
        description="Generate C# table model classes from osquery .table specs"
    )
    parser.add_argument(
        "--specs",
        required=True,
        help="Path to the osquery specs directory",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Output directory for generated C# files",
    )
    parser.add_argument(
        "--tables",
        nargs="*",
        help="Optional list of table names to generate (default: all)",
    )
    args = parser.parse_args()

    specs_dir = os.path.abspath(args.specs)
    output_dir = os.path.abspath(args.output)

    if not os.path.isdir(specs_dir):
        print(f"Error: specs directory not found: {specs_dir}", file=sys.stderr)
        sys.exit(1)

    os.makedirs(output_dir, exist_ok=True)

    table_files = find_table_specs(specs_dir)
    print(f"Found {len(table_files)} table spec files")

    generated = 0
    errors = 0

    for spec_path in table_files:
        spec = parse_table_spec(spec_path)
        if spec is None:
            errors += 1
            continue

        if args.tables and spec.table_name not in args.tables:
            continue

        class_name = get_class_name(spec.table_name)
        output_path = os.path.join(output_dir, f"{class_name}.cs")

        content = generate_class(spec)
        with open(output_path, "w") as f:
            f.write(content)

        generated += 1

    print(f"Generated {generated} C# table model classes in {output_dir}")
    if errors:
        print(f"  ({errors} specs skipped due to parse errors)")


if __name__ == "__main__":
    main()
