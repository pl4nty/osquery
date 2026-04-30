// Copyright (c) 2014-present, The osquery authors
//
// This source code is licensed as defined by the LICENSE file found in the
// root directory of this source tree.
//
// SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

using System.Text.Json;
using System.Text.Json.Serialization;
using Scriban;
using Scriban.Runtime;

// ─── CLI argument parsing ────────────────────────────────────────────────────

if (args.Length < 2)
{
    Console.Error.WriteLine("Usage: Osquery.CodeGen <schema.json> <output-dir> [table1 table2 ...]");
    Console.Error.WriteLine();
    Console.Error.WriteLine("  schema.json  - The osquery JSON schema (produced by genwebsitejson.py)");
    Console.Error.WriteLine("  output-dir   - Directory to write generated .cs files into");
    Console.Error.WriteLine("  [tables]     - Optional list of table names to generate (default: all)");
    return 1;
}

var schemaPath = args[0];
var outputDir = args[1];
var tableFilter = args.Length > 2 ? args[2..].ToHashSet() : null;

if (!File.Exists(schemaPath))
{
    Console.Error.WriteLine($"Error: schema file not found: {schemaPath}");
    return 1;
}

Directory.CreateDirectory(outputDir);

// ─── Load schema ─────────────────────────────────────────────────────────────

var json = await File.ReadAllTextAsync(schemaPath);
var tables = JsonSerializer.Deserialize<List<TableEntry>>(json)!;

// ─── Load template ───────────────────────────────────────────────────────────

var templatePath = Path.Combine(AppContext.BaseDirectory, "Templates", "TableModel.sbn");
if (!File.Exists(templatePath))
{
    // Fallback for running from source
    templatePath = Path.Combine(Path.GetDirectoryName(Environment.ProcessPath!)!, "Templates", "TableModel.sbn");
}
if (!File.Exists(templatePath))
{
    templatePath = Path.Combine(Directory.GetCurrentDirectory(), "Templates", "TableModel.sbn");
}
if (!File.Exists(templatePath))
{
    Console.Error.WriteLine("Error: Could not locate Templates/TableModel.sbn");
    return 1;
}

var templateText = await File.ReadAllTextAsync(templatePath);
var template = Template.Parse(templateText, templatePath);
if (template.HasErrors)
{
    Console.Error.WriteLine("Template parse errors:");
    foreach (var msg in template.Messages)
        Console.Error.WriteLine($"  {msg}");
    return 1;
}

// ─── Generate ────────────────────────────────────────────────────────────────

var generated = 0;
foreach (var table in tables)
{
    if (tableFilter != null && !tableFilter.Contains(table.Name))
        continue;

    var className = TableNameToClassName(table.Name);
    var columns = new List<ScriptObject>();

    var seenProps = new HashSet<string>();
    foreach (var col in table.Columns)
    {
        var propName = ColumnToPropertyName(col.Name, className);
        if (!seenProps.Add(propName))
            continue;

        var csharpType = MapType(col.Type);
        var so = new ScriptObject();
        so["name"] = col.Name;
        so["description"] = col.Description ?? "";
        so["property_name"] = propName;
        so["csharp_type"] = csharpType;
        so["default_value"] = csharpType == "string" ? " = \"\";" : "";
        columns.Add(so);
    }

    var model = new ScriptObject();
    model["table_name"] = table.Name;
    model["class_name"] = className;
    model["description"] = table.Description ?? $"Represents the osquery '{table.Name}' table.";
    model["columns"] = columns;

    var context = new TemplateContext();
    context.PushGlobal(model);
    var result = await template.RenderAsync(context);

    var outputPath = Path.Combine(outputDir, $"{className}.cs");
    await File.WriteAllTextAsync(outputPath, result);
    generated++;
}

Console.WriteLine($"Generated {generated} C# table model classes in {outputDir}");
return 0;

// ─── Helpers ─────────────────────────────────────────────────────────────────

static string MapType(string osqueryType) => osqueryType switch
{
    "text" => "string",
    "integer" => "int",
    "bigint" => "long",
    "unsigned_bigint" => "long",
    "double" => "double",
    "blob" => "string",
    _ => "string"
};

static string ToPascalCase(string snakeCase)
{
    var parts = snakeCase.Split('_', StringSplitOptions.RemoveEmptyEntries);
    return string.Concat(parts.Select(p =>
        char.ToUpperInvariant(p[0]) + p[1..]));
}

static string TableNameToClassName(string tableName)
{
    var pascal = ToPascalCase(tableName);
    // Simple singularization
    if (pascal.EndsWith("sses"))
        pascal = pascal[..^2]; // e.g. Addresses -> Address
    else if (pascal.EndsWith("ses"))
        pascal = pascal[..^2]; // e.g. Processes -> Process
    else if (pascal.EndsWith("ies"))
        pascal = pascal[..^3] + "y"; // e.g. Batteries -> Battery
    else if (pascal.EndsWith("s") && !pascal.EndsWith("ss") && !pascal.EndsWith("us") && !pascal.EndsWith("is"))
        pascal = pascal[..^1]; // e.g. Users -> User
    return pascal;
}

static string ColumnToPropertyName(string columnName, string className)
{
    HashSet<string> csharpKeywords = new(StringComparer.OrdinalIgnoreCase)
    {
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
    };

    var pascal = ToPascalCase(columnName);
    if (csharpKeywords.Contains(pascal))
        return "@" + pascal;
    if (pascal == className)
        return pascal + "Value";
    return pascal;
}

// ─── JSON model ──────────────────────────────────────────────────────────────

record TableEntry(
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("description")] string? Description,
    [property: JsonPropertyName("columns")] List<ColumnEntry> Columns
);

record ColumnEntry(
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("description")] string? Description,
    [property: JsonPropertyName("type")] string Type
);
