// Copyright (c) 2014-present, The osquery authors
//
// This source code is licensed as defined by the LICENSE file found in the
// root directory of this source tree.
//
// SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

using System.Linq.Expressions;
using System.Reflection;

namespace Osquery;

/// <summary>
/// IQueryProvider implementation that translates LINQ expressions into osquery SQL
/// and executes them via the OsqueryClient.
/// </summary>
public class OsqueryQueryProvider : IQueryProvider
{
    private readonly OsqueryClient _client;

    internal OsqueryQueryProvider(OsqueryClient client)
    {
        _client = client;
    }

    public IQueryable CreateQuery(Expression expression)
    {
        var elementType = GetElementType(expression);
        var queryableType = typeof(OsqueryQueryable<>).MakeGenericType(elementType);
        return (IQueryable)Activator.CreateInstance(queryableType, this, expression)!;
    }

    public IQueryable<TElement> CreateQuery<TElement>(Expression expression)
    {
        return new OsqueryQueryable<TElement>(this, expression);
    }

    public object? Execute(Expression expression)
    {
        var sql = OsqueryExpressionVisitor.Translate(expression, out var elementType);
        var rows = _client.ExecuteQueryAsync(sql).GetAwaiter().GetResult();

        if (elementType == typeof(int))
        {
            // COUNT query
            var firstRow = rows.FirstOrDefault();
            if (firstRow != null && firstRow.TryGetValue("COUNT(*)", out var countStr))
                return int.Parse(countStr);
            return 0;
        }

        var method = typeof(OsqueryQueryProvider)
            .GetMethod(nameof(MapRowsTyped), BindingFlags.NonPublic | BindingFlags.Static)!
            .MakeGenericMethod(elementType);
        var results = (System.Collections.IEnumerable)method.Invoke(null, new object[] { rows })!;
        return results.Cast<object>().FirstOrDefault();
    }

    public TResult Execute<TResult>(Expression expression)
    {
        var sql = OsqueryExpressionVisitor.Translate(expression, out var elementType);
        var rows = _client.ExecuteQueryAsync(sql).GetAwaiter().GetResult();

        // Check if we're returning an enumerable
        if (typeof(TResult).IsGenericType &&
            typeof(TResult).GetGenericTypeDefinition() == typeof(IEnumerable<>))
        {
            var innerType = typeof(TResult).GetGenericArguments()[0];
            var method = typeof(OsqueryQueryProvider)
                .GetMethod(nameof(MapRowsTyped), BindingFlags.NonPublic | BindingFlags.Static)!
                .MakeGenericMethod(innerType);
            return (TResult)method.Invoke(null, new object[] { rows })!;
        }

        if (typeof(TResult) == typeof(int))
        {
            var firstRow = rows.FirstOrDefault();
            if (firstRow != null && firstRow.TryGetValue("COUNT(*)", out var countStr))
                return (TResult)(object)int.Parse(countStr);
            return (TResult)(object)0;
        }

        // Single result
        var singleMethod = typeof(OsqueryQueryProvider)
            .GetMethod(nameof(MapRowsTyped), BindingFlags.NonPublic | BindingFlags.Static)!
            .MakeGenericMethod(elementType);
        var enumerable = (IEnumerable<object>)singleMethod.Invoke(null, new object[] { rows })!;
        var first = enumerable.FirstOrDefault();
        return (TResult)first!;
    }

    private static IEnumerable<T> MapRowsTyped<T>(IEnumerable<Dictionary<string, string>> rows) where T : new()
    {
        return MapRows<T>(rows);
    }

    private static IEnumerable<T> MapRows<T>(IEnumerable<Dictionary<string, string>> rows) where T : new()
    {
        var targetType = typeof(T);
        var properties = targetType.GetProperties(BindingFlags.Public | BindingFlags.Instance);
        var columnMap = new Dictionary<string, PropertyInfo>(StringComparer.OrdinalIgnoreCase);

        foreach (var prop in properties)
        {
            var colAttr = prop.GetCustomAttribute<OsqueryColumnAttribute>();
            var colName = colAttr?.Name ?? OsqueryExpressionVisitor.ToSnakeCase(prop.Name);
            columnMap[colName] = prop;
        }

        foreach (var row in rows)
        {
            var instance = new T();
            foreach (var (key, value) in row)
            {
                if (columnMap.TryGetValue(key, out var prop))
                {
                    var converted = ConvertValue(value, prop.PropertyType);
                    prop.SetValue(instance, converted);
                }
            }
            yield return instance;
        }
    }

    private static object? ConvertValue(string value, Type targetType)
    {
        if (string.IsNullOrEmpty(value))
        {
            if (targetType.IsValueType)
            {
                var underlying = Nullable.GetUnderlyingType(targetType);
                if (underlying != null) return null;
                return Activator.CreateInstance(targetType);
            }
            return null;
        }

        var type = Nullable.GetUnderlyingType(targetType) ?? targetType;

        if (type == typeof(string)) return value;
        if (type == typeof(int)) return int.TryParse(value, out var i) ? i : 0;
        if (type == typeof(long)) return long.TryParse(value, out var l) ? l : 0L;
        if (type == typeof(double)) return double.TryParse(value, out var d) ? d : 0.0;
        if (type == typeof(bool)) return value == "1" || value.Equals("true", StringComparison.OrdinalIgnoreCase);
        if (type == typeof(ulong)) return ulong.TryParse(value, out var ul) ? ul : 0UL;

        return Convert.ChangeType(value, type);
    }

    private static Type GetElementType(Expression expression)
    {
        if (expression.Type.IsGenericType)
        {
            var genericDef = expression.Type.GetGenericTypeDefinition();
            if (genericDef == typeof(IQueryable<>) || genericDef == typeof(IOrderedQueryable<>))
                return expression.Type.GetGenericArguments()[0];
        }
        return expression.Type;
    }
}
