// Copyright (c) 2014-present, The osquery authors
//
// This source code is licensed as defined by the LICENSE file found in the
// root directory of this source tree.
//
// SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

using System.Linq.Expressions;
using System.Reflection;
using System.Text;

namespace Osquery;

/// <summary>
/// Translates LINQ expression trees into osquery SQL queries.
/// Supports Where, Select, OrderBy, OrderByDescending, Take, and Count.
/// </summary>
internal static class OsqueryExpressionVisitor
{
    public static string Translate(Expression expression, out Type elementType)
    {
        var context = new TranslationContext();
        VisitExpression(expression, context);
        elementType = context.ElementType!;
        return context.BuildSql();
    }

    private static void VisitExpression(Expression expression, TranslationContext context)
    {
        switch (expression)
        {
            case MethodCallExpression methodCall:
                VisitMethodCall(methodCall, context);
                break;
            case ConstantExpression constant when constant.Value is IQueryable queryable:
                context.ElementType ??= queryable.ElementType;
                context.TableName = GetTableName(queryable.ElementType);
                break;
            default:
                throw new NotSupportedException($"Expression type {expression.NodeType} is not supported.");
        }
    }

    private static void VisitMethodCall(MethodCallExpression methodCall, TranslationContext context)
    {
        // First, visit the source (which may be another method call or the root queryable)
        VisitExpression(methodCall.Arguments[0], context);

        switch (methodCall.Method.Name)
        {
            case "Where":
                var whereLambda = GetLambda(methodCall.Arguments[1]);
                var whereClause = TranslatePredicate(whereLambda.Body, whereLambda.Parameters[0]);
                context.WhereClauses.Add(whereClause);
                break;

            case "Select":
                var selectLambda = GetLambda(methodCall.Arguments[1]);
                context.Projection = TranslateProjection(selectLambda);
                context.ElementType = methodCall.Method.GetGenericArguments().Last();
                break;

            case "OrderBy":
            case "ThenBy":
                var orderLambda = GetLambda(methodCall.Arguments[1]);
                var orderCol = TranslateMemberAccess(orderLambda.Body, orderLambda.Parameters[0]);
                context.OrderByClauses.Add((orderCol, ascending: true));
                break;

            case "OrderByDescending":
            case "ThenByDescending":
                var orderDescLambda = GetLambda(methodCall.Arguments[1]);
                var orderDescCol = TranslateMemberAccess(orderDescLambda.Body, orderDescLambda.Parameters[0]);
                context.OrderByClauses.Add((orderDescCol, ascending: false));
                break;

            case "Take":
                var takeCount = (int)((ConstantExpression)methodCall.Arguments[1]).Value!;
                context.Limit = takeCount;
                break;

            case "Count":
                if (methodCall.Arguments.Count > 1)
                {
                    var countLambda = GetLambda(methodCall.Arguments[1]);
                    var countClause = TranslatePredicate(countLambda.Body, countLambda.Parameters[0]);
                    context.WhereClauses.Add(countClause);
                }
                context.IsCount = true;
                context.ElementType = typeof(int);
                break;

            case "First":
            case "FirstOrDefault":
                if (methodCall.Arguments.Count > 1)
                {
                    var firstLambda = GetLambda(methodCall.Arguments[1]);
                    var firstClause = TranslatePredicate(firstLambda.Body, firstLambda.Parameters[0]);
                    context.WhereClauses.Add(firstClause);
                }
                context.Limit = 1;
                break;

            default:
                throw new NotSupportedException($"LINQ method '{methodCall.Method.Name}' is not supported by the osquery LINQ provider.");
        }
    }

    private static string TranslatePredicate(Expression body, ParameterExpression param)
    {
        return body switch
        {
            BinaryExpression binary => TranslateBinary(binary, param),
            MethodCallExpression methodCall => TranslateMethodCallPredicate(methodCall, param),
            UnaryExpression { NodeType: ExpressionType.Not } unary => $"NOT ({TranslatePredicate(unary.Operand, param)})",
            _ => throw new NotSupportedException($"Predicate expression type {body.NodeType} is not supported.")
        };
    }

    private static string TranslateBinary(BinaryExpression binary, ParameterExpression param)
    {
        if (binary.NodeType == ExpressionType.AndAlso)
        {
            var left = TranslatePredicate(binary.Left, param);
            var right = TranslatePredicate(binary.Right, param);
            return $"({left} AND {right})";
        }

        if (binary.NodeType == ExpressionType.OrElse)
        {
            var left = TranslatePredicate(binary.Left, param);
            var right = TranslatePredicate(binary.Right, param);
            return $"({left} OR {right})";
        }

        var column = TranslateMemberAccess(binary.Left, param);
        var value = EvaluateExpression(binary.Right);
        var op = binary.NodeType switch
        {
            ExpressionType.Equal => "=",
            ExpressionType.NotEqual => "!=",
            ExpressionType.GreaterThan => ">",
            ExpressionType.GreaterThanOrEqual => ">=",
            ExpressionType.LessThan => "<",
            ExpressionType.LessThanOrEqual => "<=",
            _ => throw new NotSupportedException($"Operator {binary.NodeType} is not supported.")
        };

        return $"{column} {op} {FormatValue(value)}";
    }

    private static string TranslateMethodCallPredicate(MethodCallExpression methodCall, ParameterExpression param)
    {
        if (methodCall.Method.Name == "Contains" && methodCall.Object != null)
        {
            var column = TranslateMemberAccess(methodCall.Object, param);
            var value = EvaluateExpression(methodCall.Arguments[0]);
            return $"{column} LIKE '%{EscapeSqlString(value?.ToString() ?? "")}%'";
        }

        if (methodCall.Method.Name == "StartsWith" && methodCall.Object != null)
        {
            var column = TranslateMemberAccess(methodCall.Object, param);
            var value = EvaluateExpression(methodCall.Arguments[0]);
            return $"{column} LIKE '{EscapeSqlString(value?.ToString() ?? "")}%'";
        }

        if (methodCall.Method.Name == "EndsWith" && methodCall.Object != null)
        {
            var column = TranslateMemberAccess(methodCall.Object, param);
            var value = EvaluateExpression(methodCall.Arguments[0]);
            return $"{column} LIKE '%{EscapeSqlString(value?.ToString() ?? "")}'";
        }

        throw new NotSupportedException($"Method '{methodCall.Method.Name}' is not supported in predicates.");
    }

    private static string TranslateMemberAccess(Expression expression, ParameterExpression param)
    {
        if (expression is MemberExpression member && member.Expression == param)
        {
            return GetColumnName(member.Member);
        }

        // Handle conversion expressions (e.g., implicit casts)
        if (expression is UnaryExpression unary && unary.NodeType == ExpressionType.Convert)
        {
            return TranslateMemberAccess(unary.Operand, param);
        }

        throw new NotSupportedException($"Expression '{expression}' is not a supported column reference.");
    }

    private static string? TranslateProjection(LambdaExpression lambda)
    {
        var param = lambda.Parameters[0];
        var body = lambda.Body;

        switch (body)
        {
            case MemberExpression member:
                return GetColumnName(member.Member);

            case NewExpression newExpr when newExpr.Arguments.Count > 0:
                var columns = new List<string>();
                for (int i = 0; i < newExpr.Arguments.Count; i++)
                {
                    if (newExpr.Arguments[i] is MemberExpression argMember && argMember.Expression == param)
                    {
                        var col = GetColumnName(argMember.Member);
                        var alias = newExpr.Members?[i]?.Name;
                        if (alias != null && alias != col)
                            columns.Add($"{col} AS {alias}");
                        else
                            columns.Add(col);
                    }
                }
                return string.Join(", ", columns);

            case MemberInitExpression memberInit:
                var initColumns = new List<string>();
                foreach (var binding in memberInit.Bindings)
                {
                    if (binding is MemberAssignment assignment &&
                        assignment.Expression is MemberExpression assignMember &&
                        assignMember.Expression == param)
                    {
                        var col = GetColumnName(assignMember.Member);
                        initColumns.Add(col);
                    }
                }
                return string.Join(", ", initColumns);

            default:
                return null; // fallback to SELECT *
        }
    }

    private static object? EvaluateExpression(Expression expression)
    {
        // Compile and evaluate constant or captured variable expressions
        var lambda = Expression.Lambda(expression);
        var compiled = lambda.Compile();
        return compiled.DynamicInvoke();
    }

    private static string FormatValue(object? value)
    {
        if (value == null) return "NULL";
        if (value is string s) return $"'{EscapeSqlString(s)}'";
        if (value is bool b) return b ? "1" : "0";
        return value.ToString()!;
    }

    private static string EscapeSqlString(string value)
    {
        return value.Replace("'", "''");
    }

    private static LambdaExpression GetLambda(Expression expression)
    {
        if (expression is UnaryExpression unary)
            return (LambdaExpression)unary.Operand;
        return (LambdaExpression)expression;
    }

    private static string GetTableName(Type type)
    {
        var attr = type.GetCustomAttribute<OsqueryTableAttribute>();
        if (attr != null) return attr.Name;
        return ToSnakeCase(type.Name);
    }

    private static string GetColumnName(MemberInfo member)
    {
        var attr = member.GetCustomAttribute<OsqueryColumnAttribute>();
        if (attr?.Name != null) return attr.Name;
        return ToSnakeCase(member.Name);
    }

    internal static string ToSnakeCase(string name)
    {
        var sb = new StringBuilder();
        for (int i = 0; i < name.Length; i++)
        {
            var c = name[i];
            if (char.IsUpper(c))
            {
                if (i > 0) sb.Append('_');
                sb.Append(char.ToLowerInvariant(c));
            }
            else
            {
                sb.Append(c);
            }
        }
        return sb.ToString();
    }

    private class TranslationContext
    {
        public string? TableName;
        public Type? ElementType;
        public List<string> WhereClauses = new();
        public List<(string column, bool ascending)> OrderByClauses = new();
        public string? Projection;
        public int? Limit;
        public bool IsCount;

        public string BuildSql()
        {
            var sb = new StringBuilder();
            sb.Append("SELECT ");

            if (IsCount)
                sb.Append("COUNT(*)");
            else if (Projection != null)
                sb.Append(Projection);
            else
                sb.Append('*');

            sb.Append(" FROM ");
            sb.Append(TableName);

            if (WhereClauses.Count > 0)
            {
                sb.Append(" WHERE ");
                sb.Append(string.Join(" AND ", WhereClauses));
            }

            if (OrderByClauses.Count > 0)
            {
                sb.Append(" ORDER BY ");
                sb.Append(string.Join(", ", OrderByClauses.Select(o => $"{o.column} {(o.ascending ? "ASC" : "DESC")}")));
            }

            if (Limit.HasValue)
            {
                sb.Append(" LIMIT ");
                sb.Append(Limit.Value);
            }

            return sb.ToString();
        }
    }
}
