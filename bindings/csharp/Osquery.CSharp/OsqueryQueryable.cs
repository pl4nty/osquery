// Copyright (c) 2014-present, The osquery authors
//
// This source code is licensed as defined by the LICENSE file found in the
// root directory of this source tree.
//
// SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

using System.Collections;
using System.Linq.Expressions;

namespace Osquery;

/// <summary>
/// IQueryable implementation that represents an osquery table and supports LINQ operations.
/// </summary>
public class OsqueryQueryable<T> : IQueryable<T>, IOrderedQueryable<T>
{
    public Type ElementType => typeof(T);
    public Expression Expression { get; }
    public IQueryProvider Provider { get; }

    internal OsqueryQueryable(OsqueryQueryProvider provider)
    {
        Provider = provider;
        Expression = Expression.Constant(this);
    }

    internal OsqueryQueryable(OsqueryQueryProvider provider, Expression expression)
    {
        Provider = provider;
        Expression = expression;
    }

    public IEnumerator<T> GetEnumerator()
    {
        return Provider.Execute<IEnumerable<T>>(Expression).GetEnumerator();
    }

    IEnumerator IEnumerable.GetEnumerator()
    {
        return GetEnumerator();
    }
}
