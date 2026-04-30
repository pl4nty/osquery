// Copyright (c) 2014-present, The osquery authors
//
// This source code is licensed as defined by the LICENSE file found in the
// root directory of this source tree.
//
// SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

using System.Buffers.Binary;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;

namespace Osquery;

/// <summary>
/// Connects to osquery's extension manager via a Unix domain socket
/// using the Thrift binary protocol.
/// </summary>
public class OsquerySocketConnection : IOsqueryConnection
{
    private readonly string _socketPath;
    private Socket? _socket;
    private NetworkStream? _stream;
    private bool _disposed;

    // Thrift binary protocol constants
    private const uint VersionMask = 0xffff0000;
    private const uint Version1 = 0x80010000;
    private const byte TCall = 1;
    private const byte TReply = 2;

    // Thrift type IDs
    private const byte TTypeStop = 0;
    private const byte TTypeBool = 2;
    private const byte TTypeI32 = 8;
    private const byte TTypeI64 = 10;
    private const byte TTypeString = 11;
    private const byte TTypeStruct = 12;
    private const byte TTypeMap = 13;
    private const byte TTypeList = 15;

    public OsquerySocketConnection(string socketPath)
    {
        _socketPath = socketPath ?? throw new ArgumentNullException(nameof(socketPath));
    }

    public async Task EnsureConnectedAsync()
    {
        if (_socket is { Connected: true })
            return;

        _socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        var endpoint = new UnixDomainSocketEndPoint(_socketPath);
        await _socket.ConnectAsync(endpoint);
        _stream = new NetworkStream(_socket, ownsSocket: false);
    }

    public async Task<QueryResult> QueryAsync(string sql)
    {
        if (_stream == null)
            throw new InvalidOperationException("Not connected. Call EnsureConnectedAsync first.");

        // Build the Thrift binary protocol message for ExtensionManager.query(sql)
        var requestBytes = BuildQueryRequest(sql);
        await _stream.WriteAsync(requestBytes);
        await _stream.FlushAsync();

        // Read the response
        return await ReadQueryResponse();
    }

    private byte[] BuildQueryRequest(string sql)
    {
        using var ms = new MemoryStream();
        using var writer = new BinaryWriter(ms);

        // Message header: version | type, sequence, method name
        WriteI32(writer, unchecked((int)(Version1 | TCall)));
        var methodName = "query"u8;
        WriteI32(writer, methodName.Length);
        writer.Write(methodName);
        WriteI32(writer, 0); // sequence ID

        // Struct: query args - field 1 is string (sql)
        writer.Write(TTypeString); // field type
        WriteI16(writer, 1); // field id
        var sqlBytes = Encoding.UTF8.GetBytes(sql);
        WriteI32(writer, sqlBytes.Length);
        writer.Write(sqlBytes);

        writer.Write(TTypeStop); // end of struct
        writer.Flush();
        return ms.ToArray();
    }

    private async Task<QueryResult> ReadQueryResponse()
    {
        // Read message header
        var headerInt = await ReadI32Async();
        var version = (uint)headerInt & VersionMask;
        if (version != Version1)
            throw new OsqueryException($"Unexpected Thrift protocol version: 0x{version:X8}");

        var methodNameLen = await ReadI32Async();
        var methodNameBuf = new byte[methodNameLen];
        await ReadExactAsync(methodNameBuf);
        // sequence id
        await ReadI32Async();

        // Read ExtensionResponse struct
        return await ReadExtensionResponse();
    }

    private async Task<QueryResult> ReadExtensionResponse()
    {
        var status = new ExtensionStatus();
        var rows = new List<Dictionary<string, string>>();

        while (true)
        {
            var fieldType = await ReadByteAsync();
            if (fieldType == TTypeStop)
                break;

            var fieldId = await ReadI16Async();

            if (fieldId == 1 && fieldType == TTypeStruct)
            {
                // ExtensionStatus
                status = await ReadExtensionStatus();
            }
            else if (fieldId == 2 && fieldType == TTypeList)
            {
                // ExtensionPluginResponse = list<map<string,string>>
                rows = await ReadPluginResponse();
            }
            else
            {
                await SkipFieldAsync(fieldType);
            }
        }

        return new QueryResult(status, rows);
    }

    private async Task<ExtensionStatus> ReadExtensionStatus()
    {
        int code = 0;
        string message = "";

        while (true)
        {
            var fieldType = await ReadByteAsync();
            if (fieldType == TTypeStop)
                break;

            var fieldId = await ReadI16Async();

            if (fieldId == 1 && fieldType == TTypeI32)
                code = await ReadI32Async();
            else if (fieldId == 2 && fieldType == TTypeString)
                message = await ReadStringAsync();
            else
                await SkipFieldAsync(fieldType);
        }

        return new ExtensionStatus(code, message);
    }

    private async Task<List<Dictionary<string, string>>> ReadPluginResponse()
    {
        var listType = await ReadByteAsync();
        var listSize = await ReadI32Async();
        var rows = new List<Dictionary<string, string>>(listSize);

        for (int i = 0; i < listSize; i++)
        {
            var row = await ReadMapStringStringAsync();
            rows.Add(row);
        }

        return rows;
    }

    private async Task<Dictionary<string, string>> ReadMapStringStringAsync()
    {
        // Read map header within a struct wrapper
        // In Thrift, list<map<string,string>> means each element is a map directly
        var keyType = await ReadByteAsync();
        var valueType = await ReadByteAsync();
        var mapSize = await ReadI32Async();

        var dict = new Dictionary<string, string>(mapSize);
        for (int i = 0; i < mapSize; i++)
        {
            var key = await ReadStringAsync();
            var value = await ReadStringAsync();
            dict[key] = value;
        }

        return dict;
    }

    private async Task SkipFieldAsync(byte fieldType)
    {
        switch (fieldType)
        {
            case TTypeBool:
                await ReadByteAsync();
                break;
            case TTypeI32:
                await ReadI32Async();
                break;
            case TTypeI64:
                var buf8 = new byte[8];
                await ReadExactAsync(buf8);
                break;
            case TTypeString:
                await ReadStringAsync();
                break;
            case TTypeStruct:
                while (true)
                {
                    var ft = await ReadByteAsync();
                    if (ft == TTypeStop) break;
                    await ReadI16Async(); // field id
                    await SkipFieldAsync(ft);
                }
                break;
            case TTypeMap:
                await ReadByteAsync(); // key type
                await ReadByteAsync(); // value type
                var mapLen = await ReadI32Async();
                for (int i = 0; i < mapLen; i++)
                {
                    await ReadStringAsync();
                    await ReadStringAsync();
                }
                break;
            case TTypeList:
                var elemType = await ReadByteAsync();
                var listLen = await ReadI32Async();
                for (int i = 0; i < listLen; i++)
                    await SkipFieldAsync(elemType);
                break;
        }
    }

    private async Task<byte> ReadByteAsync()
    {
        var buf = new byte[1];
        await ReadExactAsync(buf);
        return buf[0];
    }

    private async Task<short> ReadI16Async()
    {
        var buf = new byte[2];
        await ReadExactAsync(buf);
        return BinaryPrimitives.ReadInt16BigEndian(buf);
    }

    private async Task<int> ReadI32Async()
    {
        var buf = new byte[4];
        await ReadExactAsync(buf);
        return BinaryPrimitives.ReadInt32BigEndian(buf);
    }

    private async Task<string> ReadStringAsync()
    {
        var len = await ReadI32Async();
        if (len == 0) return string.Empty;
        var buf = new byte[len];
        await ReadExactAsync(buf);
        return Encoding.UTF8.GetString(buf);
    }

    private async Task ReadExactAsync(byte[] buffer)
    {
        int offset = 0;
        while (offset < buffer.Length)
        {
            var read = await _stream!.ReadAsync(buffer.AsMemory(offset, buffer.Length - offset));
            if (read == 0)
                throw new OsqueryException("Connection closed unexpectedly.");
            offset += read;
        }
    }

    private static void WriteI32(BinaryWriter writer, int value)
    {
        Span<byte> buf = stackalloc byte[4];
        BinaryPrimitives.WriteInt32BigEndian(buf, value);
        writer.Write(buf);
    }

    private static void WriteI16(BinaryWriter writer, short value)
    {
        Span<byte> buf = stackalloc byte[2];
        BinaryPrimitives.WriteInt16BigEndian(buf, value);
        writer.Write(buf);
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            _stream?.Dispose();
            _socket?.Dispose();
            _disposed = true;
        }
        GC.SuppressFinalize(this);
    }
}
