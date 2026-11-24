using System.Net;
using System.Text;

namespace NetDiag;

/// <summary>DNS record types (a subset of the IANA registry; only the types netdiag queries/parses).</summary>
public enum DnsRecordType : ushort
{
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    PTR = 12,
    MX = 15,
    TXT = 16,
    AAAA = 28,
    SRV = 33,
}

/// <summary>A single DNS resource record as parsed from a response.</summary>
public sealed record DnsRecord(string Name, DnsRecordType Type, uint Ttl, string Data);

/// <summary>A parsed DNS response message (header fields plus the answer section).</summary>
public sealed class DnsMessage
{
    public required ushort Id { get; init; }
    public required bool Truncated { get; init; }
    public required int ResponseCode { get; init; }
    public required IReadOnlyList<DnsRecord> Answers { get; init; }
    public required IReadOnlyList<DnsRecord> Authority { get; init; }
    public required IReadOnlyList<DnsRecord> Additional { get; init; }

    /// <summary>True when the server says the name does not exist (RCODE 3, NXDOMAIN).</summary>
    public bool IsNameError => ResponseCode == 3;
}

/// <summary>Thrown when a DNS response packet cannot be parsed (truncated, malformed, or mismatched).</summary>
public sealed class DnsParseException : Exception
{
    public DnsParseException(string message) : base(message) { }
}

/// <summary>
/// Hand-rolled DNS wire-format encoder/decoder (RFC 1035).
/// No DNS library is used: the query is built byte by byte and the response is
/// parsed by hand, including compressed domain names (0xC0 pointers).
/// </summary>
public static class DnsWire
{
    private const int HeaderLength = 12;
    private const int MaxCompressionJumps = 10;

    /// <summary>Build a standard recursive query packet for <paramref name="name"/> / <paramref name="type"/>.</summary>
    public static byte[] BuildQuery(ushort id, string name, DnsRecordType type)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        var labels = name.TrimEnd('.').Split('.');
        using var ms = new MemoryStream();
        WriteU16(ms, id);
        WriteU16(ms, 0x0100); // flags: recursion desired
        WriteU16(ms, 1);      // QDCOUNT
        WriteU16(ms, 0);      // ANCOUNT
        WriteU16(ms, 0);      // NSCOUNT
        WriteU16(ms, 0);      // ARCOUNT
        foreach (var label in labels)
        {
            var bytes = Encoding.ASCII.GetBytes(label);
            if (bytes.Length == 0 || bytes.Length > 63)
                throw new ArgumentException($"Invalid DNS label '{label}' (must be 1-63 bytes).", nameof(name));
            ms.WriteByte((byte)bytes.Length);
            ms.Write(bytes, 0, bytes.Length);
        }
        ms.WriteByte(0); // root label
        WriteU16(ms, (ushort)type);
        WriteU16(ms, 1); // QCLASS IN
        return ms.ToArray();
    }

    /// <summary>Parse a DNS response packet, verifying the transaction id matches <paramref name="expectedId"/>.</summary>
    public static DnsMessage ParseResponse(byte[] data, ushort expectedId)
    {
        if (data.Length < HeaderLength)
            throw new DnsParseException($"Response is {data.Length} bytes, shorter than the 12-byte DNS header.");

        ushort id = ReadU16(data, 0);
        if (id != expectedId)
            throw new DnsParseException($"Transaction id mismatch: expected {expectedId}, got {id}.");

        ushort flags = ReadU16(data, 2);
        if ((flags & 0x8000) == 0)
            throw new DnsParseException("Packet is a query, not a response (QR bit is 0).");

        bool truncated = (flags & 0x0200) != 0;
        int rcode = flags & 0x000F;
        int qdCount = ReadU16(data, 4);
        int anCount = ReadU16(data, 6);
        int nsCount = ReadU16(data, 8);
        int arCount = ReadU16(data, 10);

        int offset = HeaderLength;
        for (int i = 0; i < qdCount; i++)
        {
            ReadName(data, ref offset); // QNAME
            if (offset + 4 > data.Length)
                throw new DnsParseException("Question section is truncated.");
            offset += 4; // QTYPE + QCLASS
        }

        var answers = ReadRecords(data, ref offset, anCount);
        var authority = ReadRecords(data, ref offset, nsCount);
        var additional = ReadRecords(data, ref offset, arCount);

        return new DnsMessage
        {
            Id = id,
            Truncated = truncated,
            ResponseCode = rcode,
            Answers = answers,
            Authority = authority,
            Additional = additional,
        };
    }

    private static List<DnsRecord> ReadRecords(byte[] data, ref int offset, int count)
    {
        var records = new List<DnsRecord>(count);
        for (int i = 0; i < count; i++)
            records.Add(ReadRecord(data, ref offset));
        return records;
    }

    private static DnsRecord ReadRecord(byte[] data, ref int offset)
    {
        string name = ReadName(data, ref offset);
        if (offset + 10 > data.Length)
            throw new DnsParseException("Resource record header is truncated.");
        var type = (DnsRecordType)ReadU16(data, offset);
        offset += 2;
        offset += 2; // CLASS
        uint ttl = ReadU32(data, offset);
        offset += 4;
        ushort rdLength = ReadU16(data, offset);
        offset += 2;
        if (offset + rdLength > data.Length)
            throw new DnsParseException($"RDATA ({rdLength} bytes) extends past the end of the packet.");
        int rdataStart = offset;
        string rdata = ParseRdata(data, rdataStart, rdLength, type);
        offset += rdLength;
        return new DnsRecord(name, type, ttl, rdata);
    }

    private static string ParseRdata(byte[] data, int start, int length, DnsRecordType type)
    {
        switch (type)
        {
            case DnsRecordType.A:
                if (length != 4) throw new DnsParseException($"A record RDATA must be 4 bytes, got {length}.");
                return new IPAddress(data.AsSpan(start, 4)).ToString();
            case DnsRecordType.AAAA:
                if (length != 16) throw new DnsParseException($"AAAA record RDATA must be 16 bytes, got {length}.");
                return new IPAddress(data.AsSpan(start, 16)).ToString();
            case DnsRecordType.CNAME:
            case DnsRecordType.NS:
            case DnsRecordType.PTR:
                {
                    int offset = start;
                    return ReadName(data, ref offset);
                }
            case DnsRecordType.MX:
                {
                    if (length < 3) throw new DnsParseException($"MX record RDATA is too short ({length} bytes).");
                    ushort preference = ReadU16(data, start);
                    int offset = start + 2;
                    string exchange = ReadName(data, ref offset);
                    return $"{preference} {exchange}";
                }
            case DnsRecordType.TXT:
                {
                    // One or more length-prefixed character strings.
                    var parts = new List<string>();
                    int pos = start;
                    int end = start + length;
                    while (pos < end)
                    {
                        int len = data[pos++];
                        if (pos + len > end)
                            throw new DnsParseException("TXT character string extends past the end of RDATA.");
                        parts.Add(Encoding.ASCII.GetString(data, pos, len));
                        pos += len;
                    }
                    return string.Join(" ", parts.Select(p => $"\"{p}\""));
                }
            case DnsRecordType.SOA:
                {
                    int offset = start;
                    string mname = ReadName(data, ref offset);
                    string rname = ReadName(data, ref offset);
                    if (offset + 20 > start + length)
                        throw new DnsParseException("SOA record RDATA is truncated.");
                    uint serial = ReadU32(data, offset);
                    return $"{mname} {rname} serial={serial}";
                }
            default:
                // Unknown type: present the raw bytes as hex so nothing is silently dropped.
                return "0x" + Convert.ToHexString(data.AsSpan(start, length)).ToLowerInvariant();
        }
    }

    /// <summary>
    /// Read a domain name at <paramref name="offset"/>, following compression pointers.
    /// On return, <paramref name="offset"/> points just past the name (or just past the
    /// pointer, when compression was used), so the caller can keep parsing the packet.
    /// </summary>
    public static string ReadName(byte[] data, ref int offset)
    {
        var labels = new List<string>();
        int jumps = 0;
        int nextOffset = -1; // position after the pointer, if compression was used
        int pos = offset;
        while (true)
        {
            if (pos >= data.Length)
                throw new DnsParseException("Domain name extends past the end of the packet.");
            byte len = data[pos];
            if (len == 0)
            {
                pos++;
                break;
            }
            if ((len & 0xC0) == 0xC0)
            {
                // Compression pointer: the next 14 bits are an offset into the packet.
                if (pos + 1 >= data.Length)
                    throw new DnsParseException("Compression pointer is truncated.");
                int pointer = ((len & 0x3F) << 8) | data[pos + 1];
                if (nextOffset == -1)
                    nextOffset = pos + 2;
                if (++jumps > MaxCompressionJumps)
                    throw new DnsParseException("Too many compression jumps (possible pointer loop).");
                if (pointer >= data.Length)
                    throw new DnsParseException($"Compression pointer {pointer} is outside the packet.");
                pos = pointer;
                continue;
            }
            if ((len & 0xC0) != 0)
                throw new DnsParseException($"Invalid label length byte 0x{len:X2}.");
            pos++;
            if (pos + len > data.Length)
                throw new DnsParseException("Label extends past the end of the packet.");
            labels.Add(Encoding.ASCII.GetString(data, pos, len));
            pos += len;
        }
        offset = nextOffset == -1 ? pos : nextOffset;
        return string.Join(".", labels);
    }

    private static void WriteU16(Stream stream, ushort value)
    {
        stream.WriteByte((byte)(value >> 8));
        stream.WriteByte((byte)(value & 0xFF));
    }

    private static ushort ReadU16(byte[] data, int offset) => (ushort)((data[offset] << 8) | data[offset + 1]);

    private static uint ReadU32(byte[] data, int offset) =>
        ((uint)data[offset] << 24) | ((uint)data[offset + 1] << 16) |
        ((uint)data[offset + 2] << 8) | data[offset + 3];
}
