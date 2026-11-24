using System.Net;
using System.Text;
using Xunit;

namespace NetDiag.Tests;

/// <summary>Wire-format tests: parse hand-built response packets, including malformed ones.</summary>
public class DnsWireTests
{
    private const ushort TestId = 0x1234;

    [Fact]
    public void BuildQuery_HasCorrectHeaderAndQuestion()
    {
        byte[] query = DnsWire.BuildQuery(TestId, "example.com", DnsRecordType.A);

        // Header: id, flags 0x0100 (recursion desired), QDCOUNT 1, rest 0.
        Assert.Equal(0x12, query[0]);
        Assert.Equal(0x34, query[1]);
        Assert.Equal(0x01, query[2]);
        Assert.Equal(0x00, query[3]);
        Assert.Equal(0x00, query[4]);
        Assert.Equal(0x01, query[5]);
        Assert.Equal(0x00, query[6]);
        Assert.Equal(0x00, query[11]);
        // Question: 7 "example" 3 "com" 0, QTYPE A, QCLASS IN.
        Assert.Equal(7, query[12]);
        Assert.Equal("example", Encoding.ASCII.GetString(query, 13, 7));
        Assert.Equal(3, query[20]);
        Assert.Equal("com", Encoding.ASCII.GetString(query, 21, 3));
        Assert.Equal(0, query[24]);
        Assert.Equal(0x00, query[25]);
        Assert.Equal(0x01, query[26]);
        Assert.Equal(0x00, query[27]);
        Assert.Equal(0x01, query[28]);
    }

    [Fact]
    public void ParseResponse_A_Record()
    {
        byte[] packet = BuildResponse(0x8180, new[]
        {
            ("example.com", (ushort)DnsRecordType.A, 300u, new byte[] { 93, 184, 216, 34 }),
        });

        DnsMessage message = DnsWire.ParseResponse(packet, TestId);

        Assert.Equal(TestId, message.Id);
        Assert.False(message.Truncated);
        Assert.Equal(0, message.ResponseCode);
        DnsRecord answer = Assert.Single(message.Answers);
        Assert.Equal("example.com", answer.Name);
        Assert.Equal(DnsRecordType.A, answer.Type);
        Assert.Equal(300u, answer.Ttl);
        Assert.Equal("93.184.216.34", answer.Data);
    }

    [Fact]
    public void ParseResponse_Aaaa_Record()
    {
        byte[] ipv6 = IPAddress.Parse("2606:2800:220:1:248:1893:25c8:1946").GetAddressBytes();
        byte[] packet = BuildResponse(0x8180, new[]
        {
            ("example.com", (ushort)DnsRecordType.AAAA, 60u, ipv6),
        });

        DnsMessage message = DnsWire.ParseResponse(packet, TestId);

        DnsRecord answer = Assert.Single(message.Answers);
        Assert.Equal(DnsRecordType.AAAA, answer.Type);
        Assert.Equal("2606:2800:220:1:248:1893:25c8:1946", answer.Data);
    }

    [Fact]
    public void ParseResponse_Cname_Record()
    {
        byte[] packet = BuildResponse(0x8180, new[]
        {
            ("example.com", (ushort)DnsRecordType.CNAME, 300u, EncodeName("target.example.com")),
        });

        DnsMessage message = DnsWire.ParseResponse(packet, TestId);

        DnsRecord answer = Assert.Single(message.Answers);
        Assert.Equal(DnsRecordType.CNAME, answer.Type);
        Assert.Equal("target.example.com", answer.Data);
    }

    [Fact]
    public void ParseResponse_Mx_Record()
    {
        byte[] rdata = new byte[] { 0, 10 }.Concat(EncodeName("mail.example.com")).ToArray();
        byte[] packet = BuildResponse(0x8180, new[]
        {
            ("example.com", (ushort)DnsRecordType.MX, 300u, rdata),
        });

        DnsMessage message = DnsWire.ParseResponse(packet, TestId);

        DnsRecord answer = Assert.Single(message.Answers);
        Assert.Equal(DnsRecordType.MX, answer.Type);
        Assert.Equal("10 mail.example.com", answer.Data);
    }

    [Fact]
    public void ParseResponse_MultipleAnswers_IncludesCnameAndA()
    {
        byte[] packet = BuildResponse(0x8180, new[]
        {
            ("example.com", (ushort)DnsRecordType.CNAME, 300u, EncodeName("target.example.com")),
            ("target.example.com", (ushort)DnsRecordType.A, 300u, new byte[] { 93, 184, 216, 34 }),
        });

        DnsMessage message = DnsWire.ParseResponse(packet, TestId);

        Assert.Equal(2, message.Answers.Count);
        Assert.Equal(DnsRecordType.CNAME, message.Answers[0].Type);
        Assert.Equal("example.com", message.Answers[0].Name);
        Assert.Equal(DnsRecordType.A, message.Answers[1].Type);
        Assert.Equal("target.example.com", message.Answers[1].Name);
        Assert.Equal("93.184.216.34", message.Answers[1].Data);
    }

    [Fact]
    public void ParseResponse_Txt_Record()
    {
        byte[] txt = Encoding.ASCII.GetBytes("v=spf1 -all");
        byte[] rdata = new byte[] { (byte)txt.Length }.Concat(txt).ToArray();
        byte[] packet = BuildResponse(0x8180, new[]
        {
            ("example.com", (ushort)DnsRecordType.TXT, 300u, rdata),
        });

        DnsMessage message = DnsWire.ParseResponse(packet, TestId);

        DnsRecord answer = Assert.Single(message.Answers);
        Assert.Equal(DnsRecordType.TXT, answer.Type);
        Assert.Equal("\"v=spf1 -all\"", answer.Data);
    }

    [Fact]
    public void ParseResponse_NxDomain_SetsResponseCode()
    {
        byte[] packet = BuildResponse(0x8183, Array.Empty<(string, ushort, uint, byte[])>());

        DnsMessage message = DnsWire.ParseResponse(packet, TestId);

        Assert.True(message.IsNameError);
        Assert.Equal(3, message.ResponseCode);
        Assert.Empty(message.Answers);
    }

    [Fact]
    public void ParseResponse_TruncatedPacket_Throws()
    {
        byte[] packet = { 0x12, 0x34, 0x81, 0x80, 0x00 };

        Assert.Throws<DnsParseException>(() => DnsWire.ParseResponse(packet, TestId));
    }

    [Fact]
    public void ParseResponse_WrongTransactionId_Throws()
    {
        byte[] packet = BuildResponse(0x8180, new[]
        {
            ("example.com", (ushort)DnsRecordType.A, 300u, new byte[] { 93, 184, 216, 34 }),
        });

        Assert.Throws<DnsParseException>(() => DnsWire.ParseResponse(packet, 0x9999));
    }

    [Fact]
    public void ParseResponse_TruncatedRdata_Throws()
    {
        // Answer claims 4 bytes of RDATA but only 2 are present.
        var bytes = new List<byte>(BuildResponse(0x8180, new[]
        {
            ("example.com", (ushort)DnsRecordType.A, 300u, new byte[] { 93, 184, 216, 34 }),
        }));
        bytes.RemoveRange(bytes.Count - 2, 2);

        Assert.Throws<DnsParseException>(() => DnsWire.ParseResponse(bytes.ToArray(), TestId));
    }

    [Fact]
    public void ReadName_CompressionPointerLoop_Throws()
    {
        // Header + question, then an answer whose name pointer points at itself (offset 12).
        var packet = new List<byte>();
        packet.AddRange(new byte[] { 0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 });
        packet.AddRange(EncodeName("example.com"));
        packet.AddRange(new byte[] { 0x00, 0x01, 0x00, 0x01 }); // QTYPE A, QCLASS IN
        packet.AddRange(new byte[] { 0xC0, 0x1E }); // pointer to offset 30 (itself)
        packet.AddRange(new byte[] { 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2C, 0x00, 0x04, 93, 184, 216, 34 });

        Assert.Throws<DnsParseException>(() => DnsWire.ParseResponse(packet.ToArray(), TestId));
    }

    /// <summary>Build a minimal response: one question (example.com A) plus the given answers.</summary>
    private static byte[] BuildResponse(ushort flags, (string Name, ushort Type, uint Ttl, byte[] Rdata)[] answers)
    {
        var packet = new List<byte>();
        void U16(ushort v) { packet.Add((byte)(v >> 8)); packet.Add((byte)(v & 0xFF)); }
        void U32(uint v)
        {
            packet.Add((byte)(v >> 24)); packet.Add((byte)(v >> 16));
            packet.Add((byte)(v >> 8)); packet.Add((byte)v);
        }

        U16(TestId);
        U16(flags);
        U16(1); // QDCOUNT
        U16((ushort)answers.Length); // ANCOUNT
        U16(0);
        U16(0);
        packet.AddRange(EncodeName("example.com"));
        U16(1); // QTYPE A
        U16(1); // QCLASS IN
        foreach (var (name, type, ttl, rdata) in answers)
        {
            // Answer NAME: a compression pointer to the question name when it matches,
            // otherwise the name encoded literally.
            if (name == "example.com")
            {
                packet.Add(0xC0);
                packet.Add(0x0C);
            }
            else
            {
                packet.AddRange(EncodeName(name));
            }
            U16(type);
            U16(1); // CLASS IN
            U32(ttl);
            U16((ushort)rdata.Length);
            packet.AddRange(rdata);
        }
        return packet.ToArray();
    }

    private static byte[] EncodeName(string name)
    {
        var bytes = new List<byte>();
        foreach (string label in name.Split('.'))
        {
            byte[] labelBytes = Encoding.ASCII.GetBytes(label);
            bytes.Add((byte)labelBytes.Length);
            bytes.AddRange(labelBytes);
        }
        bytes.Add(0);
        return bytes.ToArray();
    }
}
