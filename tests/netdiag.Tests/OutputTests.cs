using System.Text;
using System.Text.Json;
using Xunit;

namespace NetDiag.Tests;

public class OutputTests
{
    [Fact]
    public void PrintTable_ContainsHeadersAndRows()
    {
        var writer = new StringWriter();
        TextWriter original = Console.Out;
        try
        {
            Console.SetOut(writer);
            Output.PrintTable(
                new[] { "Name", "Type" },
                new[] { new[] { "example.com", "A" }, new[] { "example.com", "AAAA" } });
        }
        finally
        {
            Console.SetOut(original);
        }

        string output = writer.ToString();
        Assert.Contains("Name", output);
        Assert.Contains("Type", output);
        Assert.Contains("example.com", output);
        Assert.Contains("AAAA", output);
    }

    [Fact]
    public void TcpAttempt_SerializesToValidJson()
    {
        var attempt = new TcpAttempt("127.0.0.1", 80, TcpPortStatus.Open, 1.5, null);
        string json = JsonSerializer.Serialize(attempt, Output.JsonOptions);

        using JsonDocument doc = JsonDocument.Parse(json);
        Assert.Equal("Open", doc.RootElement.GetProperty("status").GetString());
        Assert.Equal(80, doc.RootElement.GetProperty("port").GetInt32());
        Assert.Equal(1.5, doc.RootElement.GetProperty("latencyMs").GetDouble());
    }

    [Fact]
    public void DnsQueryResult_SerializesWithAnswers()
    {
        var result = new DnsQueryResult(
            "example.com", DnsRecordType.A, "8.8.8.8", false,
            new[] { new DnsRecord("example.com", DnsRecordType.A, 300, "93.184.216.34") },
            12.3, null, null);
        string json = JsonSerializer.Serialize(result, Output.JsonOptions);

        using JsonDocument doc = JsonDocument.Parse(json);
        Assert.Equal("example.com", doc.RootElement.GetProperty("name").GetString());
        Assert.Equal("93.184.216.34", doc.RootElement.GetProperty("answers")[0].GetProperty("data").GetString());
        Assert.Equal(300u, doc.RootElement.GetProperty("answers")[0].GetProperty("ttl").GetUInt32());
    }

    [Fact]
    public void FirewallLimitations_AreNonEmpty()
    {
        Assert.NotEmpty(FirewallProbe.Limitations);
        Assert.All(FirewallProbe.Limitations, l => Assert.False(string.IsNullOrWhiteSpace(l)));
    }
}
