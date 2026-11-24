using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace NetDiag;

/// <summary>Rendering of probe results: machine-readable JSON, or clean human-readable tables.</summary>
public static class Output
{
    // Internal so the test project can serialize with the exact options the CLI uses.
    internal static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        // Enums serialize as their names ("A", "Open") so the JSON is self-describing.
        Converters = { new JsonStringEnumConverter() },
    };

    public static void WriteJson(object value)
    {
        Console.WriteLine(JsonSerializer.Serialize(value, JsonOptions));
    }

    public static void PrintDns(DnsQueryResult result)
    {
        Console.WriteLine($"DNS {result.Type} query for {result.Name} via {result.Server}" +
                          (result.UsedFallback ? " (System.Net.Dns fallback)" : ""));
        Console.WriteLine($"Latency: {result.LatencyMs:F1} ms");
        if (result.Note is not null)
            Console.WriteLine($"Note: {result.Note}");
        if (result.Error is not null)
        {
            Console.WriteLine($"Error: {result.Error}");
            return;
        }
        if (result.Answers.Count == 0)
        {
            Console.WriteLine("No answers.");
            return;
        }
        Console.WriteLine();
        PrintTable(
            new[] { "Name", "Type", "TTL", "Data" },
            result.Answers.Select(a => new[] { a.Name, a.Type.ToString(), a.Ttl.ToString(), a.Data }));
    }

    public static void PrintTcp(IReadOnlyList<TcpAttempt> attempts)
    {
        Console.WriteLine();
        PrintTable(
            new[] { "Host", "Port", "Status", "Latency", "Detail" },
            attempts.Select(a => new[]
            {
                a.Host, a.Port.ToString(), a.Status.ToString(),
                $"{a.LatencyMs:F1} ms", a.Detail ?? "-",
            }));
        int open = attempts.Count(a => a.Status == TcpPortStatus.Open);
        Console.WriteLine($"\n{open} of {attempts.Count} port(s) open.");
    }

    public static void PrintPing(PingResult result)
    {
        Console.WriteLine($"Pinging {result.Host} ({result.Replies.Count} echo request(s))");
        foreach (PingReply reply in result.Replies)
        {
            string line = reply.Outcome switch
            {
                PingOutcome.Success => $"Reply {reply.Sequence}: time={reply.LatencyMs:F1} ms",
                PingOutcome.Timeout => $"Reply {reply.Sequence}: timed out",
                PingOutcome.Unreachable => $"Reply {reply.Sequence}: unreachable ({reply.Detail})",
                PingOutcome.NotPermitted => $"Reply {reply.Sequence}: not permitted ({reply.Detail})",
                _ => $"Reply {reply.Sequence}: error ({reply.Detail})",
            };
            Console.WriteLine(line);
        }
        Console.WriteLine();
        Console.WriteLine($"Loss: {result.LossPercent:F0}%");
        if (result.AverageLatencyMs.HasValue)
            Console.WriteLine($"Average latency: {result.AverageLatencyMs.Value:F1} ms");
        if (result.Note is not null)
            Console.WriteLine($"Note: {result.Note}");
    }

    public static void PrintInterfaces(IReadOnlyList<InterfaceInfo> interfaces)
    {
        foreach (InterfaceInfo nic in interfaces)
        {
            Console.WriteLine($"{nic.Name}  [{nic.Type}]  {nic.Status}");
            Console.WriteLine($"  Description: {nic.Description}");
            Console.WriteLine($"  MAC:         {nic.MacAddress}");
            foreach (string address in nic.Addresses)
                Console.WriteLine($"  Address:     {address}");
            foreach (string gateway in nic.Gateways)
                Console.WriteLine($"  Gateway:     {gateway}");
            foreach (string dns in nic.DnsServers)
                Console.WriteLine($"  DNS server:  {dns}");
            Console.WriteLine();
        }
    }

    public static void PrintNat(NatResult result)
    {
        Console.WriteLine("Local addresses:");
        PrintTable(
            new[] { "Interface", "Address", "Classification" },
            result.LocalAddresses.Select(a => new[] { a.Interface, a.Address, a.Classification }));
        Console.WriteLine();
        Console.WriteLine($"Public IP: {(result.PublicIp ?? "unknown")}" +
                          (result.PublicIpSource is not null ? $" (via {result.PublicIpSource})" : ""));
        if (result.PublicIpError is not null)
            Console.WriteLine($"Public IP lookup failed: {result.PublicIpError}");
        Console.WriteLine($"NAT assessment: {result.NatAssessment}");
        Console.WriteLine();
        Console.WriteLine("Listener reachability check:");
        Console.WriteLine($"  {(result.ListenerCheck.Succeeded ? "Succeeded" : "Failed")} " +
                          (result.ListenerCheck.Succeeded ? $"on 127.0.0.1:{result.ListenerCheck.Port}" : ""));
        Console.WriteLine($"  {result.ListenerCheck.Note}");
    }

    public static void PrintFirewall(FirewallResult result)
    {
        Console.WriteLine("Outbound checks:");
        PrintTable(
            new[] { "Check", "Target", "Status", "Latency" },
            result.Checks.Select(c => new[]
            {
                c.Name, $"{c.Host}:{c.Port}" + (c.ResolvedIp is not null ? $" ({c.ResolvedIp})" : ""),
                c.Status.ToString(), $"{c.LatencyMs:F1} ms",
            }));
        Console.WriteLine();
        foreach (FirewallCheck check in result.Checks)
            Console.WriteLine($"- {check.Name}: {check.Proves}");
        Console.WriteLine();
        Console.WriteLine("Listener reachability check:");
        Console.WriteLine($"  {(result.ListenerCheck.Succeeded ? "Succeeded" : "Failed")} " +
                          (result.ListenerCheck.Succeeded ? $"on 127.0.0.1:{result.ListenerCheck.Port}" : ""));
        Console.WriteLine($"  {result.ListenerCheck.Note}");
        Console.WriteLine();
        Console.WriteLine("Limitations:");
        foreach (string limitation in result.Limitations)
            Console.WriteLine($"- {limitation}");
    }

    /// <summary>Print a simple left-aligned table with a header row.</summary>
    public static void PrintTable(string[] headers, IEnumerable<string[]> rows)
    {
        var rowList = rows.ToList();
        int columns = headers.Length;
        int[] widths = new int[columns];
        for (int i = 0; i < columns; i++)
            widths[i] = headers[i].Length;
        foreach (string[] row in rowList)
            for (int i = 0; i < columns; i++)
                widths[i] = Math.Max(widths[i], row[i].Length);

        var line = new StringBuilder();
        for (int i = 0; i < columns; i++)
            line.Append(headers[i].PadRight(widths[i] + 2));
        Console.WriteLine(line.ToString().TrimEnd());
        Console.WriteLine(new string('-', Math.Max(0, line.Length - 2)));
        foreach (string[] row in rowList)
        {
            line.Clear();
            for (int i = 0; i < columns; i++)
                line.Append(row[i].PadRight(widths[i] + 2));
            Console.WriteLine(line.ToString().TrimEnd());
        }
    }
}
