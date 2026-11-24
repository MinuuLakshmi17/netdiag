using System.Diagnostics;
using System.Net;
using System.Net.Sockets;

namespace NetDiag;

/// <summary>Result of one <c>dns</c> command invocation.</summary>
public sealed record DnsQueryResult(
    string Name,
    DnsRecordType Type,
    string Server,
    bool UsedFallback,
    IReadOnlyList<DnsRecord> Answers,
    double LatencyMs,
    string? Error,
    string? Note);

/// <summary>
/// Minimal DNS client over UDP, using the hand-rolled wire format in <see cref="DnsWire"/>.
/// Falls back to <see cref="System.Net.Dns"/> only when the hand-rolled client fails,
/// and says so in the result.
/// </summary>
public static class DnsClient
{
    private const int DefaultTimeoutMs = 3000;
    private const int MaxCnameHops = 5;
    private const int AttemptsPerHop = 2;

    /// <summary>
    /// Resolve <paramref name="name"/> for <paramref name="type"/> against <paramref name="server"/>.
    /// For A/AAAA queries, CNAME answers are chased (up to 5 hops) so the caller gets the
    /// final addresses. Returns a result object; the error is carried in the result, not thrown,
    /// except for invalid arguments.
    /// </summary>
    public static async Task<DnsQueryResult> QueryAsync(
        string name, DnsRecordType type, string server, int timeoutMs = DefaultTimeoutMs)
    {
        if (!IPAddress.TryParse(server, out var serverAddress))
            return new DnsQueryResult(name, type, server, false, Array.Empty<DnsRecord>(), 0,
                $"Invalid DNS server address '{server}'.", null);

        var stopwatch = Stopwatch.StartNew();
        var collected = new List<DnsRecord>();
        string currentName = name;

        try
        {
            for (int hop = 0; hop <= MaxCnameHops; hop++)
            {
                DnsMessage? response = null;
                Exception? lastError = null;
                for (int attempt = 0; attempt < AttemptsPerHop; attempt++)
                {
                    try
                    {
                        response = await SendQueryAsync(currentName, type, serverAddress, timeoutMs);
                        break;
                    }
                    catch (Exception ex) when (ex is SocketException or TimeoutException or DnsParseException or OperationCanceledException)
                    {
                        // OperationCanceledException is what the per-attempt timeout
                        // (CancellationTokenSource) produces; it must retry like a timeout.
                        lastError = ex;
                    }
                }
                if (response is null)
                    throw lastError ?? new TimeoutException("DNS query timed out.");

                if (response.IsNameError)
                    return Finish(name, type, server, collected, stopwatch, "NXDOMAIN: the name does not exist.");

                if (response.Truncated)
                    // Truncated UDP responses should be retried over TCP (RFC 1035);
                    // netdiag does not implement DNS-over-TCP, so it falls back instead.
                    return await FallbackAsync(name, type, server, stopwatch,
                        "response was truncated (TC bit set)");

                collected.AddRange(response.Answers);

                // If we already have an answer of the requested type, we are done.
                if (response.Answers.Any(a => a.Type == type))
                    return Finish(name, type, server, collected, stopwatch, null);

                // Otherwise chase a CNAME (only for address queries).
                var cname = response.Answers.FirstOrDefault(a => a.Type == DnsRecordType.CNAME);
                if (cname is not null && (type == DnsRecordType.A || type == DnsRecordType.AAAA))
                {
                    currentName = cname.Data;
                    continue;
                }

                // No usable answer and nothing to chase.
                return Finish(name, type, server, collected, stopwatch,
                    response.Answers.Count == 0
                        ? "No answer records returned (NODATA)."
                        : $"No {type} record returned.");
            }

            return Finish(name, type, server, collected, stopwatch,
                $"CNAME chain exceeded {MaxCnameHops} hops.");
        }
        catch (Exception ex)
        {
            // Hand-rolled client failed: fall back to the framework resolver and say so.
            return await FallbackAsync(name, type, server, stopwatch, ex.Message);
        }
    }

    private static DnsQueryResult Finish(
        string name, DnsRecordType type, string server, List<DnsRecord> collected,
        Stopwatch stopwatch, string? error)
    {
        stopwatch.Stop();
        return new DnsQueryResult(name, type, server, false, collected,
            stopwatch.Elapsed.TotalMilliseconds, error, null);
    }

    private static async Task<DnsMessage> SendQueryAsync(
        string name, DnsRecordType type, IPAddress server, int timeoutMs)
    {
        ushort id = (ushort)Random.Shared.Next(0, 65536);
        byte[] query = DnsWire.BuildQuery(id, name, type);
        using var udp = new UdpClient();
        udp.Connect(server, 53);
        using var timeout = new CancellationTokenSource(timeoutMs);
        await udp.SendAsync(new ReadOnlyMemory<byte>(query), timeout.Token);
        UdpReceiveResult result = await udp.ReceiveAsync(timeout.Token);
        return DnsWire.ParseResponse(result.Buffer, id);
    }

    private static async Task<DnsQueryResult> FallbackAsync(
        string name, DnsRecordType type, string server, Stopwatch stopwatch, string reason)
    {
        try
        {
            IPAddress[] addresses = await Dns.GetHostAddressesAsync(name);
            var records = addresses
                .Select(a => new DnsRecord(name,
                    a.AddressFamily == AddressFamily.InterNetwork ? DnsRecordType.A : DnsRecordType.AAAA,
                    0, a.ToString()))
                .Where(r => r.Type == type || type is DnsRecordType.A or DnsRecordType.AAAA)
                .ToList();
            stopwatch.Stop();
            return new DnsQueryResult(name, type, server, true, records,
                stopwatch.Elapsed.TotalMilliseconds, null,
                $"Hand-rolled DNS client failed ({reason}); fell back to System.Net.Dns. TTLs are not available from the fallback.");
        }
        catch (Exception ex)
        {
            stopwatch.Stop();
            return new DnsQueryResult(name, type, server, true, Array.Empty<DnsRecord>(),
                stopwatch.Elapsed.TotalMilliseconds,
                $"Hand-rolled DNS client failed ({reason}) and the System.Net.Dns fallback also failed: {ex.Message}", null);
        }
    }

    /// <summary>
    /// The default DNS server: the first nameserver in /etc/resolv.conf on Unix,
    /// otherwise 8.8.8.8 (Google Public DNS). On Windows there is no resolv.conf,
    /// so 8.8.8.8 is used unless --server is given.
    /// </summary>
    public static string GetDefaultServer()
    {
        if (OperatingSystem.IsWindows())
            return "8.8.8.8";
        try
        {
            foreach (string line in File.ReadLines("/etc/resolv.conf"))
            {
                string[] parts = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length >= 2 && parts[0] == "nameserver" && IPAddress.TryParse(parts[1], out _))
                    return parts[1];
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Fall through to the default below.
        }
        return "8.8.8.8";
    }
}
