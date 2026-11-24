using System.Diagnostics;
using System.Net;
using System.Net.Sockets;

namespace NetDiag;

/// <summary>What a single TCP connect attempt concluded.</summary>
public enum TcpPortStatus
{
    /// <summary>The connect completed: something is listening.</summary>
    Open,
    /// <summary>The host actively refused the connection (RST): nothing is listening.</summary>
    Closed,
    /// <summary>No response within the timeout: the port is filtered, or the host is silently dropping packets.</summary>
    Filtered,
    /// <summary>The host or network is unreachable (ICMP error or no route).</summary>
    Unreachable,
    /// <summary>Some other failure (for example DNS resolution failed).</summary>
    Error,
}

/// <summary>Result of one TCP connect attempt.</summary>
public sealed record TcpAttempt(string Host, int Port, TcpPortStatus Status, double LatencyMs, string? Detail, string? ResolvedIp = null);

/// <summary>TCP connect probe with a configurable timeout.</summary>
public static class TcpProbe
{
    public const int DefaultTimeoutMs = 2000;
    public const int MaxPortsPerRange = 1024;
    private const int MaxConcurrency = 16;

    /// <summary>
    /// Probe a single host:port. Never throws for network outcomes; they are reported in the result.
    /// The host is resolved first and each address is tried with a socket of the matching
    /// address family. That matters: a dual-mode IPv6 socket connecting to an IPv4-mapped
    /// address can be redirected by transparent proxies, so the probe must use an IPv4
    /// socket for IPv4 targets to be sure it actually reaches the target.
    /// </summary>
    public static async Task<TcpAttempt> ProbeAsync(string host, int port, int timeoutMs = DefaultTimeoutMs)
    {
        IPAddress[] addresses;
        try
        {
            addresses = await Dns.GetHostAddressesAsync(host);
        }
        catch (Exception ex)
        {
            return new TcpAttempt(host, port, TcpPortStatus.Error, 0,
                $"DNS resolution failed: {ex.Message}");
        }
        if (addresses.Length == 0)
            return new TcpAttempt(host, port, TcpPortStatus.Error, 0, "DNS resolution returned no addresses.");

        // IPv4 first: it is the common case, and it avoids IPv6-mapped interception.
        TcpAttempt? lastAttempt = null;
        foreach (IPAddress address in addresses.OrderBy(a => a.AddressFamily == AddressFamily.InterNetwork ? 0 : 1))
        {
            TcpAttempt attempt = await ProbeAddressAsync(host, address, port, timeoutMs);
            if (attempt.Status is TcpPortStatus.Open or TcpPortStatus.Closed)
                return attempt; // Definitive: something answered, or actively refused.
            lastAttempt = attempt; // Filtered / Unreachable / Error: try the next address.
        }
        return lastAttempt!;
    }

    private static async Task<TcpAttempt> ProbeAddressAsync(string host, IPAddress address, int port, int timeoutMs)
    {
        var stopwatch = Stopwatch.StartNew();
        try
        {
            using var client = new TcpClient(address.AddressFamily);
            using var timeout = new CancellationTokenSource(timeoutMs);
            await client.ConnectAsync(address, port, timeout.Token);
            stopwatch.Stop();
            return new TcpAttempt(host, port, TcpPortStatus.Open, stopwatch.Elapsed.TotalMilliseconds, null, address.ToString());
        }
        catch (OperationCanceledException)
        {
            stopwatch.Stop();
            return new TcpAttempt(host, port, TcpPortStatus.Filtered, stopwatch.Elapsed.TotalMilliseconds,
                "No response within the timeout.", address.ToString());
        }
        catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionRefused)
        {
            stopwatch.Stop();
            return new TcpAttempt(host, port, TcpPortStatus.Closed, stopwatch.Elapsed.TotalMilliseconds,
                "Connection refused (RST).", address.ToString());
        }
        catch (SocketException ex) when (ex.SocketErrorCode is SocketError.HostUnreachable or SocketError.NetworkUnreachable)
        {
            stopwatch.Stop();
            return new TcpAttempt(host, port, TcpPortStatus.Unreachable, stopwatch.Elapsed.TotalMilliseconds,
                ex.Message, address.ToString());
        }
        catch (SocketException ex)
        {
            stopwatch.Stop();
            return new TcpAttempt(host, port, TcpPortStatus.Error, stopwatch.Elapsed.TotalMilliseconds,
                ex.Message, address.ToString());
        }
        catch (Exception ex)
        {
            stopwatch.Stop();
            return new TcpAttempt(host, port, TcpPortStatus.Error, stopwatch.Elapsed.TotalMilliseconds,
                ex.Message, address.ToString());
        }
    }

    /// <summary>Probe an inclusive port range, up to <see cref="MaxPortsPerRange"/> ports, with bounded concurrency. Results are returned in port order.</summary>
    public static async Task<IReadOnlyList<TcpAttempt>> ProbeRangeAsync(
        string host, int startPort, int endPort, int timeoutMs = DefaultTimeoutMs)
    {
        using var semaphore = new SemaphoreSlim(MaxConcurrency);
        var tasks = new List<Task<TcpAttempt>>();
        for (int port = startPort; port <= endPort; port++)
        {
            int p = port;
            tasks.Add(Task.Run(async () =>
            {
                await semaphore.WaitAsync();
                try { return await ProbeAsync(host, p, timeoutMs); }
                finally { semaphore.Release(); }
            }));
        }
        TcpAttempt[] results = await Task.WhenAll(tasks);
        return results.OrderBy(r => r.Port).ToList();
    }
}
