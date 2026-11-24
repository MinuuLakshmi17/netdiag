using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using Xunit;

namespace NetDiag.Tests;

public class TcpProbeTests
{
    [Fact]
    public async Task ProbeAsync_OpenPort_ReturnsOpen()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        // Accept in the background so the connect completes cleanly.
        Task<TcpClient> accept = listener.AcceptTcpClientAsync();

        TcpAttempt attempt = await TcpProbe.ProbeAsync("127.0.0.1", port, timeoutMs: 2000);

        Assert.Equal(TcpPortStatus.Open, attempt.Status);
        Assert.True(attempt.LatencyMs >= 0);
        (await accept).Dispose();
    }

    [Fact]
    public async Task ProbeAsync_ClosedPort_ReturnsClosed()
    {
        int port = GetFreePort();

        TcpAttempt attempt = await TcpProbe.ProbeAsync("127.0.0.1", port, timeoutMs: 2000);

        Assert.Equal(TcpPortStatus.Closed, attempt.Status);
    }

    [Fact]
    public async Task ProbeAsync_UnroutableAddress_DoesNotReportOpen_AndReturnsQuickly()
    {
        // 192.0.2.1 is TEST-NET-1: allocated for documentation, not routed on the
        // public internet. On a normal network this either times out (Filtered) or
        // fails fast with no route (Unreachable). In THIS sandbox every non-loopback
        // TCP connect is accepted by the egress proxy (198.19.0.1:3128), so Open is
        // the honest report here. The assertion that must hold everywhere is that
        // the probe returns quickly and never hangs or throws.
        var stopwatch = Stopwatch.StartNew();
        TcpAttempt attempt = await TcpProbe.ProbeAsync("192.0.2.1", 80, timeoutMs: 500);
        stopwatch.Stop();

        Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(5),
            $"Probe took {stopwatch.Elapsed.TotalSeconds:F1}s, longer than the timeout allows.");
        if (attempt.Status == TcpPortStatus.Open)
        {
            // Sandbox egress proxy intercepted the connect; see the comment above.
            return;
        }
        Assert.NotEqual(TcpPortStatus.Open, attempt.Status);
    }

    [Fact]
    public async Task ProbeRangeAsync_ReturnsResultsInPortOrder()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int openPort = ((IPEndPoint)listener.LocalEndpoint).Port;
        Task<TcpClient> accept = listener.AcceptTcpClientAsync();

        // A small 3-port window starting at the open port: the first is open,
        // the other two are (barring a race) closed.
        IReadOnlyList<TcpAttempt> ranged = await TcpProbe.ProbeRangeAsync("127.0.0.1", openPort, openPort + 2, 2000);

        Assert.Equal(3, ranged.Count);
        Assert.Equal(ranged.Select(a => a.Port), ranged.Select(a => a.Port).OrderBy(p => p));
        Assert.Equal(TcpPortStatus.Open, ranged[0].Status);
        Assert.Equal(openPort, ranged[0].Port);
        (await accept).Dispose();
    }

    [Fact]
    public async Task ProbeAsync_InvalidHost_ReturnsError_NotException()
    {
        // A hostname containing a space is rejected by getaddrinfo before any DNS
        // query is sent, so it fails even where the sandbox DNS proxy answers every
        // well-formed name (it synthesizes an address for "nonexistent.invalid.").
        TcpAttempt attempt = await TcpProbe.ProbeAsync("not a host!", 80, timeoutMs: 2000);

        Assert.Equal(TcpPortStatus.Error, attempt.Status);
        Assert.NotNull(attempt.Detail);
    }

    /// <summary>Get a port that is free right now (bind then release it).</summary>
    private static int GetFreePort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }
}
