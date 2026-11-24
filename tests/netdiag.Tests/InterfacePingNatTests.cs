using System.Net;
using Xunit;

namespace NetDiag.Tests;

public class InterfaceTests
{
    [Fact]
    public void List_ReturnsAtLeastLoopback()
    {
        IReadOnlyList<InterfaceInfo> interfaces = InterfaceProbe.List();

        Assert.NotEmpty(interfaces);
        Assert.Contains(interfaces, nic =>
            nic.Addresses.Any(a => a.StartsWith("127.0.0.1", StringComparison.Ordinal)));
    }

    [Fact]
    public void List_EveryInterfaceHasANameAndStatus()
    {
        IReadOnlyList<InterfaceInfo> interfaces = InterfaceProbe.List();

        Assert.All(interfaces, nic =>
        {
            Assert.False(string.IsNullOrWhiteSpace(nic.Name));
            Assert.False(string.IsNullOrWhiteSpace(nic.Status));
        });
    }
}

public class PingTests
{
    [Fact]
    public async Task RunAsync_Loopback_EitherSucceedsOrReportsNotPermitted()
    {
        // Raw ICMP needs privileges this sandbox may not grant, and this sandbox
        // also drops ICMP echo packets outright (the unprivileged ICMP socket opens,
        // but no reply ever comes back). All three outcomes are acceptable; what must
        // never happen is a faked success or an exception.
        PingResult result = await PingProbe.RunAsync("127.0.0.1", count: 1, timeoutMs: 1000);

        if (result.Overall == PingOutcome.NotPermitted)
        {
            Assert.NotNull(result.Note);
            Assert.Contains("privileg", result.Note, StringComparison.OrdinalIgnoreCase);
        }
        else if (result.Overall == PingOutcome.Timeout)
        {
            // 100% loss reported honestly; no latency attached to a reply that never arrived.
            Assert.Equal(100, result.LossPercent);
            Assert.Null(result.Replies[0].LatencyMs);
        }
        else
        {
            Assert.Equal(PingOutcome.Success, result.Overall);
            Assert.NotNull(result.Replies[0].LatencyMs);
        }
    }
}

public class NatTests
{
    [Theory]
    [InlineData("10.0.0.1", "Private (RFC 1918)")]
    [InlineData("172.16.0.1", "Private (RFC 1918)")]
    [InlineData("172.31.255.255", "Private (RFC 1918)")]
    [InlineData("192.168.1.1", "Private (RFC 1918)")]
    [InlineData("169.254.1.1", "Link-local")]
    [InlineData("127.0.0.1", "Loopback")]
    [InlineData("8.8.8.8", "Public")]
    [InlineData("::1", "Loopback")]
    [InlineData("fe80::1", "Link-local")]
    [InlineData("fc00::1", "Unique-local")]
    public void Classify_ReturnsExpectedClass(string address, string expected)
    {
        Assert.Equal(expected, NatProbe.Classify(IPAddress.Parse(address)));
    }

    [Fact]
    public void ListenerCheck_SucceedsOnLoopback()
    {
        ListenerCheckResult check = NatProbe.ListenerCheck();

        Assert.True(check.Succeeded);
        Assert.True(check.Port > 0);
        Assert.Contains("local reachability only", check.Note, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task FetchPublicIpAsync_NeverThrows()
    {
        // Depends on the public internet; when offline it must return null + error,
        // never throw. When online it must return a parseable IP.
        (string? ip, string? _, string? error) = await NatProbe.FetchPublicIpAsync(timeoutMs: 3000);

        if (ip is null)
            Assert.NotNull(error);
        else
            Assert.True(IPAddress.TryParse(ip, out _));
    }
}
