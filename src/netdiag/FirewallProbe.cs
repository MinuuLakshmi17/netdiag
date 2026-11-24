using System.Net;
using System.Net.Sockets;

namespace NetDiag;

/// <summary>One outbound connectivity check.</summary>
public sealed record FirewallCheck(
    string Name,
    string Host,
    int Port,
    string? ResolvedIp,
    TcpPortStatus Status,
    double LatencyMs,
    string Proves,
    string? Detail);

/// <summary>Result of one <c>firewall</c> command invocation.</summary>
public sealed record FirewallResult(
    IReadOnlyList<FirewallCheck> Checks,
    ListenerCheckResult ListenerCheck,
    IReadOnlyList<string> Limitations);

/// <summary>
/// Outbound firewall checks: TCP connects to well-known hosts/ports, plus the local
/// loopback listener check. Every result states what it proves, and the result
/// carries an explicit list of what these checks cannot prove.
/// </summary>
public static class FirewallProbe
{
    private const int DefaultTimeoutMs = 3000;

    // (display name, host, port). IP literals avoid depending on DNS; hostnames exercise it.
    private static readonly (string Name, string Host, int Port)[] Targets =
    {
        ("Google Public DNS", "8.8.8.8", 53),
        ("Cloudflare DNS", "1.1.1.1", 53),
        ("Google HTTPS", "google.com", 443),
        ("Example HTTP", "example.com", 80),
        ("GitHub HTTPS", "github.com", 443),
    };

    public static readonly IReadOnlyList<string> Limitations = new[]
    {
        "These checks test outbound TCP connectivity to specific destinations. A success proves that destination and port are reachable from here; it does not prove other destinations or ports are open.",
        "They say nothing about inbound connectivity: they cannot prove that a port on this machine is reachable from the internet or from other hosts.",
        "A failure cannot distinguish a firewall block from the remote host being down, the network being unreachable, or DNS failing.",
        "DNS-based targets depend on DNS resolution succeeding first; a DNS failure is reported as such, not as a firewall block.",
        "No packet inspection is performed: these checks do not verify what a firewall allows in general, only these five connections.",
    };

    public static async Task<FirewallResult> RunAsync(int timeoutMs = DefaultTimeoutMs)
    {
        var checks = new List<FirewallCheck>();
        foreach (var (name, host, port) in Targets)
        {
            string? resolvedIp = null;
            TcpAttempt attempt;
            if (IPAddress.TryParse(host, out IPAddress? literal))
            {
                resolvedIp = literal.ToString();
                attempt = await TcpProbe.ProbeAsync(host, port, timeoutMs);
            }
            else
            {
                try
                {
                    IPAddress[] addresses = await Dns.GetHostAddressesAsync(host);
                    IPAddress? first = addresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork)
                        ?? addresses.FirstOrDefault();
                    if (first is null)
                    {
                        checks.Add(new FirewallCheck(name, host, port, null, TcpPortStatus.Error, 0,
                            "Nothing: DNS returned no addresses, so the connection was never attempted.",
                            "DNS resolution returned no addresses."));
                        continue;
                    }
                    resolvedIp = first.ToString();
                    attempt = await TcpProbe.ProbeAsync(first.ToString(), port, timeoutMs);
                }
                catch (Exception ex)
                {
                    checks.Add(new FirewallCheck(name, host, port, null, TcpPortStatus.Error, 0,
                        "Nothing: DNS resolution failed, so the connection was never attempted.",
                        $"DNS resolution failed: {ex.Message}"));
                    continue;
                }
            }

            string proves = attempt.Status switch
            {
                TcpPortStatus.Open => $"Outbound TCP to {host}:{port} is permitted from this machine (for this destination).",
                TcpPortStatus.Closed => $"The remote host actively refused TCP on {host}:{port}; this is the remote end, not a local firewall block.",
                TcpPortStatus.Filtered => $"No response from {host}:{port} within the timeout; this may be a firewall block or the host silently dropping packets — this check cannot tell which.",
                TcpPortStatus.Unreachable => $"The network to {host} is unreachable; this is a routing problem, not a firewall verdict.",
                _ => $"The check to {host}:{port} failed ({attempt.Detail}); no firewall conclusion can be drawn.",
            };
            checks.Add(new FirewallCheck(name, host, port, resolvedIp, attempt.Status,
                attempt.LatencyMs, proves, attempt.Detail));
        }

        return new FirewallResult(checks, NatProbe.ListenerCheck(), Limitations);
    }
}
