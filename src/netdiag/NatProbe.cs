using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace NetDiag;

/// <summary>One local address and how it is classified.</summary>
public sealed record LocalAddressInfo(string Interface, string Address, string Classification);

/// <summary>Result of the local loopback listener reachability check.</summary>
public sealed record ListenerCheckResult(bool Succeeded, int Port, string Note);

/// <summary>Result of one <c>nat</c> command invocation.</summary>
public sealed record NatResult(
    IReadOnlyList<LocalAddressInfo> LocalAddresses,
    string? PublicIp,
    string? PublicIpSource,
    string? PublicIpError,
    string NatAssessment,
    ListenerCheckResult ListenerCheck);

/// <summary>
/// NAT assessment: local addresses (RFC 1918 detection), the public IP as seen from
/// the internet, whether the machine appears to sit behind NAT, and a local loopback
/// listener check. The listener check proves local reachability only — it says
/// nothing about reachability from outside the machine.
/// </summary>
public static class NatProbe
{
    private static readonly string[] PublicIpEndpoints =
    {
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
    };

    private const int PublicIpTimeoutMs = 4000;

    public static async Task<NatResult> RunAsync()
    {
        var local = new List<LocalAddressInfo>();
        foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            foreach (UnicastIPAddressInformation addr in nic.GetIPProperties().UnicastAddresses)
                local.Add(new LocalAddressInfo(nic.Name, addr.Address.ToString(), Classify(addr.Address)));
        }

        (string? ip, string? source, string? error) = await FetchPublicIpAsync();
        var listener = ListenerCheck();

        string assessment;
        if (ip is null)
        {
            assessment = "Unknown: the public IP could not be determined, so NAT status cannot be assessed.";
        }
        else if (local.Any(a => a.Address == ip))
        {
            assessment = "No NAT detected: a local address matches the public IP, so this machine appears directly reachable.";
        }
        else if (local.Any(a => a.Classification.StartsWith("Private", StringComparison.Ordinal)))
        {
            assessment = "Appears behind NAT: local addresses are private (RFC 1918) while the public IP differs.";
        }
        else
        {
            assessment = "Unclear: the public IP differs from every local address, but no private address was found.";
        }

        return new NatResult(local, ip, source, error, assessment, listener);
    }

    /// <summary>Classify an address: Loopback, Private (RFC 1918), Link-local, Unique-local, or Public.</summary>
    public static string Classify(IPAddress address)
    {
        if (IPAddress.IsLoopback(address))
            return "Loopback";
        byte[] b = address.GetAddressBytes();
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            if (b[0] == 10) return "Private (RFC 1918)";
            if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return "Private (RFC 1918)";
            if (b[0] == 192 && b[1] == 168) return "Private (RFC 1918)";
            if (b[0] == 169 && b[1] == 254) return "Link-local";
            if (b[0] == 100 && b[1] >= 64 && b[1] <= 127) return "Shared (CGNAT)";
            return "Public";
        }
        // IPv6
        if (b[0] == 0xFE && (b[1] & 0xC0) == 0x80) return "Link-local";
        if ((b[0] & 0xFE) == 0xFC) return "Unique-local";
        return "Public";
    }

    /// <summary>Fetch the public IP from the first endpoint that answers. Returns (ip, source, error).</summary>
    public static async Task<(string? Ip, string? Source, string? Error)> FetchPublicIpAsync(int timeoutMs = PublicIpTimeoutMs)
    {
        using var http = new HttpClient { Timeout = TimeSpan.FromMilliseconds(timeoutMs) };
        List<string> failures = new();
        foreach (string endpoint in PublicIpEndpoints)
        {
            try
            {
                string body = (await http.GetStringAsync(endpoint)).Trim();
                if (IPAddress.TryParse(body, out IPAddress? ip))
                    return (ip.ToString(), endpoint, null);
                failures.Add($"{endpoint}: unexpected response '{body}'");
            }
            catch (Exception ex)
            {
                failures.Add($"{endpoint}: {ex.Message}");
            }
        }
        return (null, null, "All public-IP endpoints failed: " + string.Join("; ", failures));
    }

    /// <summary>
    /// Bind an ephemeral port on loopback and connect to it from this process.
    /// Success proves only that the local loopback stack accepts connections;
    /// it does NOT prove the port is reachable from other hosts or the internet.
    /// </summary>
    public static ListenerCheckResult ListenerCheck()
    {
        TcpListener? listener = null;
        try
        {
            listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            int port = ((IPEndPoint)listener.LocalEndpoint).Port;
            // Explicit IPv4 socket: a dual-mode IPv6 socket connecting to an IPv4-mapped
            // address can be redirected by transparent proxies, which would prove nothing
            // about the local listener.
            using var client = new TcpClient(AddressFamily.InterNetwork);
            // Accept in the background so the connect is not left pending.
            Task<TcpClient> accept = listener.AcceptTcpClientAsync();
            client.Connect(IPAddress.Loopback, port);
            accept.Wait(TimeSpan.FromSeconds(2));
            if (accept.IsCompletedSuccessfully)
                accept.Result.Dispose();
            return new ListenerCheckResult(true, port,
                "Local loopback listener accepted a connection. This proves local reachability only, NOT external reachability.");
        }
        catch (Exception ex)
        {
            return new ListenerCheckResult(false, 0,
                $"Local loopback listener check failed: {ex.Message}");
        }
        finally
        {
            listener?.Stop();
        }
    }
}
