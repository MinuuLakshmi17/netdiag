namespace NetDiag;

/// <summary>Usage errors exit with code 2 and print the usage text to stderr.</summary>
public sealed class UsageException : Exception
{
    public UsageException(string message) : base(message) { }
}

/// <summary>
/// netdiag — cross-platform network diagnostics CLI.
/// Exit codes: 0 success, 1 command failure, 2 usage error.
/// </summary>
public static class Program
{
    private const string Version = "1.0.0";

    public static async Task<int> Main(string[] args)
    {
        bool json = false;
        var remaining = new List<string>();
        foreach (string arg in args)
        {
            if (arg == "--json")
                json = true;
            else if (arg is "--help" or "-h")
                return PrintUsage(0);
            else if (arg == "--version")
            {
                Console.WriteLine($"netdiag {Version}");
                return 0;
            }
            else
                remaining.Add(arg);
        }

        if (remaining.Count == 0)
            return PrintUsage(2);

        string command = remaining[0];
        string[] commandArgs = remaining.Skip(1).ToArray();

        try
        {
            return command switch
            {
                "dns" => await RunDnsAsync(commandArgs, json),
                "tcp" => await RunTcpAsync(commandArgs, json),
                "ping" => await RunPingAsync(commandArgs, json),
                "iface" => RunIface(json),
                "nat" => await RunNatAsync(json),
                "firewall" => await RunFirewallAsync(commandArgs, json),
                _ => throw new UsageException($"Unknown command '{command}'."),
            };
        }
        catch (UsageException ex)
        {
            Console.Error.WriteLine($"Error: {ex.Message}");
            PrintUsageToStderr();
            return 2;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error: {ex.Message}");
            return 1;
        }
    }

    private static async Task<int> RunDnsAsync(string[] args, bool json)
    {
        var parsed = ArgParser.Parse(args, "type", "server", "timeout");
        string host = parsed.RequirePositional(0, "host");
        string typeText = parsed.Option("type", "A");
        if (!Enum.TryParse<DnsRecordType>(typeText, ignoreCase: true, out var type))
            throw new UsageException($"Unknown DNS record type '{typeText}'. Supported: A, AAAA, MX, TXT, CNAME, NS, SOA, PTR.");
        string server = parsed.Option("server", DnsClient.GetDefaultServer());
        int timeout = parsed.OptionInt("timeout", 3000);

        DnsQueryResult result = await DnsClient.QueryAsync(host, type, server, timeout);
        if (json)
            Output.WriteJson(new { command = "dns", result });
        else
            Output.PrintDns(result);
        return result.Error is null ? 0 : 1;
    }

    private static async Task<int> RunTcpAsync(string[] args, bool json)
    {
        var parsed = ArgParser.Parse(args, "timeout", "ports");
        string host = parsed.RequirePositional(0, "host");
        int timeout = parsed.OptionInt("timeout", TcpProbe.DefaultTimeoutMs);
        if (timeout <= 0)
            throw new UsageException("--timeout must be a positive number of milliseconds.");

        IReadOnlyList<TcpAttempt> attempts;
        if (parsed.HasOption("ports"))
        {
            if (parsed.Positionals.Count > 1)
                throw new UsageException("Give either a single port or --ports <start-end>, not both.");
            (int start, int end) = ParsePortRange(parsed.Option("ports", ""));
            attempts = await TcpProbe.ProbeRangeAsync(host, start, end, timeout);
        }
        else
        {
            string portText = parsed.RequirePositional(1, "port");
            if (!int.TryParse(portText, out int port) || port < 1 || port > 65535)
                throw new UsageException($"Invalid port '{portText}' (must be 1-65535).");
            attempts = new[] { await TcpProbe.ProbeAsync(host, port, timeout) };
        }

        if (json)
            Output.WriteJson(new { command = "tcp", host, attempts });
        else
            Output.PrintTcp(attempts);
        // A probe that ran is a success even if ports are closed: closed is data, not failure.
        return attempts.Any(a => a.Status == TcpPortStatus.Error) ? 1 : 0;
    }

    private static (int Start, int End) ParsePortRange(string text)
    {
        string[] parts = text.Split('-', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length != 2
            || !int.TryParse(parts[0], out int start)
            || !int.TryParse(parts[1], out int end)
            || start < 1 || end > 65535 || start > end)
            throw new UsageException($"Invalid port range '{text}' (expected <start>-<end>, both 1-65535, start <= end).");
        if (end - start + 1 > TcpProbe.MaxPortsPerRange)
            throw new UsageException($"Port range too large (maximum {TcpProbe.MaxPortsPerRange} ports).");
        return (start, end);
    }

    private static async Task<int> RunPingAsync(string[] args, bool json)
    {
        var parsed = ArgParser.Parse(args, "count", "timeout");
        string host = parsed.RequirePositional(0, "host");
        int count = parsed.OptionInt("count", PingProbe.DefaultCount);
        if (count < 1 || count > 100)
            throw new UsageException("--count must be between 1 and 100.");
        int timeout = parsed.OptionInt("timeout", PingProbe.DefaultTimeoutMs);
        if (timeout <= 0)
            throw new UsageException("--timeout must be a positive number of milliseconds.");

        PingResult result = await PingProbe.RunAsync(host, count, timeout);
        if (json)
            Output.WriteJson(new { command = "ping", result });
        else
            Output.PrintPing(result);
        // NotPermitted is a failure of the command itself, not of the network.
        return result.Overall == PingOutcome.NotPermitted ? 1 : 0;
    }

    private static int RunIface(bool json)
    {
        IReadOnlyList<InterfaceInfo> interfaces = InterfaceProbe.List();
        if (json)
            Output.WriteJson(new { command = "iface", interfaces });
        else
            Output.PrintInterfaces(interfaces);
        return 0;
    }

    private static async Task<int> RunNatAsync(bool json)
    {
        NatResult result = await NatProbe.RunAsync();
        if (json)
            Output.WriteJson(new { command = "nat", result });
        else
            Output.PrintNat(result);
        return 0;
    }

    private static async Task<int> RunFirewallAsync(string[] args, bool json)
    {
        var parsed = ArgParser.Parse(args, "timeout");
        int timeout = parsed.OptionInt("timeout", 3000);
        if (timeout <= 0)
            throw new UsageException("--timeout must be a positive number of milliseconds.");

        FirewallResult result = await FirewallProbe.RunAsync(timeout);
        if (json)
            Output.WriteJson(new { command = "firewall", result });
        else
            Output.PrintFirewall(result);
        return 0;
    }

    private static int PrintUsage(int exitCode)
    {
        Console.WriteLine(UsageText);
        return exitCode;
    }

    private static void PrintUsageToStderr() => Console.Error.WriteLine(UsageText);

    private const string UsageText = """
        netdiag 1.0.0 — cross-platform network diagnostics CLI

        Usage: netdiag [--json] <command> [options]

        Commands:
          dns <host> [--type A|AAAA|MX|TXT|CNAME|NS|SOA|PTR] [--server <dns-server>] [--timeout ms]
              Minimal DNS client over UDP (hand-rolled wire format), with CNAME chasing
              and a System.Net.Dns fallback. Default server: first nameserver in
              /etc/resolv.conf, otherwise 8.8.8.8.
          tcp <host> <port> [--timeout ms]
          tcp <host> --ports <start-end> [--timeout ms]
              TCP connect probe. Reports open / closed (refused) / filtered (timeout)
              / unreachable, with per-attempt latency.
          ping <host> [--count n] [--timeout ms]
              ICMP echo. Reports per-reply latency and loss. Needs raw ICMP privileges;
              if they are unavailable the failure is reported honestly.
          iface
              List network interfaces with addresses, gateways, DNS servers and status.
          nat
              Local addresses with RFC 1918 detection, public IP lookup, NAT assessment,
              and a local loopback listener reachability check.
          firewall [--timeout ms]
              Outbound TCP checks to well-known hosts/ports, plus the local listener
              check. Each result states what it proves and what it cannot prove.

        Global flags:
          --json     Machine-readable JSON output (every command).
          --help     Show this help.
          --version  Show the version.

        Exit codes: 0 success, 1 command failure, 2 usage error.
        """;
}

/// <summary>Minimal argument parser: positionals plus --option value / --option=value.</summary>
public sealed class ArgParser
{
    public IReadOnlyList<string> Positionals { get; }
    private readonly Dictionary<string, string> _options;

    private ArgParser(List<string> positionals, Dictionary<string, string> options)
    {
        Positionals = positionals;
        _options = options;
    }

    public static ArgParser Parse(string[] args, params string[] allowedOptions)
    {
        var positionals = new List<string>();
        var options = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var allowed = new HashSet<string>(allowedOptions, StringComparer.OrdinalIgnoreCase);

        for (int i = 0; i < args.Length; i++)
        {
            string arg = args[i];
            if (!arg.StartsWith("--", StringComparison.Ordinal))
            {
                positionals.Add(arg);
                continue;
            }
            string name;
            string? value;
            int equals = arg.IndexOf('=');
            if (equals >= 0)
            {
                name = arg[2..equals];
                value = arg[(equals + 1)..];
            }
            else
            {
                name = arg[2..];
                if (i + 1 < args.Length && !args[i + 1].StartsWith("--", StringComparison.Ordinal))
                    value = args[++i];
                else
                    value = "";
            }
            if (!allowed.Contains(name))
                throw new UsageException($"Unknown option '--{name}'.");
            options[name] = value;
        }
        return new ArgParser(positionals, options);
    }

    public bool HasOption(string name) => _options.ContainsKey(name);

    public string Option(string name, string defaultValue) =>
        _options.TryGetValue(name, out string? value) && value.Length > 0 ? value : defaultValue;

    public int OptionInt(string name, int defaultValue)
    {
        if (!_options.TryGetValue(name, out string? value) || value.Length == 0)
            return defaultValue;
        if (!int.TryParse(value, out int parsed))
            throw new UsageException($"Invalid integer for --{name}: '{value}'.");
        return parsed;
    }

    public string RequirePositional(int index, string name)
    {
        if (Positionals.Count <= index)
            throw new UsageException($"Missing required argument <{name}>.");
        return Positionals[index];
    }
}
