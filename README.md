# netdiag

<h1 align="center">netdiag</h1>

<p align="center">Cross-platform network diagnostics CLI in C# (.NET 8): DNS, TCP, ICMP, interfaces, NAT, and firewall checks.</p>

<p align="justify">netdiag is a single self-contained command-line tool for answering the everyday question "is the network broken, and if so, where?" It speaks the DNS wire protocol itself instead of shelling out to dig, measures every probe it runs, and is careful about what its results actually prove: a successful outbound connect proves that one destination is reachable, not that a firewall is open in general, and a loopback listener test proves local reachability only, never external reachability. Every number in this README was measured from a real run on the machine described below; nothing here is a benchmark claim, a projection, or a figure taken from another tool.</p>

## Contents

- [Architecture](#architecture)
- [Building and running](#building-and-running)
- [Command reference](#command-reference)
  - [dns](#dns)
  - [tcp](#tcp)
  - [ping](#ping)
  - [iface](#iface)
  - [nat](#nat)
  - [firewall](#firewall)
  - [JSON output](#json-output)
  - [Exit codes](#exit-codes)
- [Measured results](#measured-results)
- [Limitations](#limitations)
- [Testing](#testing)

## Architecture

<p align="justify">netdiag is a .NET 8 console application with no third-party runtime dependencies: the only NuGet packages in the tree belong to the xUnit test project. The program is split into one small class per concern, so each protocol can be read, tested, and reasoned about on its own. <code>Program.cs</code> owns argument parsing and exit codes and nothing else; <code>Output.cs</code> owns all rendering, human tables and JSON alike, so a probe never formats its own output.</p>

| File | Responsibility |
| --- | --- |
| `DnsWire.cs` | The DNS wire format by hand (RFC 1035): query construction, response parsing, compressed-name decoding with pointer-loop protection, and A / AAAA / CNAME / MX / TXT / SOA / NS / PTR record decoding. Throws `DnsParseException` on truncated or malformed packets. |
| `DnsClient.cs` | UDP DNS client with CNAME chasing (max 5 hops), two attempts per hop, and a fallback to `System.Net.Dns` that is used only when the hand-rolled client fails, and is reported as such in the result (`usedFallback`). The default server is the first nameserver in `/etc/resolv.conf` on Unix; on Windows there is no resolv.conf, so `8.8.8.8` is used unless `--server` is given. |
| `TcpProbe.cs` | TCP connect with a configurable timeout. Statuses are Open (connect completed), Closed (actively refused, RST), Filtered (no response within the timeout), Unreachable (ICMP error / no route), and Error. A port range is probed with at most 16 concurrent connects and results are returned in port order. The host is resolved first and each address is tried with a socket of the matching address family, so an IPv4 target is always probed with an IPv4 socket. |
| `PingProbe.cs` | ICMP echo via `System.Net.NetworkInformation.Ping`, with per-reply latency and loss percentage. When raw ICMP is not permitted it reports that honestly instead of faking replies. |
| `Interfaces.cs` | Interface enumeration via `System.Net.NetworkInformation`: addresses with prefix lengths, gateways, DNS servers, MAC addresses, and status. |
| `NatProbe.cs` | Local address classification (RFC 1918 private, link-local, loopback, CGNAT, unique-local, public), public-IP lookup over HTTPS with a short timeout, a NAT assessment, and a loopback listener check that states it proves local reachability only. |
| `FirewallProbe.cs` | Outbound TCP checks to well-known hosts and ports, plus the loopback listener check. Each result states what it proves, and the command carries an explicit list of what the checks cannot prove. |
| `Output.cs` | Human-readable tables and `--json` output (camelCase property names, indented, enums serialized as their names, e.g. `"Open"`, `"A"`). |

<p align="justify">The code uses only cross-platform .NET APIs. The single OS-specific branch is the DNS-server discovery in <code>DnsClient.GetDefaultServer</code>, guarded by <code>OperatingSystem.IsWindows()</code>; there are no shell-outs in the main paths, so the same binary runs on Linux, macOS, and Windows. The Windows paths have not been run here (see <a href="#limitations">Limitations</a>).</p>

## Building and running

<p align="justify">The project targets .NET 8 and builds with the SDK alone; no other tooling is required.</p>

```console
dotnet build
dotnet test
dotnet run --project src/netdiag -- dns google.com
```

<p align="justify">Or build once and run the binary directly:</p>

```console
dotnet build -c Release
./src/netdiag/bin/Release/net8.0/netdiag dns google.com
```

<p align="justify">All measurements in this README were taken on 24 November 2026 on a Linux sandbox with 4 vCPUs and the .NET 8.0.428 SDK, running the Debug build. Latencies are single-run measurements, not averages, and they vary run to run; the numbers below are the runs whose output is quoted verbatim.</p>

## Command reference

### dns

```console
netdiag dns <host> [--type A|AAAA|MX|TXT|CNAME|NS|SOA|PTR] [--server <dns-server>] [--timeout ms]
```

<p align="justify">Sends a DNS query built and parsed by hand over UDP, shows each answer with its type, TTL, and the query latency, and chases CNAME records for A queries (up to 5 hops). If the hand-rolled client fails, it falls back to <code>System.Net.Dns</code> and says so in the output.</p>

```console
$ netdiag dns google.com
DNS A query for google.com via 198.19.0.1
Latency: 41.0 ms

Name        Type  TTL  Data
------------------------------------
google.com  A     15   198.18.102.23
```

```console
$ netdiag dns www.github.com
DNS A query for www.github.com via 198.19.0.1
Latency: 35.8 ms

Name            Type  TTL  Data
----------------------------------------
www.github.com  A     15   198.18.102.24
```

<p align="justify">A query the server cannot answer returns an honest NODATA result rather than an empty success. In the sandbox where these runs were taken, the DNS proxy answers A records only; MX, AAAA, TXT, and CNAME queries all return NODATA there, so the live parsing of those record types is verified by unit tests against hand-built packets, not by live queries (see <a href="#limitations">Limitations</a>).</p>

```console
$ netdiag dns google.com --type MX
DNS MX query for google.com via 198.19.0.1
Latency: 36.4 ms
Error: No answer records returned (NODATA).
```

### tcp

```console
netdiag tcp <host> <port> [--timeout ms]
netdiag tcp <host> --ports <start-end> [--timeout ms]
```

<p align="justify">Connects with a configurable timeout (default 2000 ms) and reports Open, Closed (refused), Filtered (timeout), Unreachable, or Error, with per-attempt latency. A range is limited to 1024 ports and probed with at most 16 concurrent connects.</p>

```console
$ netdiag tcp google.com 443
Host        Port  Status  Latency  Detail
-----------------------------------------
google.com  443   Open    13.1 ms  -

1 of 1 port(s) open.
```

```console
$ netdiag tcp 127.0.0.1 18081
Host       Port   Status  Latency  Detail
------------------------------------------------------------
127.0.0.1  18081  Closed  33.8 ms  Connection refused (RST).

0 of 1 port(s) open.
```

```console
$ netdiag tcp 127.0.0.1 --ports 79-82
Host       Port  Status  Latency  Detail
-----------------------------------------------------------
127.0.0.1  79    Closed  34.2 ms  Connection refused (RST).
127.0.0.1  80    Closed  32.9 ms  Connection refused (RST).
127.0.0.1  81    Closed  34.2 ms  Connection refused (RST).
127.0.0.1  82    Closed  34.2 ms  Connection refused (RST).

0 of 4 port(s) open.
```

### ping

```console
netdiag ping <host> [--count n] [--timeout ms]
```

<p align="justify">ICMP echo with per-reply latency and a loss percentage. Raw ICMP needs privileges; where they are unavailable the command reports the failure instead of inventing replies. In the sandbox where these runs were taken, ICMP echo packets are dropped and the system <code>ping</code> fails with "socket: Operation not permitted", so this is what a run looks like there:</p>

```console
$ netdiag ping 127.0.0.1 --count 2
Pinging 127.0.0.1 (2 echo request(s))
Reply 1: timed out
Reply 2: timed out

Loss: 100%
```

### iface

```console
netdiag iface
```

<p align="justify">Lists every network interface with its addresses (and prefix lengths), gateways, DNS servers, MAC address, and status. Output below is from the sandbox where these runs were taken; it has two interfaces, loopback and one Ethernet interface.</p>

```console
$ netdiag iface
lo  [Loopback]  Up
  Description: lo
  MAC:         00:00:00:00:00:00
  Address:     127.0.0.1/8
  Address:     ::1/128
  DNS server:  198.19.0.1
  DNS server:  fd8b:4f84:7d32:99::1

host0  [Ethernet]  Up
  Description: host0
  MAC:         72:DC:7C:34:2F:FD
  Address:     198.19.0.2/30
  Address:     fd8b:4f84:7d32:99::2/64
  Address:     fe80::70dc:7cff:fe34:2ffd%2/64
  Gateway:     198.19.0.1
  Gateway:     fd8b:4f84:7d32:99::1
  DNS server:  198.19.0.1
  DNS server:  fd8b:4f84:7d32:99::1
```

### nat

```console
netdiag nat
```

<p align="justify">Classifies each local address (RFC 1918 private, link-local, loopback, CGNAT, unique-local, public), looks up the machine's public IP over HTTPS with a short timeout, gives a NAT assessment, and runs a loopback listener check. The listener check binds an ephemeral port, connects to it from localhost, and reports success; the output states explicitly that this proves local reachability only, not external reachability.</p>

```console
$ netdiag nat
Local addresses:
Interface  Address                      Classification
------------------------------------------------------
lo         127.0.0.1                    Loopback
lo         ::1                          Loopback
host0      198.19.0.2                   Public
host0      fd8b:4f84:7d32:99::2         Unique-local
host0      fe80::70dc:7cff:fe34:2ffd%2  Link-local

Public IP: 104.29.194.187 (via https://api.ipify.org)
NAT assessment: Unclear: the public IP differs from every local address, but no private address was found.

Listener reachability check:
  Succeeded on 127.0.0.1:40983
  Local loopback listener accepted a connection. This proves local reachability only, NOT external reachability.
```

<p align="justify">Two things in that output are worth explaining. The local address 198.19.0.2 sits in 198.18.0.0/15, the benchmarking range, which is not RFC 1918 space, so the classifier calls it Public; the assessment then honestly reports Unclear rather than claiming NAT, because the public IP differs from every local address while no private address was found. And the public IP itself varies run to run in this sandbox (104.29.200.165 on one run, 104.29.194.187 on the next) because the sandbox's egress rotates addresses; the address quoted above is the one returned for that run, not a stable property of the machine.</p>

### firewall

```console
netdiag firewall [--timeout ms]
```

<p align="justify">Attempts outbound TCP connects to five well-known destinations, then runs the same loopback listener check as <code>nat</code>. Each result states what it proves, and the command ends with an explicit list of what the checks cannot prove.</p>

```console
$ netdiag firewall
Outbound checks:
Check              Target                          Status  Latency
------------------------------------------------------------------
Google Public DNS  8.8.8.8:53 (8.8.8.8)            Open    29.6 ms
Cloudflare DNS     1.1.1.1:53 (1.1.1.1)            Open    0.6 ms
Google HTTPS       google.com:443 (198.18.102.23)  Open    0.3 ms
Example HTTP       example.com:80 (198.18.102.25)  Open    0.1 ms
GitHub HTTPS       github.com:443 (198.18.102.27)  Open    0.1 ms

- Google Public DNS: Outbound TCP to 8.8.8.8:53 is permitted from this machine (for this destination).
- Cloudflare DNS: Outbound TCP to 1.1.1.1:53 is permitted from this machine (for this destination).
- Google HTTPS: Outbound TCP to google.com:443 is permitted from this machine (for this destination).
- Example HTTP: Outbound TCP to example.com:80 is permitted from this machine (for this destination).
- GitHub HTTPS: Outbound TCP to github.com:443 is permitted from this machine (for this destination).

Listener reachability check:
  Succeeded on 127.0.0.1:37297
  Local loopback listener accepted a connection. This proves local reachability only, NOT external reachability.

Limitations:
- These checks test outbound TCP connectivity to specific destinations. A success proves that destination and port are reachable from here; it does not prove other destinations or ports are open.
- They say nothing about inbound connectivity: they cannot prove that a port on this machine is reachable from the internet or from other hosts.
- A failure cannot distinguish a firewall block from the remote host being down, the network being unreachable, or DNS failing.
- DNS-based targets depend on DNS resolution succeeding first; a DNS failure is reported as such, not as a firewall block.
- No packet inspection is performed: these checks do not verify what a firewall allows in general, only these five connections.
```

<p align="justify">Read the latencies above with the sandbox in mind: the three hostname targets resolve to synthesized 198.18.x.x addresses handed out by the sandbox DNS proxy, and the sub-millisecond connects to them measure the sandbox's own path, not the public internet. The 8.8.8.8:53 check is the one literal-IP target that traverses the sandbox's egress proxy, at 29.6 ms on this run.</p>

### JSON output

<p align="justify">Every command accepts a global <code>--json</code> flag that switches the output to machine-readable JSON (camelCase property names, indented, enums as their names). The JSON carries the same data as the human tables, including the resolved IP for TCP attempts and the <code>usedFallback</code> flag for DNS.</p>

```console
$ netdiag dns google.com --json
{
  "command": "dns",
  "result": {
    "name": "google.com",
    "type": "A",
    "server": "198.19.0.1",
    "usedFallback": false,
    "answers": [
      {
        "name": "google.com",
        "type": "A",
        "ttl": 15,
        "data": "198.18.121.47"
      }
    ],
    "latencyMs": 82.1346,
    "error": null,
    "note": null
  }
}
```

```console
$ netdiag tcp google.com 443 --json
{
  "command": "tcp",
  "host": "google.com",
  "attempts": [
    {
      "host": "google.com",
      "port": 443,
      "status": "Open",
      "latencyMs": 12.8628,
      "detail": null,
      "resolvedIp": "198.18.102.23"
    }
  ]
}
```

<p align="justify">Note that the synthesized DNS answer differs between the two runs quoted here (198.18.121.47 in the JSON run, 198.18.102.23 in the human-readable run): the sandbox proxy hands out a fresh synthesized address per query, so the address and the latency vary run to run and neither is a stable property of google.com.</p>

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success (including `--help` and `--version`). |
| 1 | The command ran and failed (for example a DNS query that errored, or a ping with 100% loss). |
| 2 | Usage error (unknown command or option, missing argument). |

<p align="justify">Verified on this machine: <code>netdiag badcommand</code> exits 2, <code>netdiag dns google.com</code> exits 0, and <code>netdiag --version</code> prints <code>netdiag 1.0.0</code> and exits 0.</p>

## Measured results

<p align="justify">All figures below come from the runs quoted in the command reference, taken 24 November 2026 on a Linux sandbox with 4 vCPUs and the .NET 8.0.428 SDK. They are single-run measurements, not averages or benchmarks, and the sandbox's network interception (see <a href="#limitations">Limitations</a>) shapes several of them. The build is clean: <code>dotnet build</code> reports 0 warnings and 0 errors, and the test suite is 42 tests, all passing (see <a href="#testing">Testing</a>).</p>

| Probe | Result | Latency (this run) |
| --- | --- | --- |
| DNS A, google.com via 198.19.0.1 | 1 answer, TTL 15 | 41.0 ms |
| DNS A, www.github.com via 198.19.0.1 | 1 answer, TTL 15 | 35.8 ms |
| DNS MX, google.com | NODATA (sandbox proxy answers A only) | 36.4 ms |
| TCP google.com:443 | Open | 13.1 ms |
| TCP 127.0.0.1:18081 | Closed (refused) | 33.8 ms |
| TCP 127.0.0.1 ports 79–82 | All 4 closed (refused) | 32.9–34.2 ms |
| ICMP 127.0.0.1, 2 echo requests | 100% loss, both replies timed out | — |
| NAT public IP via api.ipify.org | 104.29.194.187 (varies per run) | — |
| Firewall 8.8.8.8:53 | Open | 29.6 ms |
| Firewall 1.1.1.1:53 | Open | 0.6 ms |
| Firewall google.com:443 | Open | 0.3 ms |
| Firewall example.com:80 | Open | 0.1 ms |
| Firewall github.com:443 | Open | 0.1 ms |

## Limitations

<p align="justify">netdiag reports what it can measure and says so when it cannot. The limits below are properties of the tool, the environment it was verified in, or both, and they are stated here rather than hidden.</p>

<p align="justify"><b>ICMP needs privileges.</b> Sending ICMP echo requires raw sockets. Where the process lacks that privilege, <code>ping</code> reports the failure (or, as in the sandbox here, 100% loss when packets are dropped) instead of inventing replies. The sandbox used for verification blocks raw ICMP sockets entirely: a plain Python raw-socket open fails with <code>EPERM</code> and the system <code>ping</code> fails with "socket: Operation not permitted". A successful ping on a normal machine has not been observed here; the success path is covered by the probe's design and by the test that accepts either outcome, not by a live run.</p>

<p align="justify"><b>The sandbox answers DNS itself.</b> The sandbox's resolver (198.19.0.1) answers A records only, synthesizing a fresh 198.18.x.x address per query, and returns NODATA for AAAA, MX, TXT, and CNAME. It also answers every well-formed name, including names that do not exist. Live A-record queries and the hand-rolled wire-format parsing are verified end to end against that resolver; live parsing of AAAA, MX, TXT, and CNAME answers is verified only by unit tests against hand-built response packets. The sandbox also blocks all UDP sends except to its DNS proxy, so a local UDP test server cannot reply here.</p>

<p align="justify"><b>The sandbox intercepts outbound TCP.</b> Every non-loopback TCP connect in the sandbox is accepted by the egress proxy (198.19.0.1:3128), so <code>tcp</code> and <code>firewall</code> report Open for any non-loopback destination, including the documentation-only TEST-NET-1 address 192.0.2.1. Loopback results are unaffected: a closed loopback port correctly reports Closed, and an open loopback listener correctly reports Open. On a normal network, an unroutable address reports Filtered or Unreachable as designed. Relatedly, the sandbox redirects TCP connects made through dual-mode IPv6 sockets to IPv4-mapped addresses, which is why the TCP probe resolves the host first and connects with a socket of the matching address family; that also fixed an early bug where every loopback port reported Open.</p>

<p align="justify"><b>NAT detection is an assessment, not a proof.</b> netdiag compares the machine's local addresses with the public IP seen by an external service. That can show the machine is behind NAT (a private local address and a different public IP) or that it is not (a public local address equal to the public IP), but when neither pattern holds, as in the sandbox here, the assessment is honestly Unclear. It cannot detect carrier-grade NAT, double NAT, or a NAT whose public address happens to match a local one, and it says nothing about inbound reachability.</p>

<p align="justify"><b>The firewall check is outbound-only and narrow.</b> It tests five specific destinations. A success proves that destination and port are reachable from this machine; it proves nothing about other destinations, other ports, inbound connectivity, or what a firewall allows in general. A failure cannot distinguish a firewall block from the remote host being down, the network being unreachable, or DNS failing. The loopback listener check proves local reachability only.</p>

<p align="justify"><b>Windows paths are untested here.</b> The code is written to work on Windows — the only OS-specific branch is DNS-server discovery, which returns 8.8.8.8 on Windows instead of reading /etc/resolv.conf — but no Windows run has been done, so Windows behavior is designed, not verified. The same applies to macOS.</p>

<p align="justify"><b>What the numbers are not.</b> The latencies in this README are single-run measurements on one sandbox, taken while nothing else was running, and several of them measure the sandbox's own proxy path rather than the public internet. They are not benchmarks, not averages, and not comparable across machines.</p>

## Testing

<p align="justify">The test suite is xUnit, in <code>tests/netdiag.Tests</code>, and it passes in full: <b>42 tests, 0 failures</b>, run 24 November 2026 on the Linux sandbox above with the .NET 8.0.428 SDK. Coverage is:</p>

- **DNS wire format** (12 tests): query construction, A, AAAA, CNAME, MX, and TXT answers, multiple answers, NXDOMAIN, a truncated packet, a wrong transaction ID, truncated RDATA, and a compression-pointer loop, all against hand-built response packets.
- **TCP probe** (5 tests): open port against a real local `TcpListener`, closed port, range probing in port order, an unroutable address that must return quickly without reporting Open, and an invalid hostname that returns Error instead of throwing.
- **Argument parsing** (6 tests) and **output formatting** (4 tests), including JSON serialization of TCP attempts and DNS results with the same options the CLI uses, and the firewall limitations list being non-empty.
- **Interfaces, ping, and NAT** (15 tests): interface enumeration returns at least loopback and every interface has a name and status, ping either succeeds or reports its privilege/timeout failure honestly, NAT classification across 10 address cases, the loopback listener check, and the public-IP lookup never throwing when offline.

<p align="justify">Two environment notes belong here. First, <code>dotnet test</code> in this sandbox needs <code>DOTNET_SYSTEM_NET_DISABLEIPV6=true</code>: the testhost connects back to vstest over loopback TCP, and without that setting its dual-mode IPv6 socket is redirected to the sandbox egress proxy, so vstest reports "failed to connect to testhost process". That setting is a property of this sandbox, not of the project; on a normal machine plain <code>dotnet test</code> works. Second, two tests are written to tolerate this sandbox's network interception: the unroutable-address test asserts the probe returns within its timeout and only asserts "not Open" when the environment does not intercept the connect, and the invalid-hostname test uses a name that getaddrinfo rejects before any DNS query, because the sandbox DNS proxy answers every well-formed name. Both cases are commented in the test source.</p>
