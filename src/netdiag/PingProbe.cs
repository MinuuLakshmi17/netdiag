using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace NetDiag;

/// <summary>What one ICMP echo request concluded.</summary>
public enum PingOutcome
{
    Success,
    Timeout,
    Unreachable,
    /// <summary>ICMP could not be used at all (raw sockets need privileges this process lacks).</summary>
    NotPermitted,
    Error,
}

/// <summary>One ICMP echo reply (or its failure).</summary>
public sealed record PingReply(int Sequence, PingOutcome Outcome, double? LatencyMs, string? Detail);

/// <summary>Result of one <c>ping</c> command invocation.</summary>
public sealed record PingResult(
    string Host,
    IReadOnlyList<PingReply> Replies,
    double LossPercent,
    double? AverageLatencyMs,
    PingOutcome Overall,
    string? Note);

/// <summary>
/// ICMP echo via <see cref="Ping"/>. On Linux this needs a raw socket (CAP_NET_RAW);
/// when the process lacks the privilege the failure is reported honestly instead of
/// faking replies.
/// </summary>
public static class PingProbe
{
    public const int DefaultCount = 4;
    public const int DefaultTimeoutMs = 1000;

    public static async Task<PingResult> RunAsync(string host, int count = DefaultCount, int timeoutMs = DefaultTimeoutMs)
    {
        var replies = new List<PingReply>();
        using var ping = new Ping();
        for (int i = 1; i <= count; i++)
        {
            var stopwatch = Stopwatch.StartNew();
            try
            {
                System.Net.NetworkInformation.PingReply reply = await ping.SendPingAsync(host, timeoutMs);
                stopwatch.Stop();
                replies.Add(reply.Status switch
                {
                    IPStatus.Success => new PingReply(i, PingOutcome.Success, reply.RoundtripTime, null),
                    IPStatus.TimedOut => new PingReply(i, PingOutcome.Timeout, null, "Request timed out."),
                    IPStatus.DestinationHostUnreachable or IPStatus.DestinationNetworkUnreachable
                        => new PingReply(i, PingOutcome.Unreachable, null, reply.Status.ToString()),
                    _ => new PingReply(i, PingOutcome.Error, null, reply.Status.ToString()),
                });
            }
            catch (PingException ex) when (IsPermissionError(ex))
            {
                // Raw ICMP sockets require privileges this process does not have.
                // Report it once and stop: further attempts would fail the same way.
                stopwatch.Stop();
                return new PingResult(host, replies, 100, null, PingOutcome.NotPermitted,
                    "ICMP is not permitted in this environment: sending raw ICMP packets requires " +
                    "elevated privileges (CAP_NET_RAW on Linux, administrator on Windows). " +
                    "Run as root/administrator or grant the capability. No replies were faked.");
            }
            catch (PingException ex)
            {
                stopwatch.Stop();
                replies.Add(new PingReply(i, PingOutcome.Error, null, ex.Message));
            }
        }

        int lost = replies.Count(r => r.Outcome != PingOutcome.Success);
        double loss = replies.Count == 0 ? 100 : 100.0 * lost / replies.Count;
        var latencies = replies.Where(r => r.LatencyMs.HasValue).Select(r => r.LatencyMs!.Value).ToList();
        PingOutcome overall = replies.Count == 0 ? PingOutcome.Error
            : replies.Any(r => r.Outcome == PingOutcome.Success) ? PingOutcome.Success
            : replies[0].Outcome;
        return new PingResult(host, replies, loss,
            latencies.Count > 0 ? latencies.Average() : null, overall, null);
    }

    private static bool IsPermissionError(PingException ex)
    {
        if (ex.InnerException is SocketException socket)
        {
            // EPERM (1) / EACCES (13) surface as AccessDenied on .NET.
            return socket.SocketErrorCode == SocketError.AccessDenied
                || (int)socket.SocketErrorCode == 1
                || (int)socket.SocketErrorCode == 13;
        }
        return ex.InnerException is UnauthorizedAccessException;
    }
}
