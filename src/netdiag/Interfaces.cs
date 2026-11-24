using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace NetDiag;

/// <summary>One network interface and its addresses, gateways and DNS servers.</summary>
public sealed record InterfaceInfo(
    string Name,
    string Description,
    string Type,
    string Status,
    string MacAddress,
    IReadOnlyList<string> Addresses,
    IReadOnlyList<string> Gateways,
    IReadOnlyList<string> DnsServers);

/// <summary>Interface enumeration via System.Net.NetworkInformation (cross-platform).</summary>
public static class InterfaceProbe
{
    public static IReadOnlyList<InterfaceInfo> List()
    {
        var result = new List<InterfaceInfo>();
        foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            IPInterfaceProperties props = nic.GetIPProperties();
            var addresses = props.UnicastAddresses
                .Select(a => $"{a.Address}/{PrefixLength(a)}")
                .ToList();
            var gateways = props.GatewayAddresses
                .Select(g => g.Address.ToString())
                .ToList();
            var dns = props.DnsAddresses
                .Select(d => d.ToString())
                .ToList();
            result.Add(new InterfaceInfo(
                nic.Name,
                nic.Description,
                nic.NetworkInterfaceType.ToString(),
                nic.OperationalStatus.ToString(),
                FormatMac(nic.GetPhysicalAddress()),
                addresses,
                gateways,
                dns));
        }
        return result;
    }

    private static int PrefixLength(UnicastIPAddressInformation address)
    {
        // PrefixLength is not populated on every platform; fall back to the IPv4 mask.
        if (address.PrefixLength > 0)
            return address.PrefixLength;
        if (address.Address.AddressFamily == AddressFamily.InterNetwork && address.IPv4Mask is not null)
        {
            byte[] mask = address.IPv4Mask.GetAddressBytes();
            return mask.Sum(b => System.Numerics.BitOperations.PopCount(b));
        }
        return address.Address.AddressFamily == AddressFamily.InterNetworkV6 ? 128 : 0;
    }

    private static string FormatMac(PhysicalAddress mac)
    {
        byte[] bytes = mac.GetAddressBytes();
        return bytes.Length == 0 ? "-" : string.Join(":", bytes.Select(b => b.ToString("X2")));
    }
}
