using System;
using System.Collections.Generic;
using System.Net;
using System.Text;

namespace NetScope
{
    sealed class Packet
    {
        public int Number, WireLength, Version, SourcePort, DestinationPort, Pid, TcpFlags;
        public int PeerPid;
        public DateTimeOffset Time;
        public byte[] Bytes;
        public string Source = "", Destination = "", Transport = "", Application = "", Info = "";
        public string Flow, ProcessName = "";
        public readonly List<Layer> Layers = new List<Layer>();

        public string Protocol => Application != "" ? Application :
            Transport != "" ? Transport : Version != 0 ? "IPv" + Version :
            Layers.Count != 0 ? Layers[Layers.Count - 1].Name : "未知";
        public string ProcessLabel => Pid == 0 ? "" : ProcessName == "" ? Pid.ToString() : ProcessName + " (" + Pid + ")";
        public bool HasOwner(int pid) => pid == Pid || pid == PeerPid;

        public static string Endpoint(string address, int port) =>
            (address.Contains(":") ? "[" + address + "]" : address) + ":" + port;

        public static string FlowKey(string a, string b) =>
            string.CompareOrdinal(a, b) <= 0 ? a + " / " + b : b + " / " + a;
    }

    sealed class Layer
    {
        public readonly string Name;
        public readonly int Offset, Length;
        public readonly List<string> Fields = new List<string>();

        public Layer(Packet packet, string name, int offset, int length)
        {
            Name = name;
            Offset = offset;
            Length = length;
            packet.Layers.Add(this);
        }

        public void Add(string key, object value) => Fields.Add(key + "  " + value);
    }

    static class PacketDecoder
    {
        public static bool Supports(int link) => link == 1 || link == 0 || link == 101 || link == 12;

        public static Packet Decode(byte[] bytes, int link, DateTimeOffset time, int wireLength)
        {
            var packet = new Packet { Bytes = bytes, Time = time, WireLength = wireLength };
            int offset = 0;
            int type;
            switch (link)
            {
                case 1:
                    if (bytes.Length < 14) return Short(packet, "Ethernet II");
                    packet.Source = Mac(bytes, 6);
                    packet.Destination = Mac(bytes, 0);
                    type = U16(bytes, 12);
                    var ethernet = new Layer(packet, "Ethernet II", 0, 14);
                    ethernet.Add("源 MAC", packet.Source);
                    ethernet.Add("目的 MAC", packet.Destination);
                    ethernet.Add("EtherType", "0x" + type.ToString("X4"));
                    offset = 14;
                    while (type == 0x8100 || type == 0x88A8)
                    {
                        if (bytes.Length - offset < 4) return Short(packet, "VLAN");
                        var vlan = new Layer(packet, "VLAN", offset, 4);
                        vlan.Add("VLAN ID", U16(bytes, offset) & 0xfff);
                        type = U16(bytes, offset + 2);
                        vlan.Add("内部 EtherType", "0x" + type.ToString("X4"));
                        offset += 4;
                    }
                    break;
                case 0:
                    if (bytes.Length < 4) return Short(packet, "回环");
                    var loop = new Layer(packet, "回环", 0, 4);
                    int family = BitConverter.ToInt32(bytes, 0);
                    if (family > 255 || family < 0)
                        family = unchecked((int)U32(bytes, 0));
                    loop.Add("地址族", family);
                    type = family == 2 ? 0x0800 :
                        family == 10 || family == 23 || family == 24 || family == 28 || family == 30 ? 0x86DD : 0;
                    offset = 4;
                    break;
                case 12:
                case 101:
                    if (bytes.Length == 0) return Short(packet, "IP");
                    int version = bytes[0] >> 4;
                    type = version == 4 ? 0x0800 : version == 6 ? 0x86DD : 0;
                    break;
                default:
                    packet.Info = "链路类型 " + link;
                    return packet;
            }

            switch (type)
            {
                case 0x0800: IPv4(packet, offset); break;
                case 0x86DD: IPv6(packet, offset); break;
                case 0x0806: Arp(packet, offset); break;
                default: packet.Info = "未解析的网络层协议"; break;
            }
            return packet;
        }

        static void IPv4(Packet p, int start)
        {
            var b = p.Bytes;
            if (b.Length - start < 20) { Short(p, "IPv4"); return; }
            int header = (b[start] & 15) * 4;
            int total = U16(b, start + 2);
            if ((b[start] >> 4) != 4 || header < 20 || header > total || header > b.Length - start)
            { Short(p, "IPv4"); return; }

            p.Version = 4;
            p.Source = Ip(b, start + 12, 4);
            p.Destination = Ip(b, start + 16, 4);
            int fragment = U16(b, start + 6);
            int next = b[start + 9];
            var layer = new Layer(p, "IPv4", start, header);
            layer.Add("源地址", p.Source);
            layer.Add("目的地址", p.Destination);
            layer.Add("首部长度 / 总长度", header + " / " + total);
            layer.Add("标识", U16(b, start + 4));
            layer.Add("TTL / 协议号", b[start + 8] + " / " + next);
            layer.Add("分片偏移 / MF", ((fragment & 0x1fff) * 8) + " 字节 / " + ((fragment >> 13) & 1));
            if ((fragment & 0x1fff) != 0) { p.Info = "IPv4 后续分片"; return; }
            Transport(p, start + header, Math.Min(b.Length, start + total), next, (fragment & 0x2000) != 0);
        }

        static void IPv6(Packet p, int start)
        {
            var b = p.Bytes;
            if (b.Length - start < 40 || (b[start] >> 4) != 6) { Short(p, "IPv6"); return; }
            int payload = U16(b, start + 4);
            int next = b[start + 6];
            int end = Math.Min(b.Length, start + 40 + payload);
            p.Version = 6;
            p.Source = Ip(b, start + 8, 16);
            p.Destination = Ip(b, start + 24, 16);
            var layer = new Layer(p, "IPv6", start, 40);
            layer.Add("源地址", p.Source);
            layer.Add("目的地址", p.Destination);
            layer.Add("载荷长度", payload);
            layer.Add("下一首部 / 跳数限制", next + " / " + b[start + 7]);

            int offset = start + 40;
            bool fragmented = false;
            while (next == 0 || next == 43 || next == 44 || next == 51 || next == 60)
            {
                if (end - offset < 2) { Short(p, "IPv6 扩展头"); return; }
                int length = next == 44 ? 8 : next == 51 ? (b[offset + 1] + 2) * 4 : (b[offset + 1] + 1) * 8;
                if (end - offset < length) { Short(p, "IPv6 扩展头"); return; }
                var extension = new Layer(p, "IPv6 扩展头 (" + next + ")", offset, length);
                extension.Add("下一首部 / 长度", b[offset] + " / " + length);
                if (next == 44)
                {
                    int fragment = U16(b, offset + 2);
                    extension.Add("分片偏移 / M", (fragment & 0xfff8) + " 字节 / " + (fragment & 1));
                    extension.Add("分片标识", U32(b, offset + 4));
                    if ((fragment & 0xfff8) != 0) { p.Info = "IPv6 后续分片"; return; }
                    fragmented |= (fragment & 1) != 0;
                }
                next = b[offset];
                offset += length;
            }
            Transport(p, offset, end, next, fragmented);
        }

        static void Transport(Packet p, int start, int end, int next, bool fragmented)
        {
            var b = p.Bytes;
            int length = end - start;
            switch (next)
            {
                case 6:
                    p.Transport = "TCP";
                    if (length < 20) { Short(p, "TCP"); return; }
                    int header = (b[start + 12] >> 4) * 4;
                    if (header < 20 || header > length) { Short(p, "TCP"); return; }
                    p.SourcePort = U16(b, start);
                    p.DestinationPort = U16(b, start + 2);
                    p.Flow = Packet.FlowKey(Packet.Endpoint(p.Source, p.SourcePort), Packet.Endpoint(p.Destination, p.DestinationPort));
                    p.TcpFlags = b[start + 13];
                    var flags = TcpFlags(p.TcpFlags);
                    var tcp = new Layer(p, "TCP", start, header);
                    tcp.Add("源端口 / 目的端口", p.SourcePort + " / " + p.DestinationPort);
                    tcp.Add("序列号", U32(b, start + 4));
                    tcp.Add("确认号", U32(b, start + 8));
                    tcp.Add("首部长度 / 标志", header + " / " + flags);
                    tcp.Add("窗口", U16(b, start + 14));
                    tcp.Add("载荷长度（捕获）", length - header);
                    p.Info = p.SourcePort + " → " + p.DestinationPort + "  [" + flags + "]  Len=" + (length - header);
                    if (!fragmented) Http(p, start + header, end);
                    break;
                case 17:
                    p.Transport = "UDP";
                    if (length < 8) { Short(p, "UDP"); return; }
                    p.SourcePort = U16(b, start);
                    p.DestinationPort = U16(b, start + 2);
                    int udpLength = U16(b, start + 4);
                    var udp = new Layer(p, "UDP", start, 8);
                    udp.Add("源端口 / 目的端口", p.SourcePort + " / " + p.DestinationPort);
                    udp.Add("长度", udpLength);
                    udp.Add("校验和", "0x" + U16(b, start + 6).ToString("X4"));
                    p.Info = p.SourcePort + " → " + p.DestinationPort + "  Len=" + udpLength;
                    break;
                case 1 when p.Version == 4:
                case 58 when p.Version == 6:
                    p.Transport = next == 1 ? "ICMP" : "ICMPv6";
                    if (length < 4) { Short(p, p.Transport); return; }
                    int type = b[start];
                    int code = b[start + 1];
                    string echo = type == (next == 1 ? 8 : 128) ? "Echo Request" :
                                  type == (next == 1 ? 0 : 129) ? "Echo Reply" : null;
                    var icmp = new Layer(p, p.Transport, start, length);
                    icmp.Add("类型 / 代码", type + " / " + code);
                    icmp.Add("校验和", "0x" + U16(b, start + 2).ToString("X4"));
                    if (echo != null && length >= 8)
                        icmp.Add("标识 / 序号", U16(b, start + 4) + " / " + U16(b, start + 6));
                    p.Info = echo ?? ("Type=" + type + " Code=" + code);
                    break;
                default:
                    p.Info = next == 59 && p.Version == 6 ? "无下一首部" : "IP 协议号 " + next;
                    break;
            }
        }

        static void Http(Packet p, int start, int end)
        {
            var b = p.Bytes;
            int limit = Math.Min(end, start + 8192);
            int lineEnd = FindLineEnd(b, start, limit);
            if (lineEnd < 0 || lineEnd == start) return;
            for (int i = start; i < lineEnd; i++)
                if (b[i] < 0x20 || b[i] > 0x7e) return;

            string line = Encoding.ASCII.GetString(b, start, lineEnd - start);
            var parts = line.Split(new[] { ' ' }, 3);
            if (parts.Length != 3) return;
            bool response = IsHttpVersion(parts[0]) && parts[1].Length == 3 &&
                int.TryParse(parts[1], out int status) && status >= 100 && status <= 599;
            bool request = IsHttpVersion(parts[2]) && parts[1].Length != 0 &&
                Array.IndexOf(HttpMethods, parts[0]) >= 0;
            if (!response && !request) return;

            p.Application = "HTTP";
            p.Info = line;
            var layer = new Layer(p, "HTTP/1.x", start, end - start);
            layer.Add(response ? "状态行" : "请求行", line);
            int offset = lineEnd + 2;
            for (int i = 0; i < 32 && offset < limit; i++)
            {
                lineEnd = FindLineEnd(b, offset, limit);
                if (lineEnd <= offset) break;
                layer.Fields.Add(Encoding.ASCII.GetString(b, offset, lineEnd - offset));
                offset = lineEnd + 2;
            }
        }

        static readonly string[] HttpMethods =
            { "GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "CONNECT", "TRACE" };

        static bool IsHttpVersion(string text) => text == "HTTP/1.0" || text == "HTTP/1.1";

        static int FindLineEnd(byte[] bytes, int start, int end)
        {
            for (int i = start; i + 1 < end; i++)
            {
                if (bytes[i] == 13 && bytes[i + 1] == 10) return i;
                if (bytes[i] < 0x20 && bytes[i] != 9) break;
            }
            return -1;
        }

        static void Arp(Packet p, int start)
        {
            var b = p.Bytes;
            if (b.Length - start < 8) { Short(p, "ARP"); return; }
            int hardwareLength = b[start + 4];
            int protocolLength = b[start + 5];
            int size = 8 + 2 * (hardwareLength + protocolLength);
            if (b.Length - start < size) { Short(p, "ARP"); return; }
            p.Transport = "ARP";
            int operation = U16(b, start + 6);
            var arp = new Layer(p, "ARP", start, size);
            arp.Add("操作码", operation);
            if (U16(b, start) == 1 && U16(b, start + 2) == 0x0800 && hardwareLength == 6 && protocolLength == 4)
            {
                p.Source = Ip(b, start + 14, 4);
                p.Destination = Ip(b, start + 24, 4);
                arp.Add("发送端", Mac(b, start + 8) + " / " + p.Source);
                arp.Add("目标端", Mac(b, start + 18) + " / " + p.Destination);
                p.Info = operation == 1 ? "Who has " + p.Destination + "? Tell " + p.Source :
                    operation == 2 ? p.Source + " is at " + Mac(b, start + 8) : "操作码 " + operation;
            }
            else p.Info = "操作码 " + operation;
        }

        static Packet Short(Packet p, string name)
        {
            p.Info = name + " 首部不完整或无效";
            return p;
        }

        static string TcpFlags(int flags)
        {
            string[] names = { "FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR" };
            var set = new List<string>();
            for (int bit = 0; bit < names.Length; bit++)
                if ((flags & (1 << bit)) != 0) set.Add(names[bit]);
            return string.Join(", ", set);
        }

        static int U16(byte[] b, int i) => (b[i] << 8) | b[i + 1];
        static uint U32(byte[] b, int i) => ((uint)U16(b, i) << 16) | (uint)U16(b, i + 2);
        static string Mac(byte[] b, int i) => BitConverter.ToString(b, i, 6).Replace('-', ':');

        static string Ip(byte[] b, int i, int count)
        {
            var address = new byte[count];
            Buffer.BlockCopy(b, i, address, 0, count);
            return new IPAddress(address).ToString();
        }
    }
}
