using System;
using System.Collections.Generic;
using System.IO;

namespace NetScope
{
    static class PcapFile
    {
        public const int MaxPackets = 20000;
        public const long MaxBytes = 64L * 1024 * 1024;

        public static List<Packet> Read(Stream stream, out int link, out bool limited)
        {
            using (var input = new BinaryReader(stream))
            {
                uint magic = input.ReadUInt32();
                bool big = magic == 0xd4c3b2a1 || magic == 0x4d3cb2a1;
                bool nano = magic == 0xa1b23c4d || magic == 0x4d3cb2a1;
                if (magic != 0xa1b2c3d4 && !big && !nano)
                    throw new IOException("请选择传统 .pcap 文件。");
                var version = input.ReadBytes(4);
                if (version.Length != 4 || version[big ? 1 : 0] != 2 || version[big ? 3 : 2] != 4)
                    throw new IOException("不支持的 PCAP 版本。");
                input.ReadUInt32();
                input.ReadUInt32();
                uint snapLength = Read32(input, big);
                link = (int)(Read32(input, big) & 0xffff);
                if (!PacketDecoder.Supports(link))
                    throw new IOException("不支持的 PCAP 链路类型：" + link);

                var packets = new List<Packet>();
                long used = 0;
                limited = false;
                while (stream.Position < stream.Length)
                {
                    uint seconds = Read32(input, big);
                    uint fraction = Read32(input, big);
                    uint count = Read32(input, big);
                    uint original = Read32(input, big);
                    if (count > snapLength || count > original || original > int.MaxValue ||
                        fraction >= (nano ? 1000000000u : 1000000u))
                        throw new IOException("PCAP 记录头无效。");
                    if (packets.Count == MaxPackets || used + count > MaxBytes)
                    {
                        limited = true;
                        break;
                    }
                    var bytes = input.ReadBytes((int)count);
                    if (bytes.Length != count) throw new EndOfStreamException("PCAP 记录不完整。");
                    var time = DateTimeOffset.FromUnixTimeSeconds(seconds).AddTicks(nano ? fraction / 100L : fraction * 10L);
                    packets.Add(PacketDecoder.Decode(bytes, link, time, (int)original));
                    used += count;
                }
                return packets;
            }
        }

        public static void Write(Stream stream, int link, IList<Packet> packets)
        {
            using (var output = new BinaryWriter(stream))
            {
                output.Write(0xa1b2c3d4u);
                output.Write((ushort)2);
                output.Write((ushort)4);
                output.Write(0u);
                output.Write(0u);
                int snapLength = 65535;
                foreach (var packet in packets) snapLength = Math.Max(snapLength, packet.Bytes.Length);
                output.Write(snapLength);
                output.Write(link == 12 ? 101 : link);
                foreach (var packet in packets)
                {
                    output.Write((uint)packet.Time.ToUnixTimeSeconds());
                    output.Write((uint)(packet.Time.UtcDateTime.Ticks % TimeSpan.TicksPerSecond / 10));
                    output.Write(packet.Bytes.Length);
                    output.Write(packet.WireLength);
                    output.Write(packet.Bytes);
                }
            }
        }

        static uint Read32(BinaryReader input, bool big)
        {
            uint n = input.ReadUInt32();
            return big ? (n << 24) | ((n & 0xff00) << 8) | ((n >> 8) & 0xff00) | (n >> 24) : n;
        }
    }
}