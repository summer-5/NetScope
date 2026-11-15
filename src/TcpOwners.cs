using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;

namespace NetScope
{
    sealed class TcpOwners
    {
        readonly Stopwatch clock = Stopwatch.StartNew();
        readonly Dictionary<string, int> connections = new Dictionary<string, int>();
        readonly Dictionary<string, int> listeners = new Dictionary<string, int>();
        readonly Dictionary<int, string> names = new Dictionary<int, string>();
        readonly HashSet<string> localAddresses = new HashSet<string> { "127.0.0.1", "::1" };
        long refreshAt;

        public TcpOwners()
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
                foreach (var unicast in nic.GetIPProperties().UnicastAddresses)
                    localAddresses.Add(unicast.Address.ToString().Split('%')[0]);
        }

        public void Attach(Packet packet)
        {
            if (packet.Flow == null) return;
            if (clock.ElapsedMilliseconds >= refreshAt)
            {
                refreshAt = clock.ElapsedMilliseconds + 350;
                connections.Clear();
                listeners.Clear();
                names.Clear();
                ReadTable(false);
                ReadTable(true);
            }

            string source = Packet.Endpoint(packet.Source, packet.SourcePort);
            string destination = Packet.Endpoint(packet.Destination, packet.DestinationPort);
            connections.TryGetValue(Key(source, destination), out int pid);
            connections.TryGetValue(Key(destination, source), out int peerPid);
            if (pid == 0)
            {
                pid = peerPid;
                peerPid = 0;
            }
            if (pid == 0)
            {
                if ((packet.TcpFlags & 0x12) != 2) return;
                var any = packet.Version == 6 ? "::" : "0.0.0.0";
                if (!listeners.TryGetValue(destination, out pid) &&
                    (!localAddresses.Contains(packet.Destination) || !listeners.TryGetValue(Packet.Endpoint(any, packet.DestinationPort), out pid)))
                    return;
            }
            if (pid <= 0) return;

            if (!names.TryGetValue(pid, out string name))
            {
                try
                {
                    using (var process = Process.GetProcessById(pid))
                        name = process.ProcessName;
                }
                catch (ArgumentException) { name = ""; }
                catch (InvalidOperationException) { name = ""; }
                catch (System.ComponentModel.Win32Exception) { name = ""; }
                names[pid] = name;
            }
            packet.Pid = pid;
            packet.PeerPid = peerPid == pid ? 0 : peerPid;
            packet.ProcessName = name;
        }

        void ReadTable(bool ipv6)
        {
            int family = ipv6 ? 23 : 2;
            int size = 0;
            GetExtendedTcpTable(IntPtr.Zero, ref size, false, family, 5, 0);
            while (size > 0)
            {
                var buffer = Marshal.AllocHGlobal(size);
                try
                {
                    int status = GetExtendedTcpTable(buffer, ref size, false, family, 5, 0);
                    if (status == 122) continue;
                    if (status == 0) ReadRows(buffer, ipv6);
                    return;
                }
                finally { Marshal.FreeHGlobal(buffer); }
            }
        }

        void ReadRows(IntPtr table, bool ipv6)
        {
            int count = Marshal.ReadInt32(table);
            int stride = ipv6 ? 56 : 24;
            for (int i = 0; i < count; i++)
            {
                var row = IntPtr.Add(table, 4 + i * stride);
                int state = Marshal.ReadInt32(row, ipv6 ? 48 : 0);
                int pid = Marshal.ReadInt32(row, ipv6 ? 52 : 20);
                if (pid == 0) continue;
                string local = Packet.Endpoint(Address(row, ipv6 ? 0 : 4, ipv6), Port(row, ipv6 ? 20 : 8));
                if (state == 2)
                    listeners[local] = pid;
                else
                {
                    string remote = Packet.Endpoint(Address(row, ipv6 ? 24 : 12, ipv6), Port(row, ipv6 ? 44 : 16));
                    connections[Key(local, remote)] = pid;
                }
            }
        }

        static string Key(string local, string remote) => local + " / " + remote;

        static string Address(IntPtr row, int offset, bool ipv6)
        {
            var bytes = new byte[ipv6 ? 16 : 4];
            Marshal.Copy(IntPtr.Add(row, offset), bytes, 0, bytes.Length);
            return new IPAddress(bytes).ToString();
        }

        static int Port(IntPtr row, int offset) =>
            (Marshal.ReadByte(row, offset) << 8) | Marshal.ReadByte(row, offset + 1);

        [DllImport("iphlpapi.dll")]
        static extern int GetExtendedTcpTable(IntPtr table, ref int size, bool order, int family, int tableClass, int reserved);
    }
}
