using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace NetScope
{
    sealed class Device
    {
        public string Name { get; }
        readonly string label;

        public Device(string name, string description)
        {
            Name = name;
            label = description ?? name;
        }

        public override string ToString() => label;
    }

    static class LiveCapture
    {
        static bool loaded;

        public static List<Device> Devices()
        {
            LoadNpcap();
            var error = new StringBuilder(256);
            if (Native.pcap_findalldevs(out var head, error) != 0)
                throw new IOException(error.ToString());

            var devices = new List<Device>();
            var adapters = NetworkInterface.GetAllNetworkInterfaces();
            try
            {
                for (var p = head; p != IntPtr.Zero;)
                {
                    var item = Marshal.PtrToStructure<Native.Interface>(p);
                    var name = Marshal.PtrToStringAnsi(item.Name);
                    var adapter = Array.Find(adapters, nic =>
                        name.EndsWith(nic.Id, StringComparison.OrdinalIgnoreCase));
                    var description = Marshal.PtrToStringAnsi(item.Description);
                    if (adapter != null)
                        description = adapter.Name + " · " + description;
                    else if (name.EndsWith("NPF_Loopback", StringComparison.OrdinalIgnoreCase))
                        description = "本机回环 · 127.0.0.1 / ::1";
                    devices.Add(new Device(name, description));
                    p = item.Next;
                }
            }
            finally
            {
                if (head != IntPtr.Zero) Native.pcap_freealldevs(head);
            }
            return devices;
        }

        public static void Run(Device device, bool promiscuous, string bpf,
            Action<int> ready, Func<Packet, bool> receive, CancellationToken stop)
        {
            LoadNpcap();
            var error = new StringBuilder(256);
            var handle = Native.pcap_open_live(device.Name, 65535, promiscuous ? 1 : 0, 50, error);
            if (handle == IntPtr.Zero) throw new IOException(error.ToString());

            try
            {
                if (!string.IsNullOrWhiteSpace(bpf))
                    SetFilter(handle, bpf);
                if (Native.pcap_setnonblock(handle, 1, error) != 0)
                    throw new IOException(error.ToString());

                int link = Native.pcap_datalink(handle);
                if (!PacketDecoder.Supports(link))
                    throw new IOException("当前网卡链路类型不受支持，DLT = " + link);

                ready(link);
                var owners = new TcpOwners();
                while (!stop.IsCancellationRequested)
                {
                    int result = Native.pcap_next_ex(handle, out var header, out var data);
                    if (result == 0)
                    {
                        stop.WaitHandle.WaitOne(20);
                        continue;
                    }
                    if (result != 1) throw new IOException(Error(handle));

                    var info = Marshal.PtrToStructure<Native.Header>(header);
                    var bytes = new byte[info.Captured];
                    Marshal.Copy(data, bytes, 0, bytes.Length);
                    var time = DateTimeOffset.FromUnixTimeSeconds(info.Seconds).AddTicks(info.Micros * 10L);
                    var packet = PacketDecoder.Decode(bytes, link, time, info.Original);
                    owners.Attach(packet);
                    if (!receive(packet)) break;
                }
            }
            finally
            {
                Native.pcap_close(handle);
            }
        }

        static void SetFilter(IntPtr handle, string expression)
        {
            if (Native.pcap_compile(handle, out var program, expression, 1, uint.MaxValue) != 0)
                throw new IOException("BPF 表达式有误。\n" + Error(handle));
            try
            {
                if (Native.pcap_setfilter(handle, ref program) != 0)
                    throw new IOException(Error(handle));
            }
            finally
            {
                Native.pcap_freecode(ref program);
            }
        }

        static string Error(IntPtr handle) => Marshal.PtrToStringAnsi(Native.pcap_geterr(handle));

        static void LoadNpcap()
        {
            if (loaded) return;
            var system = Environment.SystemDirectory;
            var path = Path.Combine(system, "Npcap", "wpcap.dll");
            if (!File.Exists(path)) path = Path.Combine(system, "wpcap.dll");
            if (!File.Exists(path))
                throw new IOException("未检测到 Npcap。安装后点击「刷新」。");
            if (Native.LoadLibraryEx(path, IntPtr.Zero, 8) == IntPtr.Zero)
                throw new Win32Exception();
            loaded = true;
        }

        static class Native
        {
            [StructLayout(LayoutKind.Sequential)]
            public struct Interface
            {
                public IntPtr Next, Name, Description, Addresses;
                public uint Flags;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct Header
            {
                public uint Seconds, Micros;
                public int Captured, Original;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct Filter
            {
                public uint Count;
                public IntPtr Instructions;
            }

            [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
            public static extern IntPtr LoadLibraryEx(string path, IntPtr file, uint flags);
            [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
            public static extern int pcap_findalldevs(out IntPtr head, StringBuilder error);
            [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
            public static extern void pcap_freealldevs(IntPtr head);
            [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
            public static extern IntPtr pcap_open_live(string name, int snaplen, int promisc, int timeout, StringBuilder error);
            [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
            public static extern int pcap_setnonblock(IntPtr handle, int mode, StringBuilder error);
            [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
            public static extern int pcap_datalink(IntPtr handle);
            [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
            public static extern int pcap_next_ex(IntPtr handle, out IntPtr header, out IntPtr data);
            [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
            public static extern int pcap_compile(IntPtr handle, out Filter program, string expression, int optimize, uint netmask);
            [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
            public static extern int pcap_setfilter(IntPtr handle, ref Filter program);
            [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
            public static extern void pcap_freecode(ref Filter program);
            [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
            public static extern IntPtr pcap_geterr(IntPtr handle);
            [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
            public static extern void pcap_close(IntPtr handle);
        }
    }
}
