using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Text.RegularExpressions;

namespace NetScope
{
    sealed class DisplayFilter
    {
        readonly List<string> tokens = new List<string>();
        int position;

        DisplayFilter(string text)
        {
            foreach (Match match in Regex.Matches(text, @"&&|\|\||==|[!()]|[^\s&|=!()]+|\S"))
                tokens.Add(match.Value);
        }

        public static Func<Packet, bool> Compile(string text)
        {
            var parser = new DisplayFilter(text);
            if (parser.Peek == null) return p => true;
            var result = parser.Or();
            if (parser.Peek != null) throw new FormatException("多余的符号：" + parser.Peek);
            return result;
        }

        string Peek => position < tokens.Count ? tokens[position] : null;
        string Read() => Peek == null ? throw new FormatException("表达式提前结束。") : tokens[position++];

        bool Take(string a, string b = null)
        {
            var token = Peek;
            if (token == null || (!token.Equals(a, StringComparison.OrdinalIgnoreCase) &&
                                  !token.Equals(b, StringComparison.OrdinalIgnoreCase))) return false;
            position++;
            return true;
        }

        Func<Packet, bool> Or()
        {
            var terms = new List<Func<Packet, bool>> { And() };
            while (Take("or", "||")) terms.Add(And());
            if (terms.Count == 1) return terms[0];
            return p => terms.Exists(term => term(p));
        }

        Func<Packet, bool> And()
        {
            var terms = new List<Func<Packet, bool>> { Unary(0) };
            while (Take("and", "&&")) terms.Add(Unary(0));
            if (terms.Count == 1) return terms[0];
            return p => terms.TrueForAll(term => term(p));
        }

        Func<Packet, bool> Unary(int negations)
        {
            if (Take("not", "!")) return Unary(negations + 1);
            Func<Packet, bool> term;
            if (Take("("))
            {
                term = Or();
                if (!Take(")")) throw new FormatException("缺少右括号。");
            }
            else term = Atom();
            return negations % 2 == 0 ? term : p => !term(p);
        }

        Func<Packet, bool> Atom()
        {
            var name = Read().ToLowerInvariant();
            switch (name)
            {
                case "ip":
                case "ipv4": return p => p.Version == 4;
                case "ipv6": return p => p.Version == 6;
                case "tcp": return p => p.Transport == "TCP";
                case "udp": return p => p.Transport == "UDP";
                case "icmp": return p => p.Transport == "ICMP" || p.Transport == "ICMPv6";
                case "icmpv6": return p => p.Transport == "ICMPv6";
                case "arp": return p => p.Transport == "ARP";
                case "http": return p => p.Application == "HTTP";
            }

            if (!Take("==")) throw new FormatException("未知条件：" + name);
            string value = Read();
            if (name == "ip.addr" || name == "ip.src" || name == "ip.dst")
            {
                if (!IPAddress.TryParse(value, out var ip) || (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork && !value.Contains(".")))
                    throw new FormatException("请输入 IPv4 或 IPv6 地址。");
                string address = ip.ToString().Split('%')[0];
                return p => p.Version != 0 &&
                    ((name != "ip.dst" && p.Source == address) || (name != "ip.src" && p.Destination == address));
            }

            if (!int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out int number))
                throw new FormatException("请输入十进制整数。");
            if (name == "pid")
            {
                if (number == 0) throw new FormatException("PID 必须大于零。");
                return p => p.HasOwner(number);
            }
            if (number > 65535) throw new FormatException("端口范围为 0–65535。");
            switch (name)
            {
                case "tcp.port": return p => p.Flow != null && (p.SourcePort == number || p.DestinationPort == number);
                case "udp.port": return p => p.Layers.Exists(layer => layer.Name == "UDP") &&
                                            (p.SourcePort == number || p.DestinationPort == number);
                default: throw new FormatException("未知字段：" + name);
            }
        }
    }
}
