using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace NetScope
{
    sealed class MainForm : Form
    {
        static readonly Color Ink = Color.FromArgb(22, 35, 51);
        static readonly Color Muted = Color.FromArgb(52, 71, 89);
        static readonly Color Line = Color.FromArgb(218, 228, 237);
        static readonly Color Wash = Color.FromArgb(241, 246, 250);
        static readonly Color Accent = Color.FromArgb(0, 108, 100);

        readonly ComboBox devices = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 260 };
        readonly CheckBox promisc = new CheckBox { Text = "混杂模式", AutoSize = true };
        readonly TextBox bpf = new TextBox { Width = 190, MaxLength = 1024 };
        readonly TextBox expression = new TextBox { Dock = DockStyle.Fill, MaxLength = 1024 };
        readonly Button start = Button("开始捕获", true), stop = Button("停止"), refresh = Button("刷新"),
            open = Button("打开 PCAP"), save = Button("保存 PCAP"),
            follow = Button("追踪 TCP 流"), process = Button("追踪进程"), clearScope = Button("取消追踪"),
            apply = Button("应用"), reset = Button("清空");
        readonly Label totals = new Label { AutoSize = true },
            scope = new Label { AutoSize = true }, detailTitle = new Label { Dock = DockStyle.Fill };
        readonly DataGridView grid = new DataGridView();
        readonly TreeView tree = new TreeView { Dock = DockStyle.Fill, BorderStyle = BorderStyle.None, HideSelection = false };
        readonly RichTextBox hex = new RichTextBox { Dock = DockStyle.Fill, ReadOnly = true, WordWrap = false, BorderStyle = BorderStyle.None };
        readonly SplitContainer mainSplit = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal };
        readonly SplitContainer detailSplit = new SplitContainer { Dock = DockStyle.Fill };
        readonly List<Packet> packets = new List<Packet>();
        readonly List<Packet> visible = new List<Packet>();
        readonly System.Windows.Forms.Timer timer = new System.Windows.Forms.Timer { Interval = 100 };
        readonly ConcurrentQueue<Packet> pending = new ConcurrentQueue<Packet>();

        CancellationTokenSource cancel;
        Task worker;
        Func<Packet, bool> filter = p => true;
        Packet selected;
        string flowScope;
        int pidScope;
        int link, captureLink = -1;
        bool limited, busy, captureOpened;
        DateTimeOffset first;
        const int HexBytes = 16 * 1024;

        public MainForm()
        {
            Text = "NetScope  ·  网络嗅探器";
            Font = new Font("Microsoft YaHei UI", 11);
            ForeColor = Ink;
            BackColor = Wash;
            StartPosition = FormStartPosition.CenterScreen;
            ClientSize = new Size(1120, 710);
            MinimumSize = new Size(950, 560);
            SuspendLayout();
            AutoScaleDimensions = new SizeF(96, 96);
            AutoScaleMode = AutoScaleMode.Dpi;
            Build();
            Bind();
            ResumeLayout();
            Shown += (s, e) =>
            {
                SizePacketViews(CurrentAutoScaleDimensions.Width);
                mainSplit.SplitterDistance = (int)(mainSplit.Height * 0.55);
                detailSplit.SplitterDistance = (int)(detailSplit.Width * 0.46);
                RefreshDevices();
            };
            DpiChanged += (s, e) => SizePacketViews(e.DeviceDpiNew);
            SetControls();
        }

        void Build()
        {
            var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 5 };
            foreach (int height in new[] { 63, 46, 46, 48 })
                root.RowStyles.Add(new RowStyle(SizeType.Absolute, height));
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            Controls.Add(root);

            var masthead = new TableLayoutPanel { Dock = DockStyle.Fill, BackColor = Ink, Margin = Padding.Empty,
                ColumnCount = 2, Padding = new Padding(19, 0, 16, 0) };
            masthead.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            masthead.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            masthead.Controls.Add(new Label { Text = "NetScope   网络嗅探器", Anchor = AnchorStyles.Left, AutoSize = true,
                Font = new Font("Microsoft YaHei UI", 18, FontStyle.Bold), ForeColor = Color.White });
            totals.Anchor = AnchorStyles.Right;
            totals.ForeColor = Color.FromArgb(184, 223, 218);
            masthead.Controls.Add(totals);
            root.Controls.Add(masthead, 0, 0);

            var captureBar = Bar();
            captureBar.Controls.AddRange(new Control[] { Caption("网卡"), devices, refresh, promisc, start, stop, open, save });
            root.Controls.Add(captureBar, 0, 1);

            var options = Bar();
            options.Controls.AddRange(new Control[] { Caption("捕获 BPF"), bpf, follow, process, clearScope, scope });
            scope.AutoEllipsis = true;
            scope.MaximumSize = new Size(380, 26);
            scope.ForeColor = Accent;
            scope.Margin = new Padding(9, 7, 0, 0);
            root.Controls.Add(options, 0, 2);

            var filters = new TableLayoutPanel { Dock = DockStyle.Fill, Margin = Padding.Empty, ColumnCount = 5,
                BackColor = Color.White, Padding = new Padding(14, 8, 14, 5) };
            filters.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            filters.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            filters.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            filters.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            filters.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            filters.Controls.Add(Caption("显示过滤"));
            filters.Controls.Add(expression);
            filters.Controls.Add(apply);
            filters.Controls.Add(reset);
            var quick = new ComboBox { Width = 145, DropDownStyle = ComboBoxStyle.DropDownList };
            quick.Items.AddRange(new object[] { "协议快捷筛选", "HTTP", "TCP", "UDP", "IPv4", "IPv6", "ICMP", "ICMPv6", "ARP" });
            quick.SelectedIndex = 0;
            quick.SelectionChangeCommitted += (s, e) =>
            {
                expression.Text = quick.SelectedIndex == 0 ? "" : quick.Text.ToLowerInvariant();
                ApplyFilter();
            };
            filters.Controls.Add(quick);
            root.Controls.Add(filters, 0, 3);

            mainSplit.Margin = new Padding(14, 4, 14, 12);
            mainSplit.SplitterWidth = 7;
            detailSplit.SplitterWidth = 7;
            mainSplit.Panel1.Controls.Add(grid);
            mainSplit.Panel2.Controls.Add(detailSplit);
            root.Controls.Add(mainSplit, 0, 4);

            BuildGrid();
            tree.BackColor = Color.White;
            tree.ForeColor = Ink;
            hex.BackColor = Color.White;
            hex.ForeColor = Ink;
            hex.Font = new Font("Consolas", 11);
            detailSplit.Panel1.Controls.Add(PanelWithTitle(detailTitle, tree, "协议详情"));
            detailSplit.Panel2.Controls.Add(PanelWithTitle(new Label { Dock = DockStyle.Fill }, hex, "原始字节  /  HEX + ASCII"));
        }

        void BuildGrid()
        {
            grid.Dock = DockStyle.Fill;
            grid.VirtualMode = true;
            grid.ReadOnly = true;
            grid.AllowUserToAddRows = false;
            grid.AllowUserToDeleteRows = false;
            grid.AllowUserToResizeRows = false;
            grid.MultiSelect = false;
            grid.RowHeadersVisible = false;
            grid.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
            grid.BackgroundColor = Color.White;
            grid.BorderStyle = BorderStyle.FixedSingle;
            grid.GridColor = Line;
            grid.CellBorderStyle = DataGridViewCellBorderStyle.SingleHorizontal;
            grid.EnableHeadersVisualStyles = false;
            grid.ColumnHeadersBorderStyle = DataGridViewHeaderBorderStyle.None;
            grid.ColumnHeadersDefaultCellStyle.BackColor = Color.FromArgb(229, 237, 245);
            grid.ColumnHeadersDefaultCellStyle.ForeColor = Ink;
            grid.DefaultCellStyle.ForeColor = Ink;
            grid.DefaultCellStyle.SelectionBackColor = Color.FromArgb(205, 235, 231);
            grid.DefaultCellStyle.SelectionForeColor = Ink;
            grid.AlternatingRowsDefaultCellStyle.BackColor = Color.FromArgb(247, 250, 252);

            Column("序号");
            Column("时间 / s");
            Column("源地址", 90);
            Column("目的地址", 90);
            Column("协议");
            Column("长度");
            Column("进程 / PID", 65);
            Column("摘要", 155);
        }

        void SizePacketViews(float dpi)
        {
            float scale = dpi / 96f;
            grid.Columns[0].Width = (int)(58 * scale);
            grid.Columns[1].Width = (int)(108 * scale);
            grid.Columns[4].Width = (int)(84 * scale);
            grid.Columns[5].Width = (int)(65 * scale);
            grid.ColumnHeadersHeight = (int)(36 * scale);
            grid.RowTemplate.Height = (int)(30 * scale);
            tree.ItemHeight = (int)(28 * scale);
        }

        void Column(string title, int fill = 0)
        {
            var column = new DataGridViewTextBoxColumn { HeaderText = title,
                SortMode = DataGridViewColumnSortMode.NotSortable };
            if (fill != 0)
            {
                column.AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill;
                column.MinimumWidth = 80;
                column.FillWeight = fill;
            }
            grid.Columns.Add(column);
        }

        void Bind()
        {
            refresh.Click += (s, e) => RefreshDevices();
            devices.SelectedIndexChanged += (s, e) => SetControls();
            start.Click += async (s, e) => await StartCapture();
            stop.Click += (s, e) => { cancel?.Cancel(); stop.Enabled = false; };
            open.Click += async (s, e) =>
            {
                using (var dialog = new OpenFileDialog { Filter = "PCAP 文件 (*.pcap)|*.pcap|所有文件 (*.*)|*.*" })
                    if (dialog.ShowDialog(this) == DialogResult.OK)
                        await LoadPackets(dialog.FileName);
            };
            save.Click += (s, e) => SavePackets();
            apply.Click += (s, e) => ApplyFilter();
            reset.Click += (s, e) => { expression.Clear(); ApplyFilter(); };
            expression.KeyDown += (s, e) =>
            {
                if (e.KeyCode != Keys.Enter) return;
                ApplyFilter();
                e.SuppressKeyPress = true;
            };
            follow.Click += (s, e) => { flowScope = selected.Flow; pidScope = 0; UpdateScope(); };
            process.Click += (s, e) => { pidScope = selected.Pid; flowScope = null; UpdateScope(); };
            clearScope.Click += (s, e) => { flowScope = null; pidScope = 0; UpdateScope(); };
            timer.Tick += (s, e) => Drain(1500);
            grid.CellValueNeeded += (s, e) =>
            {
                if (e.RowIndex < visible.Count) e.Value = Cell(visible[e.RowIndex], e.ColumnIndex);
            };
            grid.CurrentCellChanged += (s, e) =>
            {
                int row = grid.CurrentCell?.RowIndex ?? -1;
                ShowDetails(row >= 0 && row < visible.Count ? visible[row] : null);
            };
            tree.AfterSelect += (s, e) => SelectBytes(e.Node.Tag as Layer);
            FormClosing += (s, e) => cancel?.Cancel();
        }

        object Cell(Packet p, int column)
        {
            switch (column)
            {
                case 0: return p.Number;
                case 1: return (p.Time - first).TotalSeconds.ToString("F6", System.Globalization.CultureInfo.InvariantCulture);
                case 2: return p.Source;
                case 3: return p.Destination;
                case 4: return p.Protocol;
                case 5: return p.WireLength;
                case 6: return p.ProcessLabel;
                default: return p.Info;
            }
        }

        void RefreshDevices()
        {
            string previous = (devices.SelectedItem as Device)?.Name;
            devices.Items.Clear();
            try
            {
                var list = LiveCapture.Devices();
                devices.Items.AddRange(list.ToArray());
                if (list.Count != 0)
                    devices.SelectedIndex = Math.Max(0, list.FindIndex(d => d.Name == previous));
                else
                    ShowError("刷新网卡", "Npcap 未返回可用网卡。");
            }
            catch (Exception ex) { ShowError("刷新网卡", ex.Message); }
            SetControls();
        }

        async Task StartCapture()
        {
            var device = (Device)devices.SelectedItem;
            bool mixed = promisc.Checked;
            string rule = bpf.Text.Trim();
            cancel = new CancellationTokenSource();
            var token = cancel.Token;
            long bytes = 0;
            int count = 0;
            bool reachedLimit = false;
            Volatile.Write(ref captureLink, -1);
            captureOpened = false;
            worker = Task.Run(() => LiveCapture.Run(device, mixed, rule, value => Volatile.Write(ref captureLink, value),
                packet =>
                {
                    if (count == PcapFile.MaxPackets || bytes + packet.Bytes.Length > PcapFile.MaxBytes)
                    {
                        reachedLimit = true;
                        return false;
                    }
                    pending.Enqueue(packet);
                    count++;
                    bytes += packet.Bytes.Length;
                    return true;
                }, token));
            SetControls();
            timer.Start();
            string error = null;
            try { await worker; }
            catch (Exception ex) { error = ex.Message; }
            finally
            {
                timer.Stop();
                Drain(int.MaxValue);
                cancel.Dispose();
                cancel = null;
                worker = null;
                limited |= reachedLimit;
                if (!IsDisposed)
                {
                    SetControls();
                    if (error != null) ShowError("捕获失败", error);
                }
            }
        }

        void Drain(int max)
        {
            int openedLink = Interlocked.Exchange(ref captureLink, -1);
            if (openedLink >= 0)
            {
                captureOpened = true;
                ResetPackets(openedLink);
            }
            if (!captureOpened) return;
            int added = 0;
            while (added < max && pending.TryDequeue(out var packet))
            {
                AddPacket(packet);
                added++;
            }
            if (added != 0) UpdateRows();
        }

        async Task LoadPackets(string path)
        {
            busy = true;
            SetControls();
            try
            {
                var data = await Task.Run(() =>
                {
                    var list = PcapFile.Read(File.OpenRead(path), out int dataLink, out bool truncated);
                    return (list, dataLink, truncated);
                });
                ResetPackets(data.dataLink);
                limited = data.truncated;
                foreach (var packet in data.list) AddPacket(packet);
                UpdateRows();
            }
            catch (Exception ex) { ShowError("打开 PCAP", ex.Message); }
            finally { busy = false; SetControls(); }
        }

        void SavePackets()
        {
            using (var dialog = new SaveFileDialog { Filter = "PCAP 文件 (*.pcap)|*.pcap", DefaultExt = "pcap", FileName = "capture.pcap" })
            {
                if (dialog.ShowDialog(this) != DialogResult.OK) return;
                try
                {
                    PcapFile.Write(File.Create(dialog.FileName), link, packets);
                }
                catch (Exception ex) { ShowError("保存 PCAP", ex.Message); }
            }
        }

        void ShowError(string title, string message) =>
            MessageBox.Show(this, message, title, MessageBoxButtons.OK, MessageBoxIcon.Warning);

        void ResetPackets(int dataLink)
        {
            packets.Clear();
            visible.Clear();
            link = dataLink;
            limited = false;
            flowScope = null;
            pidScope = 0;
            scope.Text = "";
            UpdateRows();
        }

        void AddPacket(Packet packet)
        {
            if (packets.Count == 0) first = packet.Time;
            packet.Number = packets.Count + 1;
            packets.Add(packet);
            if (Matches(packet)) visible.Add(packet);
        }

        bool Matches(Packet packet) => filter(packet) &&
            (flowScope == null || packet.Flow == flowScope) &&
            (pidScope == 0 || packet.HasOwner(pidScope));

        void ApplyFilter()
        {
            try
            {
                filter = DisplayFilter.Compile(expression.Text);
                expression.BackColor = Color.White;
                RebuildRows();
            }
            catch (FormatException ex)
            {
                expression.BackColor = Color.FromArgb(255, 235, 231);
                ShowError("显示过滤", ex.Message + "\n继续使用上一条有效条件。");
            }
        }

        void UpdateScope()
        {
            scope.Text = flowScope != null ? "TCP · " + flowScope : pidScope == 0 ? "" : "PID " + pidScope;
            RebuildRows();
        }

        void RebuildRows()
        {
            Packet previous = selected;
            visible.Clear();
            visible.AddRange(packets.Where(Matches));
            UpdateRows();
            if (visible.Count == 0) return;
            int row = Math.Max(0, visible.IndexOf(previous));
            grid.CurrentCell = grid.Rows[row].Cells[0];
            grid.Invalidate();
            ShowDetails(visible[row]);
        }

        void UpdateRows()
        {
            grid.RowCount = visible.Count;
            if (visible.Count == 0) ShowDetails(null);
            else if (grid.CurrentCell == null) grid.CurrentCell = grid.Rows[0].Cells[0];
            UpdateTotals();
            SetControls();
        }

        void UpdateTotals() => totals.Text = "显示 " + visible.Count.ToString("N0") +
            "  /  总计 " + packets.Count.ToString("N0") + " 包" + (limited ? "  ·  已达上限" : "");

        void SetControls()
        {
            bool idle = worker == null && !busy;
            devices.Enabled = refresh.Enabled = bpf.Enabled = promisc.Enabled = open.Enabled = idle;
            start.Enabled = idle && devices.SelectedItem != null;
            stop.Enabled = worker != null && !worker.IsCompleted && !cancel.IsCancellationRequested;
            save.Enabled = idle && packets.Count > 0;
            follow.Enabled = selected?.Flow != null;
            process.Enabled = selected?.Pid > 0;
            clearScope.Enabled = flowScope != null || pidScope != 0;
            UpdateTotals();
        }

        void ShowDetails(Packet packet)
        {
            if (selected == packet) return;
            selected = packet;
            tree.BeginUpdate();
            tree.Nodes.Clear();
            hex.Clear();
            detailTitle.Text = "协议详情";
            if (packet != null)
            {
                detailTitle.Text += "   ·   #" + packet.Number + "  " + packet.Protocol;
                var frame = tree.Nodes.Add("帧  ·  " + packet.WireLength + " 字节");
                frame.Nodes.Add("捕获时间  " + packet.Time.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss.ffffff"));
                frame.Nodes.Add("捕获长度  " + packet.Bytes.Length + " 字节");
                if (packet.ProcessLabel != "") frame.Nodes.Add("本机进程  " + packet.ProcessLabel);
                if (packet.PeerPid != 0) frame.Nodes.Add("对端本机进程 PID  " + packet.PeerPid);
                if (packet.Flow != null) frame.Nodes.Add("TCP 会话  " + packet.Flow);
                foreach (var layer in packet.Layers)
                {
                    var node = tree.Nodes.Add(layer.Name + "  ·  " + layer.Length + " 字节");
                    node.Tag = layer;
                    foreach (string field in layer.Fields) node.Nodes.Add(new TreeNode(field) { Tag = layer });
                    if (layer.Name != "Ethernet II" && layer.Name != "回环") node.Expand();
                }
                hex.Text = FormatHex(packet.Bytes);
            }
            tree.EndUpdate();
            SetControls();
        }

        static string FormatHex(byte[] bytes)
        {
            int count = Math.Min(HexBytes, bytes.Length);
            var output = new StringBuilder();
            for (int i = 0; i < count; i += 16)
            {
                output.Append(i.ToString("X4")).Append("  ");
                for (int j = 0; j < 16; j++)
                {
                    if (j == 8) output.Append(' ');
                    output.Append(i + j < count ? bytes[i + j].ToString("X2") + " " : "   ");
                }
                output.Append("  ");
                for (int j = 0; j < 16 && i + j < count; j++)
                {
                    byte b = bytes[i + j];
                    output.Append(b >= 32 && b <= 126 ? (char)b : '.');
                }
                output.Append('\n');
            }
            if (bytes.Length > count) output.Append("… 预览前 16 KiB，保存 PCAP 时保留全部捕获字节。");
            return output.ToString();
        }

        void SelectBytes(Layer layer)
        {
            if (layer == null || layer.Offset >= HexBytes) return;
            int lineIndex = layer.Offset / 16;
            int start = hex.GetFirstCharIndexFromLine(lineIndex);
            if (start < 0) return;
            int offset = layer.Offset % 16;
            start += 6 + offset * 3 + (offset >= 8 ? 1 : 0);
            hex.Select(start, 2);
            hex.ScrollToCaret();
        }

        static FlowLayoutPanel Bar() => new FlowLayoutPanel { Dock = DockStyle.Fill, WrapContents = false,
            Padding = new Padding(14, 7, 4, 0), Margin = Padding.Empty };

        static Label Caption(string text) => new Label { Text = text, AutoSize = true, ForeColor = Muted,
            Anchor = AnchorStyles.Left, Margin = new Padding(3, 6, 6, 0) };

        static Button Button(string title, bool primary = false)
        {
            var button = new Button { Text = title, AutoSize = true, Height = 32, MinimumSize = new Size(57, 32),
                Padding = new Padding(7, 0, 7, 0), Margin = new Padding(3, 0, 3, 0), FlatStyle = FlatStyle.Flat,
                BackColor = primary ? Accent : Color.White, ForeColor = primary ? Color.White : Ink };
            button.FlatAppearance.BorderColor = primary ? Accent : Line;
            return button;
        }

        static Control PanelWithTitle(Label title, Control content, string text)
        {
            title.Text = text;
            title.Padding = new Padding(10, 5, 0, 0);
            title.BackColor = Color.FromArgb(229, 237, 245);
            var panel = new TableLayoutPanel { Dock = DockStyle.Fill, BackColor = Color.White, ColumnCount = 1, RowCount = 2,
                CellBorderStyle = TableLayoutPanelCellBorderStyle.Single };
            panel.RowStyles.Add(new RowStyle(SizeType.Absolute, 34));
            panel.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            panel.Controls.Add(title, 0, 0);
            panel.Controls.Add(content, 0, 1);
            return panel;
        }
    }
}
