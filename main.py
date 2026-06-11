#!/usr/bin/env python3
"""NetWatch — silent per-process network monitor (no Npcap required)"""

import sys
import time
import csv
import struct
import socket
import threading
from collections import defaultdict, deque
from datetime import datetime

import tkinter as tk
from tkinter import ttk, filedialog

import psutil
import pystray
from PIL import Image, ImageDraw
import matplotlib
matplotlib.use('TkAgg')
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.ticker as ticker


BUCKET_SECS  = 60       # one graph point per minute
MAX_BUCKETS  = 60       # 60 minutes of history
REFRESH_MS   = 2_000    # table redraw interval
GRAPH_MS     = 10_000   # graph redraw interval
CACHE_SECS   = 3        # port->pid refresh interval


# ── Helpers ───────────────────────────────────────────────────────────────────

def _fmt(b):
    for u in ('B', 'KB', 'MB', 'GB'):
        if abs(b) < 1024:
            return f'{b:.1f} {u}'
        b /= 1024
    return f'{b:.1f} TB'


# ── Data store ────────────────────────────────────────────────────────────────

class Store:
    def __init__(self):
        self._lk   = threading.Lock()
        self._data = defaultdict(lambda: [0, 0])   # pid -> [sent, recv]
        self._names = {}                            # pid -> name (cached)
        self._bkts  = deque(maxlen=MAX_BUCKETS)
        self._bkt_t = time.time()
        self._bkt_b = 0
        self._t0    = time.time()

    def record(self, pid, sent, recv):
        with self._lk:
            self._data[pid][0] += sent
            self._data[pid][1] += recv
            self._bkt_b += sent + recv
            now = time.time()
            if now - self._bkt_t >= BUCKET_SECS:
                self._bkts.append((self._bkt_t, self._bkt_b))
                self._bkt_t = now
                self._bkt_b = 0

    def cache_name(self, pid, name):
        self._names.setdefault(pid, name)

    def reset(self):
        with self._lk:
            self._data.clear()
            self._bkts.clear()
            self._bkt_t = time.time()
            self._bkt_b = 0
            self._t0    = time.time()

    def rows(self):
        with self._lk:
            hrs = max((time.time() - self._t0) / 3600, 1e-9)
            out = []
            for pid, (s, r) in self._data.items():
                tot = s + r
                if not tot:
                    continue
                name = self._names.get(pid, f'PID {pid}')
                out.append((name, pid, s, r, tot, tot / hrs))
            return sorted(out, key=lambda x: x[4], reverse=True)

    def graph_pts(self):
        with self._lk:
            pts = list(self._bkts)
            if self._bkt_b:
                pts.append((self._bkt_t, self._bkt_b))
            return pts

    def elapsed(self):
        return time.time() - self._t0

    def csv_rows(self):
        hdr  = ['Process', 'PID', 'Sent', 'Received', 'Total', 'Avg/hr']
        body = [(n, p, _fmt(s), _fmt(r), _fmt(t), _fmt(a) + '/hr')
                for n, p, s, r, t, a in self.rows()]
        return [hdr] + body


# ── Network monitor — Windows raw sockets ─────────────────────────────────────

class Monitor:
    """
    Captures all IP traffic using Windows raw sockets + SIO_RCVALL.
    No Npcap or third-party driver needed — requires Admin only.
    One socket per active network interface (including cell modem).
    Uses psutil.net_connections() to map ports -> PIDs.
    """

    def __init__(self, store):
        self._store     = store
        self._cache     = {}          # (local_port, proto) -> pid
        self._cache_lk  = threading.Lock()

    # ── port->pid cache ───────────────────────────────────────────────────────

    def _refresh_cache(self):
        try:
            conns = psutil.net_connections(kind='inet')
            m = {}
            for c in conns:
                if not (c.laddr and c.pid):
                    continue
                proto = 'tcp' if c.type == socket.SOCK_STREAM else 'udp'
                m[(c.laddr.port, proto)] = c.pid
                try:
                    self._store.cache_name(c.pid, psutil.Process(c.pid).name())
                except Exception:
                    pass
            with self._cache_lk:
                self._cache = m
        except Exception:
            pass

    def _cache_loop(self):
        while True:
            self._refresh_cache()
            time.sleep(CACHE_SECS)

    # ── packet parser ─────────────────────────────────────────────────────────

    def _parse(self, data):
        """Return (src_port, dst_port, proto, ip_total_len) or None."""
        if len(data) < 20:
            return None
        ver_ihl = data[0]
        ihl     = (ver_ihl & 0xF) * 4
        proto   = data[9]
        total_len = struct.unpack_from('!H', data, 2)[0]

        if proto == 6 and len(data) >= ihl + 4:    # TCP
            sp, dp = struct.unpack_from('!HH', data, ihl)
            return sp, dp, 'tcp', total_len
        if proto == 17 and len(data) >= ihl + 4:   # UDP
            sp, dp = struct.unpack_from('!HH', data, ihl)
            return sp, dp, 'udp', total_len
        return None

    # ── per-interface sniffer ─────────────────────────────────────────────────

    def _sniff(self, ip_addr):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            s.bind((ip_addr, 0))
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            s.settimeout(1.0)
        except Exception:
            return   # interface doesn't support raw capture; skip silently

        try:
            while True:
                try:
                    data, _ = s.recvfrom(65535)
                except socket.timeout:
                    continue
                except Exception:
                    break

                parsed = self._parse(data)
                if not parsed:
                    continue
                sp, dp, proto, size = parsed

                with self._cache_lk:
                    pid = self._cache.get((sp, proto)) or self._cache.get((dp, proto))

                if pid:
                    sent = bool(self._cache.get((sp, proto)))
                    self._store.record(pid, size if sent else 0,
                                           0 if sent else size)
        finally:
            try:
                s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                s.close()
            except Exception:
                pass

    # ── entry point ───────────────────────────────────────────────────────────

    def run(self):
        self._refresh_cache()
        threading.Thread(target=self._cache_loop, daemon=True, name='cache').start()

        # Bind to every active non-loopback IPv4 interface
        bound = 0
        for addrs in psutil.net_if_addrs().values():
            for addr in addrs:
                if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                    threading.Thread(target=self._sniff, args=(addr.address,),
                                     daemon=True, name=f'sniff-{addr.address}').start()
                    bound += 1

        if not bound:   # fallback — shouldn't happen on a machine with network
            threading.Thread(target=self._sniff, args=('0.0.0.0',),
                             daemon=True, name='sniff-any').start()


# ── Window ────────────────────────────────────────────────────────────────────

BG   = '#0d1117'
BG2  = '#161b22'
BG3  = '#1c2128'
BLUE = '#58a6ff'
DIM  = '#484f58'
FG   = '#e6edf3'


class Window:
    def __init__(self, store):
        self._store   = store
        self._visible = False
        self.root     = tk.Tk()
        self.root.title('NetWatch')
        self.root.geometry('560x580')
        self.root.configure(bg=BG)
        self.root.protocol('WM_DELETE_WINDOW', self.hide)
        self._build()
        self._tick_table()
        self._tick_graph()

    def _build(self):
        s = ttk.Style(self.root)
        s.theme_use('clam')
        s.configure('TV.Treeview',
                    background=BG2, foreground=FG,
                    fieldbackground=BG2, rowheight=22,
                    font=('Consolas', 9))
        s.configure('TV.Treeview.Heading',
                    background=BG3, foreground=BLUE,
                    font=('Consolas', 9, 'bold'), relief='flat')
        s.map('TV.Treeview', background=[('selected', '#1f6feb')])

        # Graph
        self._fig = Figure(figsize=(5.6, 1.9), dpi=96, facecolor=BG)
        self._ax  = self._fig.add_subplot(111)
        self._fig.subplots_adjust(left=0.12, right=0.97, top=0.90, bottom=0.15)
        self._mpl = FigureCanvasTkAgg(self._fig, master=self.root)
        self._mpl.get_tk_widget().pack(fill='x', padx=8, pady=(8, 2))

        # Table
        cols = ('app', 'total', 'hr', 'up', 'dn')
        self._tree = ttk.Treeview(self.root, columns=cols, show='headings',
                                   style='TV.Treeview', height=15)
        for col, lbl, w, anchor in [
            ('app',   'Application', 185, 'w'),
            ('total', 'Total',        85, 'e'),
            ('hr',    '/hr',          95, 'e'),
            ('up',    '↑ Sent',       75, 'e'),
            ('dn',    '↓ Recv',       75, 'e'),
        ]:
            self._tree.heading(col, text=lbl)
            self._tree.column(col, width=w, anchor=anchor,
                              stretch=(col == 'app'))

        sb = ttk.Scrollbar(self.root, orient='vertical', command=self._tree.yview)
        self._tree.configure(yscrollcommand=sb.set)
        sb.pack(side='right', fill='y', padx=(0, 4))
        self._tree.pack(fill='both', expand=True, padx=(8, 0), pady=2)

        # Footer
        bar = tk.Frame(self.root, bg=BG)
        bar.pack(fill='x', padx=8, pady=6)
        btn = dict(bg=BG3, fg=BLUE, activebackground='#1f6feb',
                   activeforeground=FG, relief='flat',
                   font=('Consolas', 9), cursor='hand2',
                   padx=12, pady=4, bd=0)
        tk.Button(bar, text='↺  Reset',  command=self._reset,  **btn).pack(side='left', padx=(0, 6))
        tk.Button(bar, text='↓  Export', command=self._export, **btn).pack(side='left')
        self._elapsed_var = tk.StringVar(value='00:00:00')
        tk.Label(bar, textvariable=self._elapsed_var,
                 bg=BG, fg=DIM, font=('Consolas', 8)).pack(side='right')

    def _tick_table(self):
        rows = self._store.rows()
        self._tree.delete(*self._tree.get_children())
        for name, _, s, r, tot, avg_hr in rows:
            self._tree.insert('', 'end',
                values=(name, _fmt(tot), _fmt(avg_hr) + '/hr', _fmt(s), _fmt(r)))
        e = int(self._store.elapsed())
        self._elapsed_var.set(f'{e//3600:02d}:{e%3600//60:02d}:{e%60:02d}')
        self.root.after(REFRESH_MS, self._tick_table)

    def _tick_graph(self):
        ax = self._ax
        ax.clear()
        ax.set_facecolor(BG2)
        for sp in ax.spines.values():
            sp.set_color(DIM)
        ax.tick_params(colors=DIM, labelsize=7)

        pts = self._store.graph_pts()
        if len(pts) >= 2:
            xs = list(range(len(pts)))
            ys = [b / (1 << 20) for _, b in pts]
            ax.plot(xs, ys, color=BLUE, linewidth=1.5)
            ax.fill_between(xs, ys, alpha=0.12, color=BLUE)
            ax.set_xlim(0, max(len(xs) - 1, 1))
            ax.set_ylim(bottom=0)
            ax.yaxis.set_major_formatter(
                ticker.FuncFormatter(lambda v, _: f'{v:.1f} MB'))
            ax.set_xticks([0, len(xs) - 1])
            ax.set_xticklabels([
                datetime.fromtimestamp(pts[0][0]).strftime('%H:%M'),
                datetime.fromtimestamp(pts[-1][0]).strftime('%H:%M'),
            ])
        else:
            ax.text(0.5, 0.5, 'collecting...', ha='center', va='center',
                    transform=ax.transAxes, color=DIM, fontsize=8)

        self._mpl.draw()
        self.root.after(GRAPH_MS, self._tick_graph)

    def _reset(self):
        self._store.reset()

    def _export(self):
        p = filedialog.asksaveasfilename(
            defaultextension='.csv',
            filetypes=[('CSV', '*.csv'), ('All files', '*.*')],
            initialfile=f'netwatch_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv',
        )
        if p:
            with open(p, 'w', newline='') as f:
                csv.writer(f).writerows(self._store.csv_rows())

    def show(self):
        self.root.deiconify()
        self.root.lift()
        self._visible = True

    def hide(self):
        self.root.withdraw()
        self._visible = False

    def toggle(self):
        self.hide() if self._visible else self.show()


# ── Tray icon ─────────────────────────────────────────────────────────────────

def _make_icon():
    img = Image.new('RGB', (64, 64), '#0d1117')
    d   = ImageDraw.Draw(img)
    for x, h in [(4, 38), (16, 20), (28, 52), (40, 30), (52, 14)]:
        d.rectangle([x, 62 - h, x + 8, 62], fill='#58a6ff')
    return img


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    store   = Store()
    monitor = Monitor(store)

    threading.Thread(target=monitor.run, daemon=True, name='monitor').start()

    win = Window(store)

    def _quit(icon, _):
        icon.stop()
        win.root.after(0, win.root.quit)

    icon = pystray.Icon(
        'NetWatch', _make_icon(), 'NetWatch',
        pystray.Menu(
            pystray.MenuItem('Show / Hide',
                             lambda *_: win.root.after(0, win.toggle),
                             default=True),
            pystray.MenuItem('Reset',
                             lambda *_: win.root.after(0, win._reset)),
            pystray.MenuItem('Export',
                             lambda *_: win.root.after(0, win._export)),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem('Quit', _quit),
        ),
    )

    threading.Thread(target=icon.run, daemon=True, name='tray').start()
    win.hide()
    win.root.mainloop()


if __name__ == '__main__':
    main()
