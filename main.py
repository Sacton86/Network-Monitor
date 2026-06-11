#!/usr/bin/env python3
"""NetWatch — silent per-process network monitor (no Npcap required)"""

import sys
import time
import csv
import threading
import ctypes
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


BUCKET_SECS = 60        # one graph point per minute
MAX_BUCKETS = 60        # 60 minutes of history
REFRESH_MS  = 2_000     # table redraw interval
GRAPH_MS    = 10_000    # graph redraw interval
POLL_SECS   = 2         # how often to read TCP stats


# ── Windows API ───────────────────────────────────────────────────────────────

if sys.platform == 'win32':
    import ctypes.wintypes as _wt

    _iphlp = ctypes.WinDLL('iphlpapi.dll', use_last_error=True)

    class _MIB_TCPROW(ctypes.Structure):
        _fields_ = [
            ('dwState',      _wt.DWORD),
            ('dwLocalAddr',  _wt.DWORD),
            ('dwLocalPort',  _wt.DWORD),
            ('dwRemoteAddr', _wt.DWORD),
            ('dwRemotePort', _wt.DWORD),
        ]

    class _MIB_TCPROW_PID(ctypes.Structure):
        _fields_ = [
            ('dwState',      _wt.DWORD),
            ('dwLocalAddr',  _wt.DWORD),
            ('dwLocalPort',  _wt.DWORD),
            ('dwRemoteAddr', _wt.DWORD),
            ('dwRemotePort', _wt.DWORD),
            ('dwOwningPid',  _wt.DWORD),
        ]

    class _ESTATS_DATA_RW(ctypes.Structure):
        _fields_ = [('EnableCollection', ctypes.c_byte)]

    class _ESTATS_DATA_ROD(ctypes.Structure):
        _fields_ = [
            ('DataBytesOut',    ctypes.c_uint64),
            ('DataSegsOut',     ctypes.c_uint64),
            ('DataBytesIn',     ctypes.c_uint64),
            ('DataSegsIn',      ctypes.c_uint64),
            ('SegsIn',          ctypes.c_uint64),
            ('SegsOut',         ctypes.c_uint64),
            ('SoftErrors',      _wt.DWORD),
            ('SoftErrorReason', _wt.DWORD),
        ]

    _TCP_TABLE_OWNER_PID_ALL = 5
    _AF_INET                 = 2
    _TcpConnectionEstatsData = 1

    # Explicit argtypes prevent 64-bit pointer truncation
    _iphlp.GetExtendedTcpTable.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(_wt.DWORD),
        _wt.BOOL, _wt.DWORD, ctypes.c_int, _wt.DWORD,
    ]
    _iphlp.GetExtendedTcpTable.restype = _wt.DWORD

    _iphlp.SetPerTcpConnectionEStats.argtypes = [
        ctypes.POINTER(_MIB_TCPROW), ctypes.c_int,
        ctypes.c_void_p, _wt.DWORD, _wt.DWORD, _wt.DWORD,
    ]
    _iphlp.SetPerTcpConnectionEStats.restype = _wt.DWORD

    _iphlp.GetPerTcpConnectionEStats.argtypes = [
        ctypes.POINTER(_MIB_TCPROW), ctypes.c_int,
        ctypes.c_void_p, _wt.DWORD, _wt.DWORD,
        ctypes.c_void_p, _wt.DWORD, _wt.DWORD,
        ctypes.c_void_p, _wt.DWORD, _wt.DWORD,
    ]
    _iphlp.GetPerTcpConnectionEStats.restype = _wt.DWORD

    def _get_tcp_table():
        size = _wt.DWORD(0)
        _iphlp.GetExtendedTcpTable(None, ctypes.byref(size), False,
                                    _AF_INET, _TCP_TABLE_OWNER_PID_ALL, 0)
        buf = (ctypes.c_byte * size.value)()
        if _iphlp.GetExtendedTcpTable(buf, ctypes.byref(size), False,
                                       _AF_INET, _TCP_TABLE_OWNER_PID_ALL, 0):
            return []
        n   = _wt.DWORD.from_buffer_copy(bytes(buf[:4])).value
        sz  = ctypes.sizeof(_MIB_TCPROW_PID)
        out = []
        off = 4
        for _ in range(n):
            pr = _MIB_TCPROW_PID.from_buffer_copy(bytes(buf[off:off + sz]))
            if pr.dwOwningPid and pr.dwRemoteAddr:   # skip LISTEN / no PID
                base = _MIB_TCPROW(
                    dwState=pr.dwState,
                    dwLocalAddr=pr.dwLocalAddr,
                    dwLocalPort=pr.dwLocalPort,
                    dwRemoteAddr=pr.dwRemoteAddr,
                    dwRemotePort=pr.dwRemotePort,
                )
                out.append((pr.dwOwningPid, base))
            off += sz
        return out

    def _enable(row):
        rw = _ESTATS_DATA_RW(EnableCollection=1)
        _iphlp.SetPerTcpConnectionEStats(
            ctypes.byref(row), _TcpConnectionEstatsData,
            ctypes.byref(rw), 0, ctypes.sizeof(rw), 0)

    def _read(row):
        rod = _ESTATS_DATA_ROD()
        ret = _iphlp.GetPerTcpConnectionEStats(
            ctypes.byref(row), _TcpConnectionEstatsData,
            None, 0, 0,
            None, 0, 0,
            ctypes.byref(rod), 0, ctypes.sizeof(rod))
        return (rod.DataBytesOut, rod.DataBytesIn) if ret == 0 else None

else:
    # Non-Windows stub so the file imports cleanly on dev machines
    def _get_tcp_table():
        return []
    def _enable(row): pass
    def _read(row):   return None


def is_admin():
    if sys.platform != 'win32':
        return True
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


# ── Data store ────────────────────────────────────────────────────────────────

def _fmt(b):
    for u in ('B', 'KB', 'MB', 'GB'):
        if abs(b) < 1024:
            return f'{b:.1f} {u}'
        b /= 1024
    return f'{b:.1f} TB'


class Store:
    def __init__(self):
        self._lk    = threading.Lock()
        self._data  = defaultdict(lambda: [0, 0])   # pid -> [sent, recv]
        self._names = {}                             # pid -> name (cached)
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


# ── TCP monitor (Windows IP Helper API) ──────────────────────────────────────

class TCPMonitor:
    """
    Uses GetPerTcpConnectionEStats (iphlpapi.dll) to track per-connection
    byte counts and attributes them to their owning PID.
    No packet capture driver required.
    """

    def __init__(self, store):
        self._store   = store
        self._prev    = {}   # conn_key -> (bytes_out, bytes_in)
        self._enabled = set()

    def poll(self):
        try:
            table = _get_tcp_table()
        except Exception:
            return

        current = set()

        for pid, row in table:
            try:
                key = (row.dwLocalAddr, row.dwLocalPort,
                       row.dwRemoteAddr, row.dwRemotePort)
                current.add(key)

                if key not in self._enabled:
                    _enable(row)
                    self._enabled.add(key)
                    continue   # first poll: baseline on next tick

                result = _read(row)
                if result is None:
                    continue
                out, inp = result

                if key in self._prev:
                    d_out = max(0, out - self._prev[key][0])
                    d_in  = max(0, inp - self._prev[key][1])
                    if d_out or d_in:
                        self._store.record(pid, d_out, d_in)
                        try:
                            self._store.cache_name(pid, psutil.Process(pid).name())
                        except Exception:
                            pass

                self._prev[key] = (out, inp)
            except Exception:
                continue   # bad connection never kills the loop

        for key in list(self._prev):
            if key not in current:
                del self._prev[key]
                self._enabled.discard(key)

    def run(self):
        while True:
            try:
                self.poll()
            except Exception:
                pass
            time.sleep(POLL_SECS)


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
    monitor = TCPMonitor(store)

    threading.Thread(target=monitor.run, daemon=True, name='tcp-monitor').start()

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
    win.hide()          # start minimized to tray
    win.root.mainloop()


if __name__ == '__main__':
    main()
