#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
 warspear_esp.py — ESP 30Гц + ходьба (Warspear, uc #735117)
================================================================================
ДЕФОЛТНЫЕ НАСТРОЙКИ (вшиты): Sx=2.9, Sy=3.0, ME=(+33,+18).
Якорь Bx/By зависит от позиции на карте — при первом запуске (или после
сброса) нажми «Только центр»: бот кликнет в центр, ME встанет в центр.

КАЛИБРОВКА (В СТОРОНУ → В ЦЕНТР): пересчитывает Sx/Sy и якорь заново.
МОДЕЛЬ:
  экранX = Sx*мирX + Bx                 (камера по X стоит)
  экранY = Sy*(мирY − camY) + By        (camY живой из памяти GM+0x1258+0x88;
                                         фолбэк: якорь AY с доводкой)
ПОЛЗУНКИ: ME остаётся на месте при смене масштаба.
ПОДГОНКА ME: стрелки (Shift=×10), кнопки. Ходьба кликами, автоохота.
Память только ЧИТАЕТСЯ. Приватный сервер, админ, Windows x86.
================================================================================
"""
from __future__ import annotations
import ctypes, ctypes.wintypes as wintypes, json, math, os, struct, sys, threading, time
from typing import Optional, List, Dict, Any, Tuple

user32, kernel32 = ctypes.windll.user32, ctypes.windll.kernel32
WM_MOUSEMOVE, WM_LBUTTONDOWN, WM_LBUTTONUP, MK_LBUTTON = 0x200, 0x201, 0x202, 1
VK_LEFT, VK_RIGHT, VK_UP, VK_DOWN = 0x25, 0x27, 0x26, 0x28
VK_SHIFT = 0x10
PROCESS_VM_READ, PROCESS_QUERY_INFORMATION = 0x10, 0x400
TH32CS_SNAPPROCESS, TH32CS_SNAPMODULE = 2, 8
MEM_COMMIT, PAGE_NOACCESS, PAGE_GUARD = 0x1000, 1, 0x100
READABLE = (0x02 | 0x04 | 0x20 | 0x40)
MAX_PATH = 260
kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.ReadProcessMemory.restype = wintypes.BOOL
kernel32.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p,
                                       ctypes.c_void_p, ctypes.c_size_t,
                                       ctypes.POINTER(ctypes.c_size_t)]
kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE

SIG_GSI = "A1 ? ? ? ? C3 ? ? ? ? ? ? ? ? ? ? 55 8B EC 64 A1"
CAM_SLOT = 0x1258
CAMY_OFF = 0x88
CAL_FILE = "esp_cal2.json"
Y_RELOCK_STILL = 1.5
Y_RELOCK_MIN = 2.0

# ================== ДЕФОЛТНЫЕ НАСТРОЙКИ (твои) ==================
DEF_SX = 2.9
DEF_SY = 3.0
DEF_ME_DX = 33.0
DEF_ME_DY = 18.0
# ================================================================

def hexd(d): return f"0x{d & 0xFFFFFFFF:08X}"

class PE32(ctypes.Structure):
    _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD),
                ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
                ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
                ("th32ParentProcessID", wintypes.DWORD),
                ("pcPriClassBase", ctypes.c_long), ("dwFlags", wintypes.DWORD),
                ("szExeFile", ctypes.c_wchar * MAX_PATH)]
class ME32(ctypes.Structure):
    _fields_ = [("dwSize", wintypes.DWORD), ("th32ModuleID", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD), ("GlblcntUsage", wintypes.DWORD),
                ("ProccntUsage", wintypes.DWORD),
                ("modBaseAddr", ctypes.POINTER(ctypes.c_byte)),
                ("modBaseSize", wintypes.DWORD), ("hModule", wintypes.HMODULE),
                ("szModule", ctypes.c_wchar * 256),
                ("szExePath", ctypes.c_wchar * MAX_PATH)]

def pid_by_name(name):
    try:
        import psutil
        for p in psutil.process_iter(["pid", "name"]):
            if p.info["name"] and p.info["name"].lower() == name.lower():
                return p.info["pid"]
    except ImportError:
        pass
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if not snap: return None
    try:
        e = PE32(); e.dwSize = ctypes.sizeof(PE32)
        if kernel32.Process32FirstW(snap, ctypes.byref(e)):
            while True:
                if e.szExeFile.lower() == name.lower():
                    return int(e.th32ProcessID)
                if not kernel32.Process32NextW(snap, ctypes.byref(e)):
                    break
        return None
    finally:
        kernel32.CloseHandle(snap)

def find_module(pid, name_lower):
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid)
    if not snap: return None
    try:
        e = ME32(); e.dwSize = ctypes.sizeof(ME32)
        if kernel32.Module32FirstW(snap, ctypes.byref(e)):
            while True:
                if e.szModule.lower() == name_lower:
                    base = ctypes.cast(e.modBaseAddr, ctypes.c_void_p).value or 0
                    return {"name": e.szModule, "base": base,
                            "size": int(e.modBaseSize)}
                if not kernel32.Module32NextW(snap, ctypes.byref(e)):
                    break
        return None
    finally:
        kernel32.CloseHandle(snap)

def _parse_pattern(p):
    fixed, mask = [], []
    for t in p.split():
        if t in ("?", "??"):
            fixed.append(0); mask.append(True)
        else:
            fixed.append(int(t, 16)); mask.append(False)
    return bytes(fixed), mask

def fast_find(mem, base, size, pattern):
    fixed, mask = _parse_pattern(pattern)
    if not fixed: return None
    data = mem.read(base, size)
    if not data: return None
    n = len(fixed); bl = bs = 0; cs = None; cl = 0
    for i, m in enumerate(mask):
        if not m:
            if cs is None: cs = i
            cl += 1
            if cl > bl: bl, bs = cl, cs
        else:
            cs, cl = None, 0
    if bl == 0: return None
    anchor = fixed[bs:bs+bl]
    pos = data.find(anchor)
    while pos != -1:
        start = pos - bs
        if 0 <= start <= len(data) - n:
            if all(mask[j] or data[start+j] == fixed[j] for j in range(n)):
                return base + start
        pos = data.find(anchor, pos + 1)
    return None

def _score(s):
    if not s: return 0.0
    good = sum(1 for c in s if 0x20 <= ord(c) <= 0x7E or 0x400 <= ord(c) <= 0x4FF
               or 0xC0 <= ord(c) <= 0x24F or c in "«»—…'’ ")
    ctrl = sum(1 for c in s if ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F)
    return max(0.0, good/len(s) - 0.5*ctrl)

def decode_wide(data):
    out = bytearray()
    for i in range(0, len(data)-1, 2):
        if data[i] == 0 and data[i+1] == 0: break
        out += data[i:i+2]
    return bytes(out).decode("utf-16-le", errors="ignore")

def decode_narrow(data):
    s = data.split(b"\x00", 1)[0]
    best, bs = "", 0.0
    for enc in ("utf-8", "cp1251", "latin-1"):
        try: t = s.decode(enc)
        except UnicodeDecodeError: continue
        if _score(t) > bs: best, bs = t, _score(t)
    return best

def smart_decode(data):
    if not data: return ""
    w, n = decode_wide(data), decode_narrow(data)
    sw, sn = _score(w), _score(n)
    if abs(sw - sn) < 0.05:
        return w if len(w) >= len(n) else n
    return w if sw > sn else n

class Memory:
    def __init__(self, pid):
        self.pid = pid
        self.handle = kernel32.OpenProcess(
            PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
        if not self.handle:
            raise RuntimeError(f"OpenProcess err={ctypes.GetLastError()} — нужен админ")
    def close(self):
        if self.handle:
            kernel32.CloseHandle(self.handle); self.handle = None
    def read(self, a, n):
        if a == 0 or n <= 0: return None
        buf = (ctypes.c_byte*n)(); br = ctypes.c_size_t()
        ok = kernel32.ReadProcessMemory(self.handle, ctypes.c_void_p(a), buf, n,
                                        ctypes.byref(br))
        return bytes(buf) if (ok and br.value == n) else None
    def read_int32(self, a):
        d = self.read(a, 4); return struct.unpack("<i", d)[0] if d else None
    def read_uint32(self, a):
        d = self.read(a, 4); return struct.unpack("<I", d)[0] if d else None
    def read_float(self, a):
        d = self.read(a, 4); return struct.unpack("<f", d)[0] if d else None
    def is_readable(self, a, n=1):
        class MBI(ctypes.Structure):
            _fields_ = [("BaseAddress", ctypes.c_void_p),
                        ("AllocationBase", ctypes.c_void_p),
                        ("AllocationProtect", wintypes.DWORD),
                        ("RegionSize", ctypes.c_size_t), ("State", wintypes.DWORD),
                        ("Protect", wintypes.DWORD), ("Type", wintypes.DWORD)]
        mbi = MBI()
        if kernel32.VirtualQueryEx(self.handle, ctypes.c_void_p(a),
                                   ctypes.byref(mbi), ctypes.sizeof(mbi)) == 0:
            return False
        if mbi.State != MEM_COMMIT or (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)):
            return False
        return bool(mbi.Protect & READABLE)

class GameWindow:
    def __init__(self, pid):
        self.hwnd = self._find_hwnd(pid)
        self.ok = bool(self.hwnd)
        self.w = self.h = 0
        if self.ok:
            r = wintypes.RECT()
            if user32.GetClientRect(self.hwnd, ctypes.byref(r)):
                self.w, self.h = r.right, r.bottom
        self.ok = self.ok and self.w > 50 and self.h > 50
    @staticmethod
    def _find_hwnd(pid):
        res = []
        CB = ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, wintypes.LPARAM)
        def cb(hwnd, lp):
            w = wintypes.DWORD()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(w))
            if w.value == pid and user32.IsWindowVisible(hwnd):
                res.append(hwnd); return False
            return True
        user32.EnumWindows(CB(cb), 0)
        return res[0] if res else 0

def send_click(hwnd, x, y, mode="post"):
    ix, iy = max(0, int(round(x))), max(0, int(round(y)))
    lp = ((iy & 0xFFFF) << 16) | (ix & 0xFFFF)
    if mode == "real":
        pt = wintypes.POINT(ix, iy)
        user32.ClientToScreen(hwnd, ctypes.byref(pt))
        user32.SetCursorPos(pt.x, pt.y)
        time.sleep(0.02)
        user32.mouse_event(2, 0, 0, 0, 0)
        time.sleep(0.03)
        user32.mouse_event(4, 0, 0, 0, 0)
        return
    user32.PostMessageW(hwnd, WM_MOUSEMOVE, 0, lp)
    time.sleep(0.03)
    fn = user32.SendMessageW if mode == "send" else user32.PostMessageW
    fn(hwnd, WM_LBUTTONDOWN, MK_LBUTTON, lp)
    time.sleep(0.05)
    fn(hwnd, WM_LBUTTONUP, 0, lp)

class GameReader:
    def __init__(self, mem, module, log_fn):
        self.mem, self.module, self.log = mem, module, log_fn
        self.si = self.gm = 0
    def connect(self):
        addr = fast_find(self.mem, self.module["base"], self.module["size"], SIG_GSI)
        if not addr:
            self.log("[!] Сигнатура GetGlobalSystemInstance не найдена"); return False
        b = self.mem.read(addr+1, 4)
        if not b: return False
        self.si = struct.unpack("<I", b)[0]
        self.log(f"[+] SystemInstance @ {hexd(self.si)}")
        return True
    def gm_ptr(self):
        sv = self.mem.read_uint32(self.si) or 0
        if not sv: return 0
        self.gm = self.mem.read_uint32(sv + 0x14) or 0
        return self.gm
    def lp(self):
        gm = self.gm_ptr()
        return (self.mem.read_uint32(gm + 0x40) or 0) if gm else 0
    def pos(self):
        lp = self.lp()
        if not lp: return None
        x = self.mem.read_int32(lp + 0x10); y = self.mem.read_int32(lp + 0x14)
        if x is None or y is None: return None
        return (x/65536.0, y/65536.0)
    def hp(self):
        lp = self.lp()
        if not lp: return None
        c = self.mem.read_int32(lp + 0x10C); m = self.mem.read_int32(lp + 0x110)
        if c is None or m is None or m <= 0: return None
        return (c, m)
    def cam_y(self):
        try:
            gm = self.gm_ptr()
            if not gm: return None
            p = self.mem.read_uint32(gm + CAM_SLOT)
            if not p or not self.mem.is_readable(p + CAMY_OFF, 4): return None
            v = self.mem.read_float(p + CAMY_OFF)
            if v is None or abs(v) > 1e6: return None
            return v
        except Exception:
            return None
    def read_name(self, obj):
        mem = self.mem
        best, bs = "", 0.0
        for off in (0x64, 0x60, 0x68):
            p = mem.read_uint32(obj + off)
            if p and mem.is_readable(p, 64):
                t = smart_decode(mem.read(p, 64) or b"")
                if _score(t) > bs: best, bs = t, _score(t)
        t = smart_decode(mem.read(obj + 0x64, 64) or b"")
        if _score(t) > bs: best = t
        return best
    def ent_xy(self, obj):
        x = self.mem.read_int32(obj + 0x10); y = self.mem.read_int32(obj + 0x14)
        if x is None or y is None: return None
        return (x/65536.0, y/65536.0)
    def entities(self, max_nodes=4096):
        out = []
        gm = self.gm_ptr()
        if not gm: return out
        header = self.mem.read_uint32(gm + 0x3C)
        if not header: return out
        root = self.mem.read_uint32(header)
        if not root: return out
        visited = set()
        def walk(node, depth):
            if not node or depth > 32 or len(out) >= max_nodes or node in visited:
                return
            visited.add(node)
            left = self.mem.read_uint32(node + 4)
            right = self.mem.read_uint32(node + 8)
            eid = self.mem.read_uint32(node + 0x10)
            obj = self.mem.read_uint32(node + 0x14)
            walk(left, depth+1)
            if obj:
                e = {"id": eid or 0, "obj": obj, "name": "", "x": 0.0, "y": 0.0}
                e["name"] = self.read_name(obj)
                xy = self.ent_xy(obj)
                if xy: e["x"], e["y"] = xy
                out.append(e)
            walk(right, depth+1)
        walk(root, 0)
        return out

class Overlay:
    def __init__(self, app):
        import tkinter as tk
        self.win = tk.Toplevel(app)
        self.win.overrideredirect(True)
        self.win.attributes("-topmost", True)
        self.win.config(bg="magenta")
        self.win.attributes("-transparentcolor", "magenta")
        self.cv = tk.Canvas(self.win, bg="magenta", highlightthickness=0)
        self.cv.pack(fill=tk.BOTH, expand=True)
        hwnd = user32.GetParent(self.win.winfo_id())
        style = user32.GetWindowLongW(hwnd, -20)
        user32.SetWindowLongW(hwnd, -20, style | 0x00080000 | 0x20 | 0x80)
        self._geom = ""
    def place_over_game(self, gw):
        if not gw or not gw.ok: return
        pt = wintypes.POINT(0, 0)
        user32.ClientToScreen(gw.hwnd, ctypes.byref(pt))
        g = f"{gw.w}x{gw.h}+{pt.x}+{pt.y}"
        if g != self._geom:
            self.win.geometry(g); self._geom = g
    def draw(self, items, player_sp, info, opts):
        cv = self.cv
        cv.delete("all")
        if not opts.get("enabled", True): return
        if opts.get("player") and player_sp:
            px, py = player_sp
            self._box(px, py, "#22ff66", 1.3, True)
            cv.create_text(px, py - 44, text="ME", fill="#22ff66",
                           font=("Consolas", 9, "bold"))
        for sx, sy, label, dist, sel in items:
            color = "#ffd400" if sel else "#ff3b3b"
            if opts.get("lines") and player_sp:
                cv.create_line(player_sp[0], player_sp[1], sx, sy - 20, fill=color)
            self._box(sx, sy, color, 1.0, sel)
            if opts.get("names"):
                cv.create_text(sx, sy - 44, text=label, fill="#ffffff",
                               font=("Consolas", 8, "bold"))
            if opts.get("dist") and dist is not None:
                cv.create_text(sx, sy + 6, text=f"{dist:.0f}m",
                               fill="#c8c8c8", font=("Consolas", 7))
        cv.create_text(10, 10, anchor="nw", text=info,
                       fill="#7fff7f", font=("Consolas", 9, "bold"))
    def _box(self, sx, sy, color, k, sel):
        cv = self.cv
        hw, h = 13*k, 34*k
        x0, y0, x1, y1 = sx-hw, sy-h, sx+hw, sy
        L = max(5, int(7*k))
        for args in ((x0, y0, x0+L, y0), (x0, y0, x0, y0+L),
                     (x1-L, y0, x1, y0), (x1, y0, x1, y0+L),
                     (x0, y1-L, x0, y1), (x0, y1, x0+L, y1),
                     (x1-L, y1, x1, y1), (x1, y1-L, x1, y1)):
            cv.create_line(*args, fill=color, width=2)
        if sel:
            cv.create_rectangle(x0-3, y0-3, x1+3, y1+3, outline="#ffffff", width=1)
    def clear(self):
        self.cv.delete("all")

def run_gui():
    import tkinter as tk
    from tkinter import ttk, messagebox
    SAFE_MARGIN, UI_BOTTOM = 8, 130

    class App(tk.Tk):
        def __init__(self):
            super().__init__()
            self.title("Warspear ESP — дефолт: Sx=2.9 Sy=3.0 ME=(+33,+18)")
            self.geometry("940x820")
            self.mem = None
            self.reader = None
            self.win = None
            self.pid = None
            self.lock = threading.Lock()
            # ДЕФОЛТЫ вшиты; если в json есть сохранённые — перезапишутся ниже
            self.Sx = DEF_SX
            self.Sy = DEF_SY
            self.Bx = self.By = None    # якорь требует «Только центр»
            self.AY = None
            self.user_sx = 1.0
            self.user_sy = 1.0
            self.me_dx = DEF_ME_DX
            self.me_dy = DEF_ME_DY
            self._y_last = None
            self._y_still_since = None
            self.esp_ents = []
            self.last_ents = []
            self.selected_obj = None
            self.overlay = None
            self.esp_running = False
            self.hunt_stop = threading.Event()
            self.hunt_thread = None
            self.walk_stop = threading.Event()
            self.walk_thread = None
            self.calibrating = False
            self._load_cal()     # если сохранение есть — оно главнее дефолтов
            self._build_ui()
            self.after(300, self._tick)
            self.after(500, self._y_watch)

        # ---------- persist ----------
        def _load_cal(self):
            try:
                with open(CAL_FILE, "r", encoding="utf-8") as f:
                    d = json.load(f)
                if d.get("Sx") is not None:
                    self.Sx = float(d["Sx"]); self.Sy = float(d["Sy"])
                    self.Bx = float(d["Bx"]) if d.get("Bx") is not None else None
                    self.By = float(d["By"]) if d.get("By") is not None else None
                    self.AY = float(d["AY"]) if d.get("AY") is not None else None
                if d.get("me_dx") is not None:
                    self.me_dx = float(d["me_dx"])
                    self.me_dy = float(d.get("me_dy", 0.0))
                self.user_sx = float(d.get("user_sx", 1.0))
                self.user_sy = float(d.get("user_sy", 1.0))
            except Exception:
                pass

        def _save_cal(self):
            try:
                with open(CAL_FILE, "w", encoding="utf-8") as f:
                    json.dump({"Sx": self.Sx, "Sy": self.Sy,
                               "Bx": self.Bx, "By": self.By, "AY": self.AY,
                               "user_sx": self.user_sx, "user_sy": self.user_sy,
                               "me_dx": self.me_dx, "me_dy": self.me_dy},
                              f, indent=2)
            except Exception:
                pass

        def _upd_cal_lbl(self):
            if self.Bx is None:
                self.cal_lbl.configure(
                    text=f"Sx={self._eff_Sx():.2f} Sy={self._eff_Sy():.2f} ✔ — "
                         f"нажми «Только центр»", foreground="#b33")
            else:
                self.cal_lbl.configure(
                    text=f"Sx={self._eff_Sx():.2f} Sy={self._eff_Sy():.2f} "
                         f"ME=({self.me_dx:+.0f},{self.me_dy:+.0f}) ✔",
                    foreground="#2a2")

        def _upd_me_lbl(self):
            self.me_lbl.configure(text=f"ME: ({self.me_dx:+.0f},{self.me_dy:+.0f})")

        # ---------- UI ----------
        def _build_ui(self):
            top = ttk.Frame(self, padding=8); top.pack(side=tk.TOP, fill=tk.X)
            ttk.Label(top, text="Процесс:").pack(side=tk.LEFT)
            self.proc_var = tk.StringVar(value="warspear.exe")
            ttk.Combobox(top, textvariable=self.proc_var, width=18).pack(side=tk.LEFT, padx=4)
            self.btn_conn = ttk.Button(top, text="Подключиться", command=self.connect)
            self.btn_conn.pack(side=tk.LEFT, padx=4)
            self.btn_disc = ttk.Button(top, text="Отключиться", command=self.disconnect,
                                       state=tk.DISABLED)
            self.btn_disc.pack(side=tk.LEFT, padx=4)
            self.conn_lbl = ttk.Label(top, text="не подключено", foreground="#b33")
            self.conn_lbl.pack(side=tk.LEFT, padx=12)
            self.info_lbl = ttk.Label(self, text="—", font=("Consolas", 12, "bold"),
                                      padding=(10, 2))
            self.info_lbl.pack(anchor=tk.W)

            crow = ttk.Frame(self, padding=(10, 0)); crow.pack(fill=tk.X)
            ttk.Button(crow, text="КАЛИБРОВКА (полная)",
                       command=self.auto_calibrate).pack(side=tk.LEFT)
            ttk.Button(crow, text="Только центр",
                       command=self.recenter).pack(side=tk.LEFT, padx=6)
            ttk.Button(crow, text="Сброс",
                       command=self.cal_reset).pack(side=tk.LEFT, padx=6)
            self.cal_lbl = ttk.Label(crow, text="—",
                                     font=("Consolas", 9), foreground="#b33")
            self.cal_lbl.pack(side=tk.LEFT, padx=10)
            ttk.Label(crow, text="Клики:").pack(side=tk.LEFT, padx=(12, 2))
            self.mode_var = tk.StringVar(value="post")
            ttk.Combobox(crow, textvariable=self.mode_var, width=6, state="readonly",
                         values=["post", "send", "real"]).pack(side=tk.LEFT)

            mrow = ttk.Frame(self, padding=(10, 0)); mrow.pack(fill=tk.X)
            ttk.Label(mrow, text="Подгонка ME (стрелки на клаве при фокусе на проге, "
                                 "Shift=×10):").pack(side=tk.LEFT)
            for txt, dx, dy in (("←", -1, 0), ("→", 1, 0), ("↑", 0, -1), ("↓", 0, 1)):
                ttk.Button(mrow, text=txt, width=2,
                           command=lambda a=dx, b=dy: self.nudge_me(a, b)
                           ).pack(side=tk.LEFT, padx=1)
            ttk.Button(mrow, text="Сброс ME",
                       command=self.me_reset).pack(side=tk.LEFT, padx=6)
            self.me_lbl = ttk.Label(mrow, text=f"ME: ({self.me_dx:+.0f},{self.me_dy:+.0f})",
                                    font=("Consolas", 9))
            self.me_lbl.pack(side=tk.LEFT, padx=4)

            srow = ttk.Frame(self, padding=(10, 0)); srow.pack(fill=tk.X)
            ttk.Label(srow, text="Масштаб X:").pack(side=tk.LEFT)
            self.sx_var = tk.DoubleVar(value=self.user_sx)
            ttk.Scale(srow, from_=0.6, to=1.6, variable=self.sx_var, length=190,
                      command=self._on_scale).pack(side=tk.LEFT, padx=4)
            self.sx_lbl = ttk.Label(srow, text=f"{self.user_sx:.2f}×", width=6,
                                    font=("Consolas", 9))
            self.sx_lbl.pack(side=tk.LEFT)
            ttk.Label(srow, text="Масштаб Y:").pack(side=tk.LEFT, padx=(14, 0))
            self.sy_var = tk.DoubleVar(value=self.user_sy)
            ttk.Scale(srow, from_=0.6, to=1.6, variable=self.sy_var, length=190,
                      command=self._on_scale).pack(side=tk.LEFT, padx=4)
            self.sy_lbl = ttk.Label(srow, text=f"{self.user_sy:.2f}×", width=6,
                                    font=("Consolas", 9))
            self.sy_lbl.pack(side=tk.LEFT)

            erow = ttk.Frame(self, padding=(10, 0)); erow.pack(fill=tk.X)
            self.esp_enabled = tk.BooleanVar(value=True)
            self.esp_names = tk.BooleanVar(value=True)
            self.esp_dist = tk.BooleanVar(value=True)
            self.esp_lines = tk.BooleanVar(value=True)
            self.esp_player = tk.BooleanVar(value=True)
            for txt, var in (("ESP", self.esp_enabled), ("Имена", self.esp_names),
                             ("Дистанции", self.esp_dist), ("Трейсеры", self.esp_lines),
                             ("Игрок", self.esp_player)):
                ttk.Checkbutton(erow, text=txt, variable=var).pack(side=tk.LEFT)

            main = ttk.Frame(self, padding=(8, 2)); main.pack(fill=tk.BOTH, expand=True)
            wf = ttk.Labelframe(main, text="Ходьба", padding=8); wf.pack(fill=tk.X, pady=4)
            ttk.Label(wf, text="Точка X:").grid(row=0, column=0)
            self.wx = tk.StringVar(value="0.0")
            ttk.Entry(wf, textvariable=self.wx, width=9).grid(row=0, column=1, padx=3)
            ttk.Label(wf, text="Y:").grid(row=0, column=2)
            self.wy = tk.StringVar(value="0.0")
            ttk.Entry(wf, textvariable=self.wy, width=9).grid(row=0, column=3, padx=3)
            ttk.Button(wf, text="← моя позиция", command=self.walk_copy_pos).grid(row=0, column=4, padx=3)
            ttk.Button(wf, text="Идти в точку", command=self.walk_to_point).grid(row=0, column=5, padx=6)
            ttk.Button(wf, text="Идти к выбранному энтити", command=self.walk_to_selected).grid(row=0, column=6, padx=6)
            ttk.Button(wf, text="■ Стоп", command=self.walk_stop_fn).grid(row=0, column=7, padx=6)

            ef = ttk.Labelframe(main, text="Сущности", padding=8)
            ef.pack(fill=tk.BOTH, expand=True, pady=4)
            cols = ("name", "id", "dist", "x", "y", "obj")
            self.ent_tree = ttk.Treeview(ef, columns=cols, show="headings", height=8)
            for c, h, w in zip(cols, ("Name", "ID", "Dist", "X", "Y", "obj"),
                               (170, 90, 60, 80, 80, 100)):
                self.ent_tree.heading(c, text=h)
                self.ent_tree.column(c, width=w, anchor=tk.W)
            ys = ttk.Scrollbar(ef, orient=tk.VERTICAL, command=self.ent_tree.yview)
            self.ent_tree.configure(yscrollcommand=ys.set)
            self.ent_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            ys.pack(side=tk.RIGHT, fill=tk.Y)
            self.ent_menu = tk.Menu(self, tearoff=0)
            self.ent_menu.add_command(label="Идти к нему", command=self.walk_to_selected)
            self.ent_tree.bind("<Button-3>", self._show_ent_menu)
            er = ttk.Frame(ef); er.pack(fill=tk.X, pady=(4, 0))
            ttk.Label(er, text="Фильтр:").pack(side=tk.LEFT)
            self.ent_filter = tk.StringVar(value="")
            ttk.Entry(er, textvariable=self.ent_filter, width=12).pack(side=tk.LEFT, padx=4)
            ttk.Button(er, text="Идти к ближайшему", command=self.walk_to_nearest).pack(side=tk.LEFT, padx=6)

            hf = ttk.Labelframe(main, text="Автоохота", padding=8); hf.pack(fill=tk.X, pady=4)
            ttk.Label(hf, text="Имя цели:").grid(row=0, column=0)
            self.hname = tk.StringVar(value="Rat")
            ttk.Entry(hf, textvariable=self.hname, width=12).grid(row=0, column=1, padx=3)
            ttk.Label(hf, text="Радиус:").grid(row=0, column=2)
            self.hradius = tk.StringVar(value="40")
            ttk.Entry(hf, textvariable=self.hradius, width=6).grid(row=0, column=3, padx=3)
            ttk.Label(hf, text="Стоп при HP<%:").grid(row=0, column=4)
            self.hhp = tk.StringVar(value="25")
            ttk.Entry(hf, textvariable=self.hhp, width=5).grid(row=0, column=5, padx=3)
            self.btn_hunt = ttk.Button(hf, text="▶ Охота", command=self.hunt_start)
            self.btn_hunt.grid(row=0, column=6, padx=8)
            self.btn_hstop = ttk.Button(hf, text="■ Стоп", command=self.hunt_stop_fn,
                                        state=tk.DISABLED)
            self.btn_hstop.grid(row=0, column=7)

            lf = ttk.Labelframe(self, text="Лог", padding=4); lf.pack(fill=tk.BOTH, padx=8, pady=(0, 8))
            self.log_text = tk.Text(lf, height=8, font=("Consolas", 9),
                                    state=tk.DISABLED, wrap=tk.NONE)
            ys2 = ttk.Scrollbar(lf, orient=tk.VERTICAL, command=self.log_text.yview)
            self.log_text.configure(yscrollcommand=ys2.set)
            self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            ys2.pack(side=tk.RIGHT, fill=tk.Y)

        def log(self, msg):
            self.log_text.configure(state=tk.NORMAL)
            self.log_text.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] {msg}\n")
            self.log_text.see(tk.END)
            self.log_text.configure(state=tk.DISABLED)

        def _show_ent_menu(self, ev):
            iid = self.ent_tree.identify_row(ev.y)
            if iid:
                self.ent_tree.selection_set(iid)
                self.ent_menu.post(ev.x_root, ev.y_root)

        # ---------- подгонка ME ----------
        def nudge_me(self, dx, dy):
            self.me_dx += dx
            self.me_dy += dy
            self._save_cal()
            self._upd_me_lbl()
            self._upd_cal_lbl()

        def me_reset(self):
            self.me_dx = DEF_ME_DX
            self.me_dy = DEF_ME_DY
            self._save_cal()
            self._upd_me_lbl()
            self._upd_cal_lbl()
            self.log(f"[me] сдвиг сброшен к дефолту ({DEF_ME_DX:+.0f},{DEF_ME_DY:+.0f})")

        def _arrow_loop(self):
            while self.esp_running:
                step = 10 if user32.GetAsyncKeyState(VK_SHIFT) & 0x8000 else 1
                moved = False
                if user32.GetAsyncKeyState(VK_LEFT) & 0x8000:
                    self.after(0, lambda s=step: self.nudge_me(-s, 0)); moved = True
                elif user32.GetAsyncKeyState(VK_RIGHT) & 0x8000:
                    self.after(0, lambda s=step: self.nudge_me(s, 0)); moved = True
                if user32.GetAsyncKeyState(VK_UP) & 0x8000:
                    self.after(0, lambda s=step: self.nudge_me(0, -s)); moved = True
                elif user32.GetAsyncKeyState(VK_DOWN) & 0x8000:
                    self.after(0, lambda s=step: self.nudge_me(0, s)); moved = True
                time.sleep(0.12 if moved else 0.05)

        # ---------- ползунки (ME на месте) ----------
        def _cam_y_eff(self):
            cy = self.reader.cam_y() if self.reader else None
            return cy if cy is not None else self.AY

        def _on_scale(self, _v=None):
            try:
                new_sx = float(self.sx_var.get())
                new_sy = float(self.sy_var.get())
            except Exception:
                return
            p = self.reader.pos() if self.reader else None
            cam = self._cam_y_eff()
            camv = cam if cam is not None else 0.0
            with self.lock:
                old_Bx, old_By = self.Bx, self.By
                if old_Bx is None or old_By is None or p is None:
                    self.user_sx = new_sx
                    self.user_sy = new_sy
                else:
                    old_sx = self.Sx * self.user_sx
                    old_sy = self.Sy * self.user_sy
                    ex = old_sx * p[0] + old_Bx
                    ey = old_sy * (p[1] - camv) + old_By
                    self.user_sx = new_sx
                    self.user_sy = new_sy
                    self.Bx = ex - self._eff_Sx() * p[0]
                    self.By = ey - self._eff_Sy() * (p[1] - camv)
            self.sx_lbl.configure(text=f"{self.user_sx:.2f}×")
            self.sy_lbl.configure(text=f"{self.user_sy:.2f}×")
            self._save_cal()
            self._upd_cal_lbl()

        def _eff_Sx(self):
            return self.Sx * self.user_sx

        def _eff_Sy(self):
            return self.Sy * self.user_sy

        # ---------- connect ----------
        def connect(self):
            try:
                name = self.proc_var.get().strip() or "warspear.exe"
                pid = pid_by_name(name)
                if not pid:
                    messagebox.showerror("Подключение", f"Процесс {name} не найден"); return
                module = find_module(pid, name.lower())
                if not module:
                    messagebox.showerror("Подключение", f"Модуль {name} не найден"); return
                mem = Memory(pid)
                reader = GameReader(mem, module, self.log)
                if not reader.connect():
                    mem.close(); return
                self.mem, self.reader, self.pid = mem, reader, pid
                self.win = GameWindow(pid)
                if self.win.ok:
                    self.log(f"[+] окно: {self.win.w}x{self.win.h}")
                else:
                    self.log("[!] окно игры не найдено!")
                if not reader.lp():
                    self.log("[!] LocalPlayer пуст — зайди в игру")
                cy = reader.cam_y()
                if cy is not None:
                    self.log(f"[+] camY из памяти: {cy:.1f} ✔ — ось Y точная")
                else:
                    self.log("[!] camY не читается — ось Y по якорю с доводкой")
                if self.Bx is None:
                    self.log("[i] Дефолт вшит: Sx=2.9 Sy=3.0 ME=(+33,+18). "
                             "Нажми «Только центр» для привязки к текущей точке карты.")
                self.conn_lbl.configure(text=f"PID {pid} OK", foreground="#2a2")
                self.btn_conn.configure(state=tk.DISABLED)
                self.btn_disc.configure(state=tk.NORMAL)
                self._upd_cal_lbl()
                self._upd_me_lbl()
                self.after(200, self._ensure_overlay)
                if not any(t.name == "arrows" for t in threading.enumerate()):
                    threading.Thread(target=self._arrow_loop, daemon=True,
                                     name="arrows").start()
            except RuntimeError as e:
                messagebox.showerror("Подключение", str(e))

        def disconnect(self):
            self.esp_running = False
            self.hunt_stop.set()
            self.walk_stop.set()
            if self.overlay:
                try: self.overlay.win.destroy()
                except Exception: pass
                self.overlay = None
            if self.mem:
                try: self.mem.close()
                except Exception: pass
            self.mem = self.reader = None
            self.conn_lbl.configure(text="не подключено", foreground="#b33")
            self.btn_conn.configure(state=tk.NORMAL)
            self.btn_disc.configure(state=tk.DISABLED)

        def _need(self):
            if not (self.reader and self.win and self.win.ok):
                messagebox.showinfo("ESP", "Подключись (окно игры должно быть найдено)")
                return False
            return True

        # ---------- модель W2S ----------
        def w2s(self, wx, wy):
            with self.lock:
                Sx = self._eff_Sx() if self.Sx is not None else None
                Sy = self._eff_Sy() if self.Sy is not None else None
                Bx, By = self.Bx, self.By
            if Sx is None or Sy is None or Bx is None or By is None:
                return None
            cy = self._cam_y_eff()
            if cy is None:
                return None
            return (Sx * wx + Bx + self.me_dx,
                    Sy * (wy - cy) + By + self.me_dy)

        def _in_safe_zone(self, sx, sy):
            W, H = float(self.win.w), float(self.win.h)
            return (SAFE_MARGIN <= sx <= W - SAFE_MARGIN and
                    SAFE_MARGIN <= sy <= H - UI_BOTTOM)

        # ---------- Y-доводка (фолбэк) ----------
        def _y_watch(self):
            try:
                if self.reader and self.Sx is not None and not self.calibrating:
                    if self.reader.cam_y() is not None:
                        self.after(300, self._y_watch)
                        return
                    p = self.reader.pos()
                    if p:
                        if self._y_last is not None and \
                           math.hypot(p[0]-self._y_last[0], p[1]-self._y_last[1]) < 0.05:
                            if self._y_still_since is None:
                                self._y_still_since = time.time()
                            elif time.time() - self._y_still_since >= Y_RELOCK_STILL:
                                if self.AY is not None and \
                                   abs(p[1] - self.AY) >= Y_RELOCK_MIN:
                                    self.AY = p[1]
                                    self._save_cal()
                                    self.log(f"[y] доводка: AY={p[1]:.1f}")
                                self._y_still_since = time.time()
                        else:
                            self._y_still_since = None
                        self._y_last = p
            except Exception:
                pass
            self.after(300, self._y_watch)

        # ---------- КАЛИБРОВКА: в сторону → в центр ----------
        def auto_calibrate(self):
            if not self._need(): return
            if self.calibrating: return
            self.calibrating = True
            self.log("[cal] 1) клик В СТОРОНУ (+320,+230) → 2) клик В ЦЕНТР → "
                     "ME встанет в центр. Мышь не трогать.")
            def thread_cal():
                try:
                    self._auto_cal_sync()
                finally:
                    self.calibrating = False
            threading.Thread(target=thread_cal, daemon=True).start()

        def _auto_cal_sync(self):
            W, H = float(self.win.w), float(self.win.h)
            hwnd, mode = self.win.hwnd, self.mode_var.get()
            p0 = self.reader.pos()
            if not p0:
                self.log("[cal] нет позиции игрока"); return
            P1 = (W/2 + 320, H/2 + 230)
            send_click(hwnd, *P1, mode)
            p1 = self._wait_arrive()
            if not p1:
                self.log("[cal] клик 1 (в сторону) не дошёл (открытое место!)"); return
            cam1 = self.reader.cam_y()
            P2 = (W/2, H/2)
            send_click(hwnd, *P2, mode)
            p2 = self._wait_arrive()
            if not p2:
                self.log("[cal] клик 2 (в центр) не дошёл"); return
            cam2 = self.reader.cam_y()
            dwx = p2[0] - p1[0]
            dwy = p2[1] - p1[1]
            if abs(dwx) < 10 or abs(dwy) < 8:
                self.log(f"[cal] диагональный сдвиг мал "
                         f"(Δx={dwx:.1f}, Δy={dwy:.1f}) — повтори")
                return
            Sx = abs(P2[0] - P1[0]) / abs(dwx)
            if cam1 is not None and cam2 is not None:
                den_y = (p2[1] - cam2) - (p1[1] - cam1)
                Sy = abs(P2[1] - P1[1]) / abs(den_y) if abs(den_y) > 5 else None
                cy_note = "camY из памяти"
            else:
                Sy = abs(P2[1] - P1[1]) / abs(dwy)
                cy_note = "camY недоступен — якорная модель"
            if Sy is None:
                self.log("[cal] Sy вырожден — повтори"); return
            cam_here = cam2 if cam2 is not None else p2[1]
            Bx = W/2 - Sx * p2[0]
            By = H/2 - Sy * (p2[1] - cam_here)
            with self.lock:
                self.Sx, self.Sy = Sx, Sy
                self.Bx, self.By = Bx, By
                self.AY = p2[1]
            self._save_cal()
            self._upd_cal_lbl()
            self.log(f"[cal] ✔ Sx={Sx:.2f} Sy={Sy:.2f}px/юнит ({cy_note}); "
                     f"ME В ЦЕНТРЕ (мир {p2[0]:.1f},{p2[1]:.1f})")

        def _wait_arrive(self, timeout=25.0):
            last, stable, t0 = None, 0, time.time()
            while time.time() - t0 < timeout:
                p = self.reader.pos()
                if p:
                    if last and math.hypot(p[0]-last[0], p[1]-last[1]) < 0.05:
                        stable += 1
                        if stable >= 6: return p
                    else:
                        stable = 0
                    last = p
                time.sleep(0.2)
            return last

        def recenter(self):
            if not self._need(): return
            if self.calibrating: return
            self.calibrating = True
            def thread_cal():
                try:
                    W, H = float(self.win.w), float(self.win.h)
                    send_click(self.win.hwnd, W/2, H/2, self.mode_var.get())
                    p = self._wait_arrive()
                    if not p:
                        p = self.reader.pos()
                        if not p:
                            self.log("[cal] клик не дошёл"); return
                    cam = self.reader.cam_y()
                    cam = cam if cam is not None else p[1]
                    with self.lock:
                        self.Bx = W/2 - self._eff_Sx() * p[0]
                        self.By = H/2 - self._eff_Sy() * (p[1] - cam)
                        self.AY = p[1]
                    self._save_cal()
                    self._upd_cal_lbl()
                    self.log(f"[cal] центр перепривязан: ME в центре "
                             f"(мир {p[0]:.1f},{p[1]:.1f})")
                finally:
                    self.calibrating = False
            threading.Thread(target=thread_cal, daemon=True).start()

        def cal_reset(self):
            with self.lock:
                self.Sx, self.Sy = DEF_SX, DEF_SY
                self.Bx = self.By = None
                self.AY = None
                self.me_dx, self.me_dy = DEF_ME_DX, DEF_ME_DY
                self.user_sx = self.user_sy = 1.0
            self._save_cal()
            self._upd_cal_lbl()
            self._upd_me_lbl()
            self.log("[cal] сброшена к ДЕФОЛТАМ (Sx=2.9 Sy=3.0 ME=(+33,+18)); "
                     "нажми «Только центр»")

        # ---------- клики / ходьба ----------
        def _click_world(self, wx, wy, lift=25):
            s = self.w2s(wx, wy)
            if not s: return False
            sx, sy = s[0], s[1] - lift
            if not self._in_safe_zone(sx, sy): return False
            send_click(self.win.hwnd, sx, sy, self.mode_var.get())
            return True

        def _nearest(self, name_filter):
            p = self.reader.pos()
            if not p: return None
            nf = (name_filter or "").lower()
            best = None
            for e in self.reader.entities():
                if nf and nf not in (e["name"] or "").lower(): continue
                if e["obj"] == self.reader.lp(): continue
                d = math.hypot(e["x"]-p[0], e["y"]-p[1])
                if best is None or d < best[0]: best = (d, e)
            if best: best[1]["dist"] = best[0]
            return best[1] if best else None

        def _find_by_obj(self, obj):
            return next((x for x in self.reader.entities() if x["obj"] == obj), None)

        def walk_copy_pos(self):
            if not self._need(): return
            p = self.reader.pos()
            if p:
                self.wx.set(f"{p[0]:.2f}"); self.wy.set(f"{p[1]:.2f}")

        def walk_to_selected(self):
            if not self._need(): return
            sel = self.ent_tree.selection()
            e = None
            if sel:
                obj = int(sel[0], 16)
                e = next((x for x in self.last_ents if x["obj"] == obj), None)
            if not e:
                e = self._nearest(self.ent_filter.get().strip())
            if not e:
                self.log("[walk] энтити не выбрано"); return
            self.selected_obj = e["obj"]
            self._start_walk(self._walk_entity_loop, e["obj"])

        def walk_to_nearest(self):
            if not self._need(): return
            e = self._nearest(self.ent_filter.get().strip())
            if not e:
                self.log("[walk] сущности нет"); return
            self.selected_obj = e["obj"]
            self._start_walk(self._walk_entity_loop, e["obj"])

        def walk_to_point(self):
            if not self._need(): return
            try:
                tx, ty = float(self.wx.get()), float(self.wy.get())
            except ValueError:
                self.log("[walk] X/Y — числа"); return
            self._start_walk(self._walk_point_loop, tx, ty)

        def walk_stop_fn(self):
            self.walk_stop.set(); self.log("[walk] остановлено")

        def _start_walk(self, fn, *args):
            if self.Bx is None:
                self.log("[walk] нажми «Только центр» (привязка) или КАЛИБРОВКУ"); return
            self.walk_stop.set(); time.sleep(0.15); self.walk_stop.clear()
            self.walk_thread = threading.Thread(target=fn, args=args, daemon=True)
            self.walk_thread.start()

        def _walk_entity_loop(self, obj):
            stop = self.walk_stop
            ARRIVE, RECLICK = 2.0, 1.6
            t0, last_click = time.time(), 0.0
            self.log(f"[walk] иду к энтити #{obj}")
            while not stop.is_set() and time.time()-t0 < 120:
                cur = self._find_by_obj(obj)
                if not cur:
                    self.log("[walk] энтити исчезло"); break
                p = self.reader.pos()
                if not p:
                    stop.wait(0.3); continue
                if math.hypot(cur["x"]-p[0], cur["y"]-p[1]) <= ARRIVE:
                    self.log(f"[walk] ✔ дошёл за {time.time()-t0:.0f}с"); break
                now = time.time()
                if now - last_click >= RECLICK:
                    if self._click_world(cur["x"], cur["y"]): last_click = now
                    else: last_click = now - 2.0
                stop.wait(0.2)

        def _walk_point_loop(self, tx, ty):
            stop = self.walk_stop
            ARRIVE, RECLICK = 1.0, 1.6
            t0, last_click = time.time(), 0.0
            self.log(f"[walk] иду в точку ({tx:.1f},{ty:.1f})")
            while not stop.is_set() and time.time()-t0 < 120:
                p = self.reader.pos()
                if not p:
                    stop.wait(0.3); continue
                if math.hypot(tx-p[0], ty-p[1]) <= ARRIVE:
                    self.log(f"[walk] ✔ в точке за {time.time()-t0:.0f}с"); break
                now = time.time()
                if now - last_click >= RECLICK:
                    if self._click_world(tx, ty): last_click = now
                    else: last_click = now - 2.0
                stop.wait(0.2)

        # ---------- автоохота ----------
        def hunt_start(self):
            if not self._need(): return
            if self.Bx is None:
                self.log("[hunt] нажми «Только центр» (привязка) или КАЛИБРОВКУ"); return
            if self.hunt_thread and self.hunt_thread.is_alive(): return
            self.hunt_stop.clear()
            self.btn_hstop.configure(state=tk.NORMAL)
            self.btn_hunt.configure(state=tk.DISABLED)
            self.hunt_thread = threading.Thread(target=self._hunt_loop, daemon=True)
            self.hunt_thread.start()

        def hunt_stop_fn(self):
            self.hunt_stop.set()
            self.btn_hstop.configure(state=tk.DISABLED)
            self.btn_hunt.configure(state=tk.NORMAL)
            self.log("[hunt] остановлено")

        def _hunt_loop(self):
            name = self.hname.get().strip()
            try:
                radius = float(self.hradius.get() or 40)
                hp_stop = int(self.hhp.get() or 0)
            except ValueError:
                radius, hp_stop = 40.0, 0
            kills = 0
            self.log(f"[hunt] старт: '{name}', радиус {radius}")
            while not self.hunt_stop.is_set():
                hpp = self.reader.hp()
                if hpp and hp_stop and 100*hpp[0]//hpp[1] <= hp_stop:
                    self.log("[hunt] низкий HP — стоп"); break
                e = self._nearest(name)
                if not e:
                    self.hunt_stop.wait(1.0); continue
                p = self.reader.pos()
                d = math.hypot(e["x"]-p[0], e["y"]-p[1]) if p else 999
                if d > radius:
                    self.hunt_stop.wait(0.8); continue
                corpse = self._attack(e, hp_stop)
                if self.hunt_stop.is_set(): break
                if corpse:
                    kills += 1
                    self.log(f"[hunt] ✔ убито ({kills}) — лут…")
                    self._loot(corpse)
                self.hunt_stop.wait(0.3)
            self.btn_hstop.configure(state=tk.DISABLED)
            self.btn_hunt.configure(state=tk.NORMAL)
            self.log("[hunt] завершено")

        def _attack(self, e, hp_stop):
            stop = self.hunt_stop
            ATTACK_RANGE, CONFIRM_SEC = 3.0, 6.0
            corpse = (e["x"], e["y"])
            for attempt in range(1, 5):
                if stop.is_set(): return None
                cur = self._find_by_obj(e["obj"])
                if not cur: return corpse
                if not self._click_world(cur["x"], cur["y"]):
                    time.sleep(0.5); continue
                self.log(f"[hunt] клик по {cur['name']!r} (попытка {attempt})")
                p0 = self.reader.pos()
                t0 = time.time()
                while time.time()-t0 < CONFIRM_SEC and not stop.is_set():
                    time.sleep(0.3)
                    cur = self._find_by_obj(e["obj"])
                    if not cur: return corpse
                    p = self.reader.pos()
                    if not p or not p0: continue
                    d = math.hypot(cur["x"]-p[0], cur["y"]-p[1])
                    if d <= ATTACK_RANGE:
                        return self._wait_kill(cur, hp_stop, corpse)
                    if math.hypot(cur["x"]-p0[0], cur["y"]-p0[1]) - d > 0.6:
                        return self._wait_kill(cur, hp_stop, corpse)
            self.log("[hunt] 4 попытки — цель пропущена")
            return None

        def _wait_kill(self, cur, hp_stop, corpse):
            stop = self.hunt_stop
            ATTACK_RANGE, STUCK_SEC, FIGHT_TIMEOUT = 3.0, 5.0, 120.0
            last_pos = self.reader.pos()
            t_stuck, t0 = time.time(), time.time()
            while not stop.is_set():
                time.sleep(0.35)
                c = self._find_by_obj(cur["obj"])
                if not c: return corpse
                p = self.reader.pos()
                if not p: continue
                hpp = self.reader.hp()
                if hpp and hp_stop and 100*hpp[0]//hpp[1] <= hp_stop:
                    stop.set(); return None
                d = math.hypot(c["x"]-p[0], c["y"]-p[1])
                if d <= ATTACK_RANGE:
                    t_stuck = time.time()
                    if time.time()-t0 > FIGHT_TIMEOUT:
                        self._click_world(c["x"], c["y"]); t0 = time.time()
                    continue
                if last_pos and math.hypot(p[0]-last_pos[0], p[1]-last_pos[1]) > 0.15:
                    t_stuck = time.time()
                elif time.time()-t_stuck > STUCK_SEC:
                    if self._click_world(c["x"], c["y"]):
                        self.log(f"[hunt] стоим в {d:.1f}м — переклик")
                    t_stuck = time.time()
                last_pos = p
                if time.time()-t0 > 240: return None
            return None

        def _loot(self, corpse):
            stop = self.hunt_stop
            stop.wait(1.2)
            for _ in range(3):
                if stop.is_set(): return
                if not self._click_world(corpse[0], corpse[1], lift=20): break
                stop.wait(0.7)

        # ---------- ESP 30 Гц ----------
        def _ensure_overlay(self):
            if self.overlay is not None:
                if self.win and self.win.ok:
                    self.overlay.place_over_game(self.win)
                return
            if not self.win or not self.win.ok:
                self.log("[esp] окно игры не найдено"); return
            try:
                self.overlay = Overlay(self)
                self.overlay.place_over_game(self.win)
                self.esp_running = True
                threading.Thread(target=self._esp_loop, daemon=True).start()
                self.log("[esp] ✔ оверлей создан, поток 30 Гц запущен")
            except Exception as e:
                self.log(f"[esp] оверлей не создался: {e}")
                self.esp_enabled.set(False)

        def _esp_loop(self):
            last = 0.0
            while self.esp_running:
                now = time.time()
                if now - last >= 1/30.0:
                    last = now
                    try: self._esp_frame()
                    except Exception: pass
                time.sleep(0.01)
            try:
                if self.overlay: self.overlay.clear()
            except Exception:
                pass

        def _esp_frame(self):
            if not (self.esp_enabled.get() and self.reader
                    and self.win and self.win.ok):
                return
            ov = self.overlay
            if ov is None: return
            if self.Bx is None:
                msg = ("ESP: Sx/Sy/ME из дефолта — нажми «Только центр» "
                       "для привязки")
                self.after(0, lambda: ov.draw([], None, msg, {"enabled": True}))
                return
            W, H = float(self.win.w), float(self.win.h)
            p = self.reader.pos()
            if not p: return
            ents = list(self.esp_ents)
            lp_obj = self.reader.lp()
            items, player_sp = [], None
            for e in ents:
                xy = self.reader.ent_xy(e["obj"])
                if xy: e["x"], e["y"] = xy
                s = self.w2s(e["x"], e["y"])
                if not s: continue
                if e["obj"] == lp_obj:
                    player_sp = s
                    continue
                if 0 <= s[0] <= W and 0 <= s[1] <= H:
                    d = math.hypot(e["x"]-p[0], e["y"]-p[1])
                    items.append((s[0], s[1], (e["name"] or "?")[:16], d,
                                  e["obj"] == self.selected_obj))
            info = (f"ESP30 Sx={self._eff_Sx():.1f} Sy={self._eff_Sy():.1f} "
                    f"n={len(items)} pos=({p[0]:.0f},{p[1]:.0f})")
            opts = {"enabled": True, "names": self.esp_names.get(),
                    "dist": self.esp_dist.get(), "lines": self.esp_lines.get(),
                    "player": self.esp_player.get()}
            self.after(0, lambda: ov.draw(items, player_sp, info, opts))

        # ---------- тик 1 Гц ----------
        def _tick(self):
            try:
                if self.reader:
                    ents = self.reader.entities()
                    p = self.reader.pos()
                    for e in ents:
                        e["dist"] = (math.hypot(e["x"]-p[0], e["y"]-p[1]) if p else 0.0)
                    self.esp_ents = ents
                    self.last_ents = ents
                    filt = self.ent_filter.get().strip().lower()
                    rows = [e for e in ents
                            if not filt or filt in (e["name"] or "").lower()]
                    rows.sort(key=lambda e: e["dist"])
                    t = self.ent_tree
                    sel_obj = None
                    sel = t.selection()
                    if sel:
                        try: sel_obj = int(sel[0], 16)
                        except ValueError: pass
                    t.delete(*t.get_children(""))
                    for e in rows[:120]:
                        iid = f"{e['obj']:X}"
                        t.insert("", "end", iid=iid, values=(
                            e["name"] or "?", e["id"], f"{e['dist']:.1f}",
                            f"{e['x']:.1f}", f"{e['y']:.1f}", hexd(e["obj"])))
                        if sel_obj == e["obj"]:
                            t.selection_set(iid)
                    hpp = self.reader.hp()
                    if self.Bx is not None:
                        ctxt = (f"Sx={self._eff_Sx():.2f} Sy={self._eff_Sy():.2f} "
                                f"ME=({self.me_dx:+.0f},{self.me_dy:+.0f})")
                    else:
                        ctxt = "Sx=2.9 Sy=3.0 (дефолт) — нажми «Только центр»"
                    self.info_lbl.configure(text=
                        (f"X: {p[0]:.1f}  Y: {p[1]:.1f}  HP: {hpp[0]}/{hpp[1]}  |  {ctxt}")
                        if (p and hpp) else f"LP пуст | {ctxt}")
            except Exception as ex:
                self.log(f"[tick] {type(ex).__name__}: {ex}")
            self.after(1000, self._tick)

    app = App()
    app.mainloop()

if __name__ == "__main__":
    if sys.platform != "win32":
        print("Нужен Windows")
        sys.exit(1)
    run_gui()
