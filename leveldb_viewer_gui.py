
from __future__ import annotations
from dataclasses import dataclass
from typing import Optional, List, Tuple, Dict, Any
from pathlib import Path
import os, sys, json, csv, re, binascii, shutil, tempfile

PLYVEL_OK = True
try:
    import plyvel  
except Exception as e:
    PLYVEL_OK = False
    PLYVEL_ERR = str(e)

try:
    from PySide6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QFileDialog, QTableWidget, QTableWidgetItem,
        QAbstractItemView, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QLineEdit,
        QSplitter, QTextEdit, QCheckBox, QMessageBox, QStatusBar
    )
    from PySide6.QtCore import Qt
    from PySide6.QtGui import QAction
except Exception as e:
    print("PySide6 not available:", e)
    print("Install with: pip install PySide6")
    sys.exit(1)

HEX_RE = re.compile(rb"[ -~]")  

def to_hex(b: bytes, limit: Optional[int] = 256) -> str:
    if b is None:
        return ""
    data = b if limit is None else b[:limit]
    hx = binascii.hexlify(data).decode("ascii")
    spaced = " ".join(hx[i:i+2] for i in range(0, len(hx), 2))
    if limit is not None and len(b) > limit:
        spaced += " …"
    return spaced

def to_ascii(b: bytes, limit: Optional[int] = 256) -> str:
    if b is None: return ""
    data = b if limit is None else b[:limit]
    out = bytearray()
    for ch in data:
        out.append(ch if 32 <= ch <= 126 else ord("."))
    s = out.decode("ascii", errors="replace")
    if limit is not None and len(b) > limit:
        s += " …"
    return s

def try_json(b: bytes) -> Optional[str]:
    try:
        s = b.decode("utf-8")
        j = json.loads(s)
        return json.dumps(j, ensure_ascii=False, indent=2)
    except Exception:
        return None

def try_utf8(b: bytes) -> Optional[str]:
    try:
        s = b.decode("utf-8")
        printable = sum(1 for c in s if 32 <= ord(c) <= 126 or c in "\r\n\t")
        if len(s) and printable / max(1, len(s)) > 0.7:
            return s
        return s
    except Exception:
        return None

def try_int_be(b: bytes) -> Optional[int]:
    try:
        if 1 <= len(b) <= 8:
            return int.from_bytes(b, "big", signed=False)
    except Exception:
        pass
    return None

def best_effort_decode(b: bytes) -> Tuple[str, str]:
    if not b:
        return ("empty", "")
    j = try_json(b)
    if j is not None:
        return ("json", j)
    u = try_utf8(b)
    if u is not None:
        return ("utf8", u)
    iv = try_int_be(b)
    if iv is not None:
        return ("uint-big-endian", str(iv))
    return ("hex", to_hex(b, limit=None))

@dataclass
class KVRow:
    key: bytes
    value: bytes

def detect_leveldb_root(path: Path) -> Optional[Path]:
    p = Path(path)
    if p.is_file():
        p = p.parent
    if not p.exists() or not p.is_dir():
        return None
    names = {x.name for x in p.iterdir()}
    if "CURRENT" in names or any(n.endswith(".ldb") for n in names) or any(n.startswith("MANIFEST") for n in names):
        return p
    return None

def copy_db_to_temp(src_root: Path) -> Path:
    tmp_dir = Path(tempfile.mkdtemp(prefix="ldb_copy_"))
    # Copy minimal required files
    for it in src_root.iterdir():
        if it.is_file() and (it.name == "CURRENT" or it.name.startswith("MANIFEST") or it.suffix in (".ldb", ".log", ".sst", ".ldb")):
            shutil.copy2(it, tmp_dir / it.name)
    # Copy OPTIONS* if present
    for it in src_root.glob("OPTIONS*"):
        shutil.copy2(it, tmp_dir / it.name)
    return tmp_dir

def read_leveldb_all(db_path: Path, prefix: Optional[bytes] = None, limit: Optional[int] = None) -> List[KVRow]:
    if not PLYVEL_OK:
        raise RuntimeError(f"plyvel not available: {PLYVEL_ERR}")
    db = plyvel.DB(str(db_path), create_if_missing=False)
    rows: List[KVRow] = []
    try:
        it = db.iterator(prefix=prefix) if prefix is not None else db.iterator()
        for i, (k, v) in enumerate(it):
            rows.append(KVRow(k, v))
            if limit is not None and i + 1 >= limit:
                break
    finally:
        db.close()
    return rows

def path_storage_hint(db_path: Path) -> str:
    pstr = str(db_path).lower()
    if "indexeddb" in pstr:
        return "indexeddb"
    if "local storage" in pstr or "local_storage" in pstr:
        return "localstorage"
    if "session storage" in pstr or "session_storage" in pstr:
        return "sessionstorage"
    return ""

def split_nulls(b: bytes):
    return b.split(b"\x00")

def looks_ascii(b: bytes) -> bool:
    try:
        _ = b.decode("utf-8")
        return True
    except Exception:
        return False

def decode_local_session_key(key: bytes):
    """
    Heuristic for Chrome Local/Session Storage LevelDB keys.
    Often: <origin>\\x00<key> or <origin>\\x00<namespace>\\x00<key>
    """
    parts = split_nulls(key)
    parts = [p for p in parts if p != b""]
    if len(parts) >= 2 and looks_ascii(parts[0]):
        d = {"origin": parts[0].decode("utf-8", "replace")}
        if len(parts) == 2:
            d["item_key"] = parts[1].decode("utf-8","replace")
        else:
            d["namespace"] = parts[1].decode("utf-8","replace")
            d["item_key"] = b"\x00".join(parts[2:]).decode("utf-8","replace")
        return d
    return None

def decode_indexeddb_key_basic(key: bytes):
    parts = split_nulls(key)
    parts_clean = [p for p in parts if p != b""]
    out: Dict[str, Any] = {}
    if len(parts_clean) >= 1:
        if looks_ascii(parts_clean[0]):
            out["origin_or_storage_key"] = parts_clean[0].decode("utf-8","replace")
        ids = []
        for p in parts_clean[1:]:
            if 1 <= len(p) <= 8:
                try:
                    ids.append(int.from_bytes(p, "little", signed=False))
                except Exception:
                    ids.append(p.hex())
            elif looks_ascii(p):
                ids.append(p.decode("utf-8","replace"))
            else:
                ids.append(p.hex())
        if ids:
            out["components"] = ids
    if out:
        return out
    return {"raw_hex": to_hex(key, limit=None)}

class LevelDBViewer(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("LevelDB Viewer – Python GUI")
        self.resize(1280, 840)
        self.setStatusBar(QStatusBar())

        m_file = self.menuBar().addMenu("&File")
        act_open_dir = QAction("Open Directory…", self); act_open_dir.triggered.connect(self.open_dir)
        act_open_file = QAction("Open File…", self); act_open_file.triggered.connect(self.open_file)
        m_file.addAction(act_open_dir); m_file.addAction(act_open_file)

        m_export = self.menuBar().addMenu("&Export")
        act_json = QAction("Export JSON…", self); act_json.triggered.connect(self.export_json)
        act_csv = QAction("Export CSV…", self); act_csv.triggered.connect(self.export_csv)
        m_export.addAction(act_json); m_export.addAction(act_csv)

        self.btn_open_dir = QPushButton("Open Directory…"); self.btn_open_dir.clicked.connect(self.open_dir)
        self.btn_open_file = QPushButton("Open File…"); self.btn_open_file.clicked.connect(self.open_file)
        self.edb_path = QLineEdit(); self.edb_path.setPlaceholderText("LevelDB path"); self.edb_path.setReadOnly(True)

        self.prefix_edit = QLineEdit(); self.prefix_edit.setPlaceholderText("Prefix (hex, optional) e.g. 00 01")
        self.chk_full_value = QCheckBox("Show full values"); self.chk_full_value.setChecked(False)
        self.chk_safe_copy = QCheckBox("Safe copy to temp (unlock)"); self.chk_safe_copy.setChecked(True)

        self.btn_load = QPushButton("Load"); self.btn_load.clicked.connect(self.load_db)

        top = QWidget(); top_l = QHBoxLayout(top)
        top_l.addWidget(self.btn_open_dir); top_l.addWidget(self.btn_open_file)
        top_l.addWidget(self.edb_path, 1)
        top_l.addWidget(QLabel("Prefix:")); top_l.addWidget(self.prefix_edit)
        top_l.addWidget(self.chk_full_value); top_l.addWidget(self.chk_safe_copy)
        top_l.addWidget(self.btn_load)

        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["#", "Key (hex)", "Key (ASCII)", "Value (preview)", "Decoder", "Length"])
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.itemSelectionChanged.connect(self.update_detail)

        self.key_hex = QTextEdit(); self.key_hex.setReadOnly(True); self.key_hex.setLineWrapMode(QTextEdit.NoWrap)
        self.key_ascii = QTextEdit(); self.key_ascii.setReadOnly(True); self.key_ascii.setLineWrapMode(QTextEdit.NoWrap)
        self.val_view = QTextEdit(); self.val_view.setReadOnly(True); self.val_view.setLineWrapMode(QTextEdit.NoWrap)

        left = QWidget(); left_l = QVBoxLayout(left)
        left_l.addWidget(QLabel("Key (hex)")); left_l.addWidget(self.key_hex, 1)
        left_l.addWidget(QLabel("Key (ASCII)")); left_l.addWidget(self.key_ascii, 1)

        right = QWidget(); right_l = QVBoxLayout(right)
        right_l.addWidget(QLabel("Value (decoded / full)")); right_l.addWidget(self.val_view, 1)

        bottom = QSplitter(Qt.Horizontal); bottom.addWidget(left); bottom.addWidget(right)
        bottom.setStretchFactor(0, 1); bottom.setStretchFactor(1, 2)

        main_split = QSplitter(Qt.Vertical)
        main_split.addWidget(self.table)
        main_split.addWidget(bottom)
        main_split.setStretchFactor(0, 3)
        main_split.setStretchFactor(1, 2)

        central = QWidget(); c_l = QVBoxLayout(central)
        c_l.addWidget(top); c_l.addWidget(main_split, 1)
        self.setCentralWidget(central)

        self.db_path: Optional[Path] = None
        self.rows: List[KVRow] = []
        self.opened_tmp: Optional[Path] = None  # temp copy in use

        self.table.setColumnWidth(0, 60)
        self.table.setColumnWidth(1, 320)
        self.table.setColumnWidth(2, 260)
        self.table.setColumnWidth(3, 420)
        self.table.setColumnWidth(4, 160)
        self.table.setColumnWidth(5, 90)

        if not PLYVEL_OK:
            QMessageBox.warning(self, "plyvel missing",
                                f"plyvel is not installed or LevelDB not available:\n{PLYVEL_ERR}\n\n"
                                "Install with:\n  pip install plyvel\n\n"
                                "On macOS (Homebrew):\n  brew install leveldb\n  pip install --no-binary=:all: plyvel")

    def open_dir(self):
        p = QFileDialog.getExistingDirectory(self, "Open LevelDB directory", "")
        if not p: return
        self.set_db_path(Path(p))

    def open_file(self):
        fn, _ = QFileDialog.getOpenFileName(self, "Open file within LevelDB", "", "All Files (*)")
        if not fn: return
        self.set_db_path(Path(fn))

    def set_db_path(self, p: Path):
        root = detect_leveldb_root(p)
        if not root:
            QMessageBox.critical(self, "Not a LevelDB", f"Could not detect LevelDB at:\n{p}")
            return
        self.db_path = root
        hint = path_storage_hint(root)
        hint_txt = f" [{hint}]" if hint else ""
        self.statusBar().showMessage(f"Selected DB: {root}{hint_txt}")
        self.edb_path.setText(str(root))

    def load_db(self):
        if not self.db_path:
            QMessageBox.information(self, "Path", "Please open a LevelDB directory or a file within it.")
            return

        open_path = self.db_path
        if self.chk_safe_copy.isChecked():
            try:
                if self.opened_tmp and self.opened_tmp.exists():
                    shutil.rmtree(self.opened_tmp, ignore_errors=True)
                tmp = copy_db_to_temp(self.db_path)
                self.opened_tmp = tmp
                open_path = tmp
                self.statusBar().showMessage(f"Copied DB to temp: {open_path}")
            except Exception as e:
                QMessageBox.warning(self, "Copy failed", f"Temp copy failed, opening original read-only:\n{e}")

        try:
            prefix_hex = self.prefix_edit.text().strip().replace(" ", "")
            pref = None
            if prefix_hex:
                try:
                    pref = binascii.unhexlify(prefix_hex)
                except Exception:
                    QMessageBox.warning(self, "Prefix", "Invalid hex in prefix field.")
                    return
            self.rows = read_leveldb_all(open_path, prefix=pref, limit=None)
            self.populate_table()
            n = len(self.rows)
            if n == 0:
                self.statusBar().showMessage("Loaded: 0 records. Check: (a) DB path (b) DB locked (c) prefix filters everything.")
                QMessageBox.information(self, "No records", "0 records found.\n\nTipps:\n• Prefix-Filter entfernen\n• DB während Chrome/Edge geschlossen öffnen oder Temp-Copy nutzen\n• 'Safe copy to temp' aktiviert lassen\n• Prüfen, ob im Ordner CURRENT + .ldb/MANIFEST liegt")
            else:
                self.statusBar().showMessage(f"Loaded {n} records from {open_path}")
        except Exception as e:
            QMessageBox.critical(self, "Read error", str(e))
            self.statusBar().showMessage(f"Error: {e}")

    def populate_table(self):
        self.table.setRowCount(0)
        show_full = self.chk_full_value.isChecked()
        storage_hint = path_storage_hint(self.db_path) if self.db_path else ''
        for i, row in enumerate(self.rows, start=1):
            key_hex = to_hex(row.key, limit=None if show_full else 256)
            key_ascii = to_ascii(row.key, limit=None if show_full else 256)

            kind, decoded = best_effort_decode(row.value)
            preview = decoded if show_full else (decoded[:400] + (" …" if len(decoded) > 400 else ""))
            n = len(row.value)

            extra_decoder = ''
            if storage_hint in ('localstorage','sessionstorage'):
                dk = decode_local_session_key(row.key)
                if dk:
                    extra_decoder = 'localStorage' if storage_hint=='localstorage' else 'sessionStorage'
                    if 'namespace' in dk:
                        key_ascii = f"origin={dk.get('origin')} | ns={dk.get('namespace')} | key={dk.get('item_key')}"
                    else:
                        key_ascii = f"origin={dk.get('origin')} | key={dk.get('item_key')}"
            elif storage_hint == 'indexeddb':
                dk = decode_indexeddb_key_basic(row.key)
                if dk:
                    extra_decoder = 'indexedDB'
                    key_ascii = json.dumps(dk, ensure_ascii=False)

            r = self.table.rowCount()
            self.table.insertRow(r)
            self.table.setItem(r, 0, QTableWidgetItem(str(i)))
            self.table.setItem(r, 1, QTableWidgetItem(key_hex))
            self.table.setItem(r, 2, QTableWidgetItem(key_ascii))
            self.table.setItem(r, 3, QTableWidgetItem(preview))
            dec_name = (extra_decoder + ('+' if extra_decoder else '') + kind) if extra_decoder else kind
            self.table.setItem(r, 4, QTableWidgetItem(dec_name))
            self.table.setItem(r, 5, QTableWidgetItem(str(n)))
        self.table.resizeRowsToContents()

    def update_detail(self):
        items = self.table.selectedItems()
        if not items: return
        r = items[0].row()
        kv = self.rows[r]
        self.key_hex.setText(to_hex(kv.key, limit=None))
        self.key_ascii.setText(to_ascii(kv.key, limit=None))
        kind, decoded = best_effort_decode(kv.value)
        self.val_view.setText(decoded)

        hint = path_storage_hint(self.db_path) if self.db_path else ''
        structured = None
        if hint in ('localstorage','sessionstorage'):
            structured = decode_local_session_key(kv.key)
        elif hint == 'indexeddb':
            structured = decode_indexeddb_key_basic(kv.key)
        if structured:
            self.key_ascii.setText(json.dumps(structured, ensure_ascii=False, indent=2))

    def export_json(self):
        if not self.rows:
            QMessageBox.information(self, "Export", "Nothing to export.")
            return
        fn, _ = QFileDialog.getSaveFileName(self, "Export JSON", "leveldb_export.json", "JSON (*.json)")
        if not fn: return
        out = []
        storage_hint = path_storage_hint(self.db_path) if self.db_path else ''
        for kv in self.rows:
            kind, decoded = best_effort_decode(kv.value)
            key_struct = None
            if storage_hint in ('localstorage','sessionstorage'):
                key_struct = decode_local_session_key(kv.key)
            elif storage_hint == 'indexeddb':
                key_struct = decode_indexeddb_key_basic(kv.key)
            out.append({
                "key_hex": to_hex(kv.key, limit=None),
                "key_ascii": to_ascii(kv.key, limit=None),
                "key_struct": key_struct,
                "value_kind": kind,
                "value_decoded": decoded,
                "value_len": len(kv.value),
            })
        Path(fn).write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
        QMessageBox.information(self, "Export", f"Saved JSON: {fn}")

    def export_csv(self):
        if not self.rows:
            QMessageBox.information(self, "Export", "Nothing to export.")
            return
        fn, _ = QFileDialog.getSaveFileName(self, "Export CSV", "leveldb_export.csv", "CSV (*.csv)")
        if not fn: return
        storage_hint = path_storage_hint(self.db_path) if self.db_path else ''
        with open(fn, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["key_hex", "key_ascii_or_struct", "value_kind", "value_decoded", "value_len"])
            for kv in self.rows:
                kind, decoded = best_effort_decode(kv.value)
                key_struct = None
                if storage_hint in ('localstorage','sessionstorage'):
                    key_struct = decode_local_session_key(kv.key)
                elif storage_hint == 'indexeddb':
                    key_struct = decode_indexeddb_key_basic(kv.key)
                key_repr = json.dumps(key_struct, ensure_ascii=False) if key_struct else to_ascii(kv.key, limit=None)
                w.writerow([to_hex(kv.key, limit=None), key_repr, kind, decoded, len(kv.value)])
        QMessageBox.information(self, "Export", f"Saved CSV: {fn}")

def main():
    app = QApplication(sys.argv)
    w = LevelDBViewer()
    w.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
