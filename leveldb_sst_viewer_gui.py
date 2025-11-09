
from __future__ import annotations
from pathlib import Path
from typing import List, Dict, Any, Optional
import json, sys, re

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QFileDialog, QTableWidget, QTableWidgetItem,
    QAbstractItemView, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QTextEdit, QSplitter,
    QStatusBar, QLineEdit, QCheckBox, QComboBox, QDialog, QDialogButtonBox, QTabWidget
)
from PySide6.QtCore import Qt

import sst_core_plus as core

def ascii_preview(b: bytes, limit: int = 400) -> str:
    out = []
    for ch in b[:limit]:
        out.append(chr(ch) if 32 <= ch <= 126 else '.')
    s = ''.join(out)
    if len(b) > limit: s += ' …'
    return s

def hex_dump(b: bytes, width: int = 16) -> str:
    lines = []
    for i in range(0, len(b), width):
        chunk = b[i:i+width]
        hexpart = " ".join(f"{x:02x}" for x in chunk)
        asciip = "".join(chr(x) if 32 <= x <= 126 else "." for x in chunk)
        lines.append(f"{i:08x}  {hexpart:<{width*3}}  {asciip}")
    return "\n".join(lines)

def safe_preview_from_dec(dec: Dict[str, Any]) -> str:
    if "json" in dec and isinstance(dec["json"], str):
        return dec["json"]
    if "text" in dec and isinstance(dec["text"], str):
        return dec["text"]
    pb = dec.get("protobuf") or dec.get("protobuf_guess")
    if pb is not None:
        try:
            return json.dumps(pb, ensure_ascii=False, indent=2)
        except Exception:
            pass
    return f"({dec.get('kind','bytes')}, {dec.get('len','?')} bytes)"

def wrap_text(s: str, width: int = 120) -> str:
    if width <= 0:
        return s
    out = []
    for i in range(0, len(s), width):
        out.append(s[i:i+width])
    return "\n".join(out)

class SSTViewerProV2(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SST/LevelDB Table Viewer – Protobuf + ASCII + Search (Tabs Popup) v2")
        self.resize(1400, 900)
        self.setStatusBar(QStatusBar())

        self.btn_open = QPushButton("Open .ldb/.sst…")
        self.btn_open.clicked.connect(self.open_file)

        self.ed_filter = QLineEdit()
        self.ed_filter.setPlaceholderText("Filter (substring or 're:pattern').")

        self.cmb_scope = QComboBox()
        self.cmb_scope.addItems(["key+ascii+value", "key only", "value only", "tokens only"])

        self.chk_case = QCheckBox("Case-sensitive"); self.chk_case.setChecked(False)
        self.btn_apply = QPushButton("Apply"); self.btn_apply.clicked.connect(self.apply_filter)
        self.btn_clear = QPushButton("Clear"); self.btn_clear.clicked.connect(self.clear_filter)

        self.btn_full = QPushButton("Show full value (tabs)")
        self.btn_full.clicked.connect(self.show_full_popup)
        self.btn_full.setEnabled(False)

        top = QWidget(); tl = QHBoxLayout(top)
        tl.addWidget(self.btn_open)
        tl.addWidget(QLabel("Search:")); tl.addWidget(self.ed_filter, 1)
        tl.addWidget(QLabel("Scope:")); tl.addWidget(self.cmb_scope)
        tl.addWidget(self.chk_case)
        tl.addWidget(self.btn_apply); tl.addWidget(self.btn_clear)
        tl.addWidget(self.btn_full)

        self.table = QTableWidget(0, 9)
        self.table.setHorizontalHeaderLabels([
            "#", "User Key (hex)", "User Key (ascii)",
            "Seq", "Type", "Kind",
            "Value (ascii)", "Tokens", "Preview (decoded)"
        ])
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.itemSelectionChanged.connect(self.update_detail)

        # Detail
        self.detail = QTextEdit(); self.detail.setReadOnly(True); self.detail.setLineWrapMode(QTextEdit.NoWrap)

        main = QSplitter(Qt.Vertical)
        main.addWidget(self.table); main.addWidget(self.detail)
        main.setStretchFactor(0, 2); main.setStretchFactor(1, 1)

        central = QWidget(); cl = QVBoxLayout(central); cl.addWidget(top); cl.addWidget(main, 1)
        self.setCentralWidget(central)

        self.path: Optional[Path] = None
        self.rows_full: List[Dict[str, Any]] = []
        self.rows_view: List[Dict[str, Any]] = []
        self._current_dec: Optional[Dict[str,Any]] = None

    def open_file(self):
        fn, _ = QFileDialog.getOpenFileName(self, "Open .ldb/.sst", "", "LevelDB table (*.ldb *.sst);;All Files (*)")
        if not fn: return
        self.path = Path(fn)
        self.load_entries(self.path)

    def load_entries(self, path: Path, max_rows: int = 4000):
        self.rows_full = []
        i = 0
        for k,v in core.iterate_table(str(path)):
            parts = core.split_internal_key(k)
            user = parts["user_key"]
            dec = core.decode_value_best(v)
            tokens = dec.get("keywords", [])
            value_ascii = ascii_preview(v, 400)
            preview_text = safe_preview_from_dec(dec)
            row = {
                "user_key_hex": user.hex(),
                "user_key_ascii": user.decode("utf-8", errors="replace"),
                "seq": parts["seq"],
                "type": parts["type"],
                "kind": dec.get("kind"),
                "value_ascii": value_ascii,
                "tokens": ", ".join(tokens),
                "preview": preview_text,
                "decoded": dec
            }
            self.rows_full.append(row)
            i += 1
            if i >= max_rows: break
        self.rows_view = list(self.rows_full)
        self.populate_table()
        self.statusBar().showMessage(f"Loaded {len(self.rows_full)} entries from {path} (showing first {len(self.rows_view)})")

    def populate_table(self):
        self.table.setRowCount(0)
        for i, r in enumerate(self.rows_view, start=1):
            row = self.table.rowCount(); self.table.insertRow(row)
            self.table.setItem(row, 0, QTableWidgetItem(str(i)))
            self.table.setItem(row, 1, QTableWidgetItem(r["user_key_hex"]))
            self.table.setItem(row, 2, QTableWidgetItem(r["user_key_ascii"]))
            self.table.setItem(row, 3, QTableWidgetItem(str(r["seq"])))
            self.table.setItem(row, 4, QTableWidgetItem(str(r["type"])))
            self.table.setItem(row, 5, QTableWidgetItem(str(r["kind"])))
            self.table.setItem(row, 6, QTableWidgetItem(r["value_ascii"]))
            self.table.setItem(row, 7, QTableWidgetItem(r["tokens"]))
            self.table.setItem(row, 8, QTableWidgetItem(r["preview"]))
        self.table.resizeRowsToContents()

    def apply_filter(self):
        q = self.ed_filter.text().strip()
        scope = self.cmb_scope.currentText()
        case = self.chk_case.isChecked()

        if not q:
            self.rows_view = list(self.rows_full)
        else:
            is_regex = q.startswith("re:")
            if is_regex:
                pattern = q[3:]
                flags = 0 if case else re.IGNORECASE
                rx = re.compile(pattern, flags)
                def match(r):
                    fields = self._fields_for_scope(r, scope)
                    return rx.search("\n".join(fields)) is not None
            else:
                needle = q if case else q.lower()
                def norm(s): return s if case else s.lower()
                def match(r):
                    fields = self._fields_for_scope(r, scope)
                    return any(needle in norm(f) for f in fields)
            self.rows_view = [r for r in self.rows_full if match(r)]

        self.populate_table()
        self.statusBar().showMessage(f"Filter applied: {len(self.rows_view)}/{len(self.rows_full)} rows match")

    def _fields_for_scope(self, r: Dict[str, Any], scope: str):
        if scope == "key only":
            return [r["user_key_ascii"], r["user_key_hex"]]
        if scope == "value only":
            return [r["preview"], r["value_ascii"]]
        if scope == "tokens only":
            return [r["tokens"]]
        return [r["user_key_ascii"], r["user_key_hex"], r["preview"], r["value_ascii"], r["tokens"]]

    def clear_filter(self):
        self.ed_filter.setText("")
        self.apply_filter()

    def update_detail(self):
        items = self.table.selectedItems()
        if not items:
            self.btn_full.setEnabled(False)
            return
        r = items[0].row()
        data = self.rows_view[r]
        self._current_dec = data["decoded"]
        dec_copy = dict(self._current_dec)
        if "raw_bytes" in dec_copy:
            dec_copy = dict(dec_copy)  # shallow copy
            dec_copy["raw_bytes"] = f"<bytes len={len(self._current_dec['raw_bytes'])}>"
        self.detail.setText(json.dumps(dec_copy, ensure_ascii=False, indent=2))
        self.btn_full.setEnabled(True)

    def show_full_popup(self):
        if not self._current_dec:
            return
        dec = self._current_dec

        raw_b = dec.get("raw_bytes", b"")
        ascii_full = dec.get("raw_ascii") or ""
        pb = dec.get("protobuf") or dec.get("protobuf_guess")
        hex_text = hex_dump(raw_b)
        json_text = dec.get("json") or "(no JSON)"

        # ✅ NEW: wrap ASCII lines
        ascii_wrapped = wrap_text(ascii_full, 120)

        if pb:
            pb_text = json.dumps(pb, ensure_ascii=False, indent=2)
        else:
            pb_text = "(no protobuf parsed)"

        dlg = QDialog(self)
        dlg.setWindowTitle("Full Value – ASCII / Protobuf / HEX / JSON")
        dlg.resize(1000, 700)

        tabs = QTabWidget(dlg)

        def mk(text):
            w = QTextEdit()
            w.setReadOnly(True)
            w.setLineWrapMode(QTextEdit.NoWrap)  # keep manual wrap
            w.setText(text)
            return w

        tabs.addTab(mk(ascii_wrapped), "ASCII")
        tabs.addTab(mk(pb_text), "Protobuf")
        tabs.addTab(mk(hex_text), "HEX")
        tabs.addTab(mk(json_text), "JSON")

        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(dlg.close)

        layout = QVBoxLayout()
        layout.addWidget(tabs)
        layout.addWidget(buttons)
        dlg.setLayout(layout)
        dlg.exec()

def main():
    app = QApplication(sys.argv)
    w = SSTViewerProV2()
    w.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
