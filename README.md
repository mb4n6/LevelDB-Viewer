# LevelDB & SST Forensic Viewers (GUI)

Interactive tools to inspect and decode **LevelDB** databases and single **SST/LDB table files**.
Designed for digital forensics training and classroom use.

Adapted from the Protobuf Viewer README template.

---

## Tools

- **leveldb_viewer_gui.py** — Open a LevelDB database directory (with `CURRENT`, `MANIFEST-*`, `.ldb/.sst`, `LOG`), iterate keys and values.
- **leveldb_sst_viewer_gui.py** — Open a single **SST/LDB** table file directly (no MANIFEST needed), parse internal keys and values.

---

## Features

- Decode values as **JSON**, **UTF‑8 text**, **Protobuf (best‑effort)**, or show **binary/hex** preview.
- Show **USER KEY**, **SEQ#**, **TYPE** (Put/Delete), **value previews**, and extracted **tokens** (e.g. package names).
- Full value popup with **ASCII**, **Protobuf**, **HEX**, **JSON** tabs (ASCII can be line‑wrapped for readability).
- Search & filter (substring or `re:` regex), optional case sensitivity, with scope: key only / value only / tokens only / combined.
- Integrated **“Format Explanation”** dialog for classroom: LevelDB architecture, SST layout, internal keys, IndexedDB vs Local/Session storage, compression, forensic tips.

---

## Installation

Python 3.10–3.12 recommended. Using Conda is advised:

```bash
conda create -n ldb python=3.12
conda activate ldb
conda install -c conda-forge python-snappy
pip install PySide6
# optional for DB‑mode backed by native LevelDB:
pip install plyvel
```

> On macOS (ARM), ensure Snappy is available (e.g., `brew install snappy`) if you build any native deps.

---

## Usage

**LevelDB directory viewer**

```bash
python leveldb_viewer_gui.py
```

**SST/LDB single table viewer**

```bash
python leveldb_sst_viewer_gui.py
```

---

## Contact

Prepared for training at the Hochschule für Polizei Baden‑Württemberg  
Author: **Marc Brandt**, mb4n6
