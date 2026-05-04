"""
Script migrasi: Tambah kolom scope_mode ke tabel scans.
Jalankan sekali saja: python migrations/add_scope_mode.py
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from extensions import db

app = create_app()

with app.app_context():
    try:
        db.session.execute(db.text(
            "ALTER TABLE scans ADD COLUMN scope_mode VARCHAR(20) DEFAULT 'wildcard'"
        ))
        db.session.commit()
        print("[+] Kolom 'scope_mode' berhasil ditambahkan ke tabel 'scans'.")
    except Exception as e:
        if 'Duplicate column' in str(e) or 'already exists' in str(e):
            print("[*] Kolom 'scope_mode' sudah ada, skip.")
        else:
            print(f"[!] Error: {e}")
            db.session.rollback()
