import json
import sqlite3

import server as server_module
from conftest import signup, create_company


def _get_company_row(cid):
    db = sqlite3.connect(server_module.DB_PATH)
    db.row_factory = sqlite3.Row
    row = db.execute("SELECT * FROM companies WHERE id = ?", (cid,)).fetchone()
    db.close()
    return row


def test_scheduled_backup_writes_a_file(client, tmp_path, monkeypatch):
    monkeypatch.setattr(server_module, "BACKUPS_DIR", tmp_path / "backups")
    signup(client)
    cid = create_company(client, "Backup Co").get_json()["id"]
    company = _get_company_row(cid)

    db = sqlite3.connect(server_module.DB_PATH)
    db.row_factory = sqlite3.Row
    ran = server_module.run_scheduled_backups_for_company(db, company)
    assert ran is True

    files = list((tmp_path / "backups" / str(cid)).glob("*.json"))
    assert len(files) == 1
    data = json.loads(files[0].read_text())
    assert data["company"]["name"] == "Backup Co"
    db.close()


def test_scheduled_backup_only_runs_once_per_day(client, tmp_path, monkeypatch):
    monkeypatch.setattr(server_module, "BACKUPS_DIR", tmp_path / "backups")
    signup(client)
    cid = create_company(client, "Backup Co").get_json()["id"]
    company = _get_company_row(cid)

    db = sqlite3.connect(server_module.DB_PATH)
    db.row_factory = sqlite3.Row
    assert server_module.run_scheduled_backups_for_company(db, company) is True
    assert server_module.run_scheduled_backups_for_company(db, company) is False  # already claimed today

    files = list((tmp_path / "backups" / str(cid)).glob("*.json"))
    assert len(files) == 1  # not overwritten or duplicated on the second call
    db.close()
