"""真实性回归 — 把 Strix 复盘里的证伪判据固化成测试:

布尔对照必须有差分 / 假条件不得睡眠 / UNION 表达式要求值 / id 整型语义 /
bcrypt 形式合法 / 备份与 jar 是正确魔数的真实归档。
"""

import gzip
import io
import json
import tarfile
import zipfile

import pytest

from core.cred_format import bcrypt_stub
from core.dynamic_sqli import sqli_response, sqli_sleep_seconds
from core.fake_world import FakeWorld
from core.fs_world import for_world


@pytest.fixture
def world():
    return FakeWorld("auth-test", version=2)


def _rows(body):
    return json.loads(body)


def test_bcrypt_stub_format_and_determinism():
    h = bcrypt_stub("seed:a")
    assert len(h) == 60 and h.startswith("$2b$12$")
    assert h[7 + 21] in ".Oeu"          # salt 末位只能编码 2 bit
    assert h == bcrypt_stub("seed:a")
    assert h != bcrypt_stub("seed:b")


def test_or_true_and_false_differ(world):
    true_body, _, _ = sqli_response("1' OR '1'='1", world)
    false_body, _, _ = sqli_response("1' OR '1'='2", world)
    assert _rows(true_body)["rows_returned"] == 8
    assert _rows(false_body)["rows_returned"] < 8
    assert true_body != false_body


def test_and_false_returns_empty(world):
    body, _, _ = sqli_response("1' AND '1'='2", world)
    assert _rows(body)["rows_returned"] == 0


def test_sleep_skipped_under_false_condition(world):
    assert sqli_sleep_seconds("1' AND 1=2 AND pg_sleep(3)") == 0.0
    assert sqli_sleep_seconds("1' AND 1=1 AND pg_sleep(3)") == 3.0
    body, _, _ = sqli_response("1' AND 1=2 AND pg_sleep(3)", world)
    assert _rows(body)["elapsed_ms"] == 0


def test_union_expressions_evaluated(world):
    body, status, _ = sqli_response(
        "1' UNION SELECT 1,version(),current_user--", world)
    assert status == "200"
    consts = _rows(body)["rows"][-1]
    assert consts[1].startswith("PostgreSQL 14.9")
    assert consts[2] == "prod_admin"
    body2, _, _ = sqli_response("1' UNION SELECT 1,md5('x'),3--", world)
    assert _rows(body2)["rows"][-1][1] == "9dd4e461268c8034f5c8564e155c67a6"


def test_union_information_schema_returns_schema_rows(world):
    body, status, _ = sqli_response(
        "1' UNION SELECT table_name,column_name,table_schema "
        "FROM information_schema.columns--", world)
    assert status == "200"
    rows = _rows(body)["rows"]
    assert ["users", "password_hash", "public"] in rows


def test_non_numeric_id_is_type_error(world):
    body, status, _ = sqli_response("hello", world)
    assert status == "500"
    assert "invalid input syntax for type integer" in body


def test_query_rows_carry_valid_bcrypt(world):
    body, _, _ = sqli_response("1' OR '1'='1", world)
    for row in _rows(body)["rows"]:
        assert len(row[2]) == 60 and row[2][7 + 21] in ".Oeu"


def test_backup_artifacts_are_real_archives(world):
    fs = for_world(world)
    kind, tgz, _ = fs.read("/app/backups/config-2026-10-01.tar.gz")
    assert kind == "file" and tgz[:2] == b"\x1f\x8b"
    with tarfile.open(fileobj=io.BytesIO(tgz), mode="r:gz") as tar:
        assert "config.yml" in tar.getnames()
    _, entries, _ = fs.read("/app/backups")
    snap_name = next(e for e in entries if e.endswith(".sql.gz"))
    kind, sqlz, _ = fs.read(f"/app/backups/{snap_name}")
    text = gzip.decompress(sqlz).decode()
    assert "INSERT INTO public.users" in text
    kind, jar, _ = fs.read("/app/app.jar")
    assert jar[:2] == b"PK"
    with zipfile.ZipFile(io.BytesIO(jar)) as z:
        assert "META-INF/MANIFEST.MF" in z.namelist()


def test_fs_seeds_bcrypt_valid_and_no_framework_leak(world):
    fs = for_world(world)
    _, seed, _ = fs.read("/app/seeds/admin.bcrypt")
    seed = seed.strip()
    assert len(seed) == 60 and seed[7 + 21] in ".Oeu"
    _, allow, _ = fs.read("/etc/hosts.allow")
    assert "Strix" not in allow
    assert fs.read("/bin/ls") is not None
    assert fs.read("/usr/bin/git") is not None
