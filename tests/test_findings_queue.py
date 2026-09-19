"""异常处置队列测试。

覆盖：
* 发现身份为「样本 + 关联事件 + 异常类型 + 时间边界」的稳定指纹，不按数组序号绑定；
* 链路编辑后对账：仍存在的沿用处置状态、消失的转已消除、新出现的未处理、
  已消除后再次出现自动回到未处理；
* 处置写入校验客户端指纹版本，过期请求 409 冲突；
* 跨样本筛选（类型 / 经手人 / 发生时间 / 样本 / 状态）、未处理计数、状态迁移记录；
* 事件增删改、批量导入、删除样本级联。
"""
from __future__ import annotations

import os
import tempfile

_tmp = tempfile.mkdtemp(prefix="audit-findings-tests-")
os.environ["AUDIT_DB_PATH"] = os.path.join(_tmp, "test_findings.db")

import itertools

import pytest
from fastapi.testclient import TestClient

from app.db import init_db
from app.main import app


@pytest.fixture(scope="module")
def client():
    init_db()
    with TestClient(app) as c:
        yield c


_seq = itertools.count(1)


@pytest.fixture()
def sample(client):
    code = f"UT-FINDING-{next(_seq):03d}"
    resp = client.post(
        "/api/samples",
        json={"code": code, "name": "处置队列测试样本", "description": ""},
    )
    assert resp.status_code == 201
    return resp.json()


def _add(client, sid, custodian, start, end=None, note=""):
    resp = client.post(
        f"/api/samples/{sid}/events",
        json={"custodian": custodian, "start_time": start, "end_time": end, "note": note},
    )
    assert resp.status_code == 201
    return resp.json()


def _queue(client, sid, **params):
    params.setdefault("status", "all")
    params["sample_id"] = sid
    return client.get("/api/findings/queue", params=params).json()


def _open_findings(client, sid):
    return [
        i
        for i in _queue(client, sid, status="all")["items"]
        if i["status"] == "open"
    ]


def _disposition(client, fp, action, handler, version, note=""):
    return client.post(
        f"/api/findings/{fp}/disposition",
        json={
            "action": action,
            "handler_name": handler,
            "handler_note": note,
            "expected_version": version,
        },
    )


def test_finding_identity_is_stable_fingerprint_not_array_index(client, sample):
    """追加一条不影响既有发现的事件后，原指纹不变，处置状态沿用。"""
    sid = sample["id"]
    _add(client, sid, "甲", "2026-09-18 09:00:00", "2026-09-18 10:00:00")
    _add(client, sid, "乙", "2026-09-18 10:30:00", "2026-09-18 11:00:00")

    gap = next(i for i in _open_findings(client, sid) if i["code"] == "gap")
    fp = gap["fingerprint"]
    assert len(fp) == 64
    assert set(fp) <= set("0123456789abcdef")

    assert _disposition(client, fp, "resolve", "处置人甲", gap["version"], "补齐手续").status_code == 200

    # 在时间线**之后**追加一段无缝链路：数组位置全部后移，但旧断档指纹与处置状态不变
    _add(client, sid, "丙", "2026-09-18 11:00:00", "2026-09-18 12:00:00")
    _add(client, sid, "丁", "2026-09-18 12:00:00", "2026-09-18 13:00:00")
    items = _queue(client, sid)["items"]
    same = next(i for i in items if i["fingerprint"] == fp)
    assert same["status"] == "resolved"
    assert same["handler_name"] == "处置人甲"
    assert same["handler_note"] == "补齐手续"
    assert same["version"] == 2  # 建档 v1，处置 v2，追加事件不抬版本


def test_edit_chain_reconciles_persist_eliminate_reappear(client, sample):
    sid = sample["id"]
    _add(client, sid, "甲", "2026-09-18 09:00:00", "2026-09-18 10:00:00")
    e2 = _add(client, sid, "乙", "2026-09-18 10:30:00", "2026-09-18 11:00:00")

    gap = next(i for i in _open_findings(client, sid) if i["code"] == "gap")
    fp, v1 = gap["fingerprint"], gap["version"]
    assert _disposition(client, fp, "resolve", "处置人乙", v1).status_code == 200

    # 把缺口补齐：原断档消失 -> 已消除历史，处置人与备注保留
    r = client.put(
        f"/api/events/{e2['id']}",
        json={"custodian": "乙", "start_time": "2026-09-18 10:00:00",
              "end_time": "2026-09-18 11:00:00"},
    )
    assert r.status_code == 200
    gone = next(i for i in _queue(client, sid)["items"] if i["fingerprint"] == fp)
    assert gone["status"] == "eliminated"
    assert gone["eliminated_at"]
    assert gone["handler_name"] == "处置人乙"

    # 再次拉开缺口：同一指纹再次出现 -> 自动回未处理，版本抬升、迁移可追溯
    client.put(
        f"/api/events/{e2['id']}",
        json={"custodian": "乙", "start_time": "2026-09-18 10:30:00",
              "end_time": "2026-09-18 11:00:00"},
    )
    back = next(i for i in _queue(client, sid)["items"] if i["fingerprint"] == fp)
    assert back["status"] == "open"
    assert back["version"] == 4  # create -> resolve -> eliminate -> reappear

    actions = [
        t["action"]
        for t in client.get("/api/findings/transitions", params={"fingerprint": fp}).json()["items"]
    ]
    assert actions == ["reappeared", "eliminated", "resolved", "created"]


def test_new_findings_stay_open_and_only_snapshot_change_bumps_version(client, sample):
    sid = sample["id"]
    _add(client, sid, "甲", "2026-09-18 09:00:00", "2026-09-18 10:00:00")
    _add(client, sid, "乙", "2026-09-18 10:30:00", "2026-09-18 11:00:00")

    # 丙 [09:30, 09:50] 插在甲的保管区间内且紧邻乙的断档窗口：原 30 分钟断档
    # 被时间边界不同的新发现取代，这是指纹身份变化（非序号绑定）的正确表现；
    # 新重叠以未处理建档
    _add(client, sid, "丙", "2026-09-18 09:30:00", "2026-09-18 09:50:00")
    after = {i["fingerprint"]: i for i in _queue(client, sid)["items"]}
    assert any(i["code"] == "overlap" and i["status"] == "open" for i in after.values())

    # 在末尾无缝追加不会改变既有指纹：状态沿用
    _add(client, sid, "丁", "2026-09-18 11:00:00", "2026-09-18 12:00:00")
    persisted = {i["fingerprint"]: i for i in _queue(client, sid)["items"]}
    for fp, item in after.items():
        assert persisted[fp]["status"] == item["status"]

    # 修改不参与指纹的展示字段（经手人改名 -> 快照漂移）抬升版本
    e1 = client.get(f"/api/samples/{sid}").json()["events"][0]["id"]
    original = next(i for i in persisted.values() if e1 in i["event_ids"])
    client.put(
        f"/api/events/{e1}",
        json={"custodian": "甲（已更名）", "start_time": "2026-09-18 09:00:00",
              "end_time": "2026-09-18 10:00:00"},
    )
    renamed = next(i for i in _queue(client, sid)["items"]
                   if i["fingerprint"] == original["fingerprint"])
    assert renamed["version"] == original["version"] + 1


def test_stale_version_conflict_and_reopen_rules(client, sample):
    sid = sample["id"]
    _add(client, sid, "甲", "2026-09-18 09:00:00", "2026-09-18 10:00:00")
    _add(client, sid, "乙", "2026-09-18 10:30:00", "2026-09-18 11:00:00")
    gap = _open_findings(client, sid)[0]
    fp, v1 = gap["fingerprint"], gap["version"]

    # 缺处置人 / 版本非法 -> 422
    bad = client.post(
        f"/api/findings/{fp}/disposition",
        json={"action": "resolve", "handler_name": " ", "handler_note": "",
              "expected_version": v1},
    )
    assert bad.status_code == 422

    assert _disposition(client, fp, "resolve", "处置人", v1).status_code == 200
    # 客户端仍持 v1：过期请求 409
    stale = _disposition(client, fp, "resolve", "处置人", v1)
    assert stale.status_code == 409
    assert "版本已过期" in stale.json()["detail"]

    # 链路编辑使展示快照漂移（经手人改名，措辞随之变化），版本抬升 -> 旧请求冲突
    events = client.get(f"/api/samples/{sid}").json()["events"]
    client.put(
        f"/api/events/{events[0]['id']}",
        json={"custodian": "甲（更名后）", "start_time": "2026-09-18 09:00:00",
              "end_time": "2026-09-18 10:00:00"},
    )
    fresh = next(i for i in _queue(client, sid, status="resolved")["items"]
                 if i["fingerprint"] == fp)
    assert fresh["version"] == 3
    assert _disposition(client, fp, "reopen", "复核人", v1).status_code == 409

    # 最新版本可以重新打开；对已回到未处理的发现再次 reopen 属非法状态迁移
    ok = _disposition(client, fp, "reopen", "复核人", 3, "仍需跟进")
    assert ok.status_code == 200 and ok.json()["item"]["status"] == "open"
    latest_version = ok.json()["item"]["version"]
    again = _disposition(client, fp, "reopen", "复核人", latest_version)
    assert again.status_code == 409
    assert "仅已处理" in again.json()["detail"]

    # 未知指纹 -> 404；路径格式合法但不存在同样 404
    assert client.post(
        "/api/findings/" + "z" * 64 + "/disposition",
        json={"action": "resolve", "handler_name": "x", "expected_version": 1},
    ).status_code == 404
    assert client.post(
        "/api/findings/" + "0" * 64 + "/disposition",
        json={"action": "resolve", "handler_name": "x", "expected_version": 1},
    ).status_code == 404


def test_cross_sample_filters_and_open_count(client, sample):
    sid = sample["id"]
    _add(client, sid, "专属经手人赵", "2026-09-18 09:00:00", "2026-09-18 10:00:00")
    _add(client, sid, "专属经手人钱", "2026-09-18 10:30:00", "2026-09-18 11:00:00")

    # 跨样本未处理计数（含演示样本，至少 1）
    count = client.get("/api/findings/queue/open-count").json()
    assert count["open"] >= 1

    # 类型筛选
    gaps = client.get("/api/findings/queue", params={"code": "gap", "status": "all"}).json()
    assert all(i["code"] == "gap" for i in gaps["items"])
    assert any(i["sample_id"] == sid for i in gaps["items"])

    # 经手人（子串）与样本筛选
    mine = client.get("/api/findings/queue",
                      params={"custodian": "专属经手人赵", "sample_id": sid}).json()
    assert mine["items"] and all(
        "专属经手人赵" in i["custodians"] and i["sample_id"] == sid for i in mine["items"]
    )
    assert client.get("/api/findings/queue",
                      params={"custodian": "绝对不存在的姓名"}).json()["items"] == []

    # 发生时间边界：断档发生于 10:00；从 10:01 起过滤不到，从 10:00 起可以
    assert client.get(
        "/api/findings/queue",
        params={"sample_id": sid, "occurred_from": "2026-09-18 10:01:00"},
    ).json()["items"] == []
    hit = client.get(
        "/api/findings/queue",
        params={"sample_id": sid, "occurred_from": "2026-09-18 10:00:00"},
    ).json()["items"]
    assert any(i["code"] == "gap" for i in hit)
    # 非法时间格式 422
    bad = client.get("/api/findings/queue", params={"occurred_from": "18-09-18"})
    assert bad.status_code == 422

    # 样本详情包含该样本的处置计数
    detail = client.get(f"/api/samples/{sid}").json()
    assert detail["findings_summary"]["open"] >= 1


def test_transition_log_records_lifecycle_and_cascade_delete(client, sample):
    sid = sample["id"]
    _add(client, sid, "甲", "2026-09-18 09:00:00", "2026-09-18 10:00:00")
    _add(client, sid, "乙", "2026-09-18 10:30:00", "2026-09-18 11:00:00")
    fp = _open_findings(client, sid)[0]["fingerprint"]
    _disposition(client, fp, "resolve", "处理人", 1, "ok")
    _disposition(client, fp, "reopen", "复核人", 2, "again")

    log = client.get("/api/findings/transitions", params={"sample_id": sid}).json()["items"]
    pairs = [(t["action"], t["actor"], t["note"]) for t in log]
    assert ("resolved", "处理人", "ok") in pairs
    assert ("reopened", "复核人", "again") in pairs
    assert any(t["action"] == "created" and t["actor"] == "system" for t in log)
    assert all(t["sample_code"] is not None for t in log)

    # 删除样本：处置行与迁移记录级联清除
    assert client.delete(f"/api/samples/{sid}").status_code == 204
    assert client.get(
        "/api/findings/queue", params={"sample_id": sid}
    ).status_code == 404
    assert client.get(
        "/api/findings/transitions", params={"fingerprint": fp}
    ).json()["items"] == []


def test_event_delete_eliminates_findings_and_bulk_import_reconciles(client, sample):
    sid = sample["id"]
    e1 = _add(client, sid, "甲", "2026-09-18 09:00:00", "2026-09-18 10:00:00")
    _add(client, sid, "乙", "2026-09-18 10:30:00", "2026-09-18 11:00:00")
    fp = next(i["fingerprint"] for i in _open_findings(client, sid) if i["code"] == "gap")

    # 删除断档涉及的事件后，该发现转已消除
    client.delete(f"/api/events/{e1['id']}")
    assert next(
        i for i in _queue(client, sid)["items"] if i["fingerprint"] == fp
    )["status"] == "eliminated"

    # 批量导入引入新异常：预览 -> 确认后新发现建档为未处理
    csv_body = (
        "经手人,开始时间,结束时间,备注\r\n"
        "丙,2026-09-18 11:30:00,2026-09-18 12:00:00,恢复链路\r\n"
        "丁,2026-09-18 12:30:00,2026-09-18 13:00:00,再次断档\r\n"
    ).encode("utf-8")
    preview = client.post(
        f"/api/samples/{sid}/events/import-preview", content=csv_body,
        headers={"Content-Type": "text/csv"},
    )
    assert preview.status_code == 200
    token = preview.json()["token"]
    confirm = client.post(
        f"/api/samples/{sid}/events/import-confirm", json={"token": token}
    )
    assert confirm.status_code == 201
    codes = {i["code"]: i["status"] for i in _queue(client, sid)["items"]}
    assert codes.get("gap") == "open"
