"""异常处置队列（跨样本审计发现处置）。

审计引擎在每次链路重算后输出若干「发现」（断档 / 重叠 / 起止倒置 / 逆序录入 /
时间错误）。处置队列不为这些发现分配易变的数组序号，而是为每条发现生成**稳定
指纹**：

    fingerprint = SHA-256(sample_id + 关联事件 id 集合 + 异常类型 + 时间边界)

链路被编辑后调用 :func:`reconcile_findings` 重算：

* 指纹仍在 —— 沿用既有处置状态（未处理 / 已处理）；仅当可见描述发生变化时
  才抬升指纹版本号；
* 指纹消失 —— 原处置行保留，转为 ``eliminated``（已消除历史）；
* 指纹首次出现 —— 新建 ``open``（未处理）处置行；
* 已消除的指纹在后续编辑中再次出现 —— 自动回到未处理，并记录迁移。

每次状态迁移（建档 / 已处理 / 重新打开 / 已消除 / 再次出现）都在
``finding_transitions`` 留痕。处置写入（标记已处理 / 重新打开）必须携带客户端
看到的 ``expected_version``；链路重算或他人处置抬升版本后，过期请求以 409
冲突拒绝，由前端刷新后重试。
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any, Optional
from sqlite3 import Connection

from .audit import build_audit, fmt_dt, parse_dt

# 处置状态
OPEN = "open"
RESOLVED = "resolved"
ELIMINATED = "eliminated"

# 迁移动作
ACTION_CREATED = "created"            # 新发现建档（系统）
ACTION_RESOLVED = "resolved"          # 人工标记已处理
ACTION_REOPENED = "reopened"          # 人工重新打开
ACTION_ELIMINATED = "eliminated"      # 链路重算后消失（系统）
ACTION_REAPPEARED = "reappeared"      # 已消除发现再次出现（系统）

SYSTEM_ACTOR = "system"

STATUS_TEXT = {
    OPEN: "未处理",
    RESOLVED: "已处理",
    ELIMINATED: "已消除",
}

ACTION_TEXT = {
    ACTION_CREATED: "新发现建档",
    ACTION_RESOLVED: "标记已处理",
    ACTION_REOPENED: "重新打开",
    ACTION_ELIMINATED: "链路重算后已消除",
    ACTION_REAPPEARED: "再次出现，转未处理",
}

FINDING_CODE_TEXT = {
    "gap": "保管断档",
    "overlap": "交接重叠",
    "reversed_interval": "起止倒置",
    "out_of_order": "逆序录入",
    "bad_time": "时间错误",
}

_VALID_STATUSES = (OPEN, RESOLVED, ELIMINATED)


class FindingError(Exception):
    """处置队列业务校验失败，由路由层转换为 HTTPException。"""

    def __init__(self, message: str, status_code: int = 409):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


# ---------- 稳定指纹 ----------

def _parse_safe(value: Optional[str]) -> Optional[datetime]:
    try:
        return parse_dt(value)
    except (ValueError, AttributeError):
        return None


def make_fingerprint(
    sample_id: int,
    code: str,
    event_ids: list[int],
    time_from: Optional[str],
    time_to: Optional[str],
) -> str:
    """由样本、关联事件、异常类型与时间边界生成稳定指纹（与数组序号无关）。"""
    payload = {
        "sample_id": sample_id,
        "code": code,
        # 关联事件身份以 id 集合表示，排序规范化，避免顺序差异造成伪不同
        "event_ids": sorted(int(i) for i in event_ids),
        "from": time_from or "",
        "to": time_to or "",
    }
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def extract_current_findings(
    conn: Connection, sample_id: int, events: Optional[list[dict[str, Any]]] = None
) -> dict[str, dict[str, Any]]:
    """重算样本审计结果，返回 {fingerprint: 发现描述}；同指纹去重。

    描述中同时包含展示所需的最新信息（经手人快照、可读消息、发生时间锚点），
    这些字段不参与指纹，仅用于队列展示与版本漂移判定。
    """
    if events is None:
        rows = conn.execute(
            "SELECT * FROM events WHERE sample_id = ? ORDER BY id", (sample_id,)
        ).fetchall()
        events = [dict(r) for r in rows]

    audit = build_audit(events)
    by_id = {e["id"]: e for e in events}

    current: dict[str, dict[str, Any]] = {}
    for finding in audit["findings"]:
        ids = sorted({int(x) for x in (finding.get("event_ids") or [])})
        code = finding["code"]
        time_from = finding.get("from") or None
        time_to = finding.get("to") or None
        fingerprint = make_fingerprint(sample_id, code, ids, time_from, time_to)
        if fingerprint in current:
            # 同一身份在一次审计中重复出现时合并，禁止按数组序号拆成多条
            continue

        custodians = [by_id[i]["custodian"] for i in ids if i in by_id]

        # 发生时间：优先使用异常时间窗口起点；缺窗口（逆序 / 倒置 / 时间错误）
        # 时回退到关联事件的最早起始时间，供「按发生时间筛选」使用
        occurred_at = time_from or time_to or ""
        if not occurred_at:
            starts = [
                s for s in (_parse_safe(by_id[i].get("start_time")) for i in ids if i in by_id)
                if s is not None
            ]
            occurred_at = fmt_dt(min(starts)) if starts else ""

        current[fingerprint] = {
            "code": code,
            "kind": finding.get("kind"),
            "event_ids": ids,
            "from": time_from,
            "to": time_to,
            "custodians": custodians,
            "message": finding.get("message", ""),
            "occurred_at": occurred_at,
        }
    return current


# ---------- 迁移记录 ----------

def _log_transition(
    conn: Connection,
    *,
    fingerprint: str,
    sample_id: int,
    action: str,
    actor: Optional[str],
    note: str,
    from_status: Optional[str],
    to_status: str,
    created_at: str,
) -> None:
    conn.execute(
        "INSERT INTO finding_transitions (fingerprint, sample_id, action, actor, note, "
        "from_status, to_status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (fingerprint, sample_id, action, actor, note, from_status, to_status, created_at),
    )


# ---------- 链路重算后的对账 ----------

def reconcile_findings(
    conn: Connection, sample_id: int, now: Optional[str] = None
) -> dict[str, int]:
    """按当前链路重算发现并对账处置行。

    * 新指纹                 -> 插入 open（version=1），记录 created；
    * 已消除指纹再次出现     -> 回到 open，version+1，记录 reappeared；
    * 指纹仍在且描述变化     -> 更新快照、version+1，状态沿用（无迁移记录）；
    * 指纹仍在且描述未变     -> 原样保留（处置状态与版本均不变）；
    * 消失的 open/resolved   -> eliminated，version+1，记录 eliminated。
    """
    now = now or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    current = extract_current_findings(conn, sample_id)

    existing = {
        r["fingerprint"]: r
        for r in conn.execute(
            "SELECT * FROM finding_dispositions WHERE sample_id = ?", (sample_id,)
        ).fetchall()
    }

    counts = {"created": 0, "reappeared": 0, "updated": 0, "eliminated": 0}

    for fingerprint, desc in current.items():
        snap_json = json.dumps(desc, ensure_ascii=False, sort_keys=True)
        row = existing.get(fingerprint)
        if row is None:
            conn.execute(
                "INSERT INTO finding_dispositions (fingerprint, sample_id, finding_code, "
                "status, event_ids, time_from, time_to, occurred_at, custodians, message, "
                "snapshot, handler_name, handler_note, version, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, '', 1, ?, ?)",
                (
                    fingerprint, sample_id, desc["code"], OPEN,
                    json.dumps(desc["event_ids"]),
                    desc["from"], desc["to"], desc["occurred_at"],
                    json.dumps(desc["custodians"], ensure_ascii=False),
                    desc["message"], snap_json, now, now,
                ),
            )
            _log_transition(
                conn, fingerprint=fingerprint, sample_id=sample_id,
                action=ACTION_CREATED, actor=SYSTEM_ACTOR, note="",
                from_status=None, to_status=OPEN, created_at=now,
            )
            counts["created"] += 1
            continue

        if row["status"] == ELIMINATED:
            # 历史已消除的同一指纹再次出现：自动回到未处理，旧处置与迁移均保留
            conn.execute(
                "UPDATE finding_dispositions SET status = ?, finding_code = ?, "
                "event_ids = ?, time_from = ?, time_to = ?, occurred_at = ?, "
                "custodians = ?, message = ?, snapshot = ?, eliminated_at = NULL, "
                "version = version + 1, updated_at = ? WHERE fingerprint = ?",
                (
                    OPEN, desc["code"], json.dumps(desc["event_ids"]),
                    desc["from"], desc["to"], desc["occurred_at"],
                    json.dumps(desc["custodians"], ensure_ascii=False),
                    desc["message"], snap_json, now, fingerprint,
                ),
            )
            _log_transition(
                conn, fingerprint=fingerprint, sample_id=sample_id,
                action=ACTION_REAPPEARED, actor=SYSTEM_ACTOR, note="",
                from_status=ELIMINATED, to_status=OPEN, created_at=now,
            )
            counts["reappeared"] += 1
            continue

        # 指纹仍在：沿用处置状态；仅当可见描述漂移（如经手人改名、措辞随边界
        # 变化）才抬升版本，使拿着旧视图的客户端写入时收到冲突
        old_desc: dict[str, Any] = {}
        try:
            old_desc = json.loads(row["snapshot"] or "{}")
        except json.JSONDecodeError:
            old_desc = {}
        if old_desc != desc:
            conn.execute(
                "UPDATE finding_dispositions SET finding_code = ?, event_ids = ?, "
                "time_from = ?, time_to = ?, occurred_at = ?, custodians = ?, "
                "message = ?, snapshot = ?, version = version + 1, updated_at = ? "
                "WHERE fingerprint = ?",
                (
                    desc["code"], json.dumps(desc["event_ids"]),
                    desc["from"], desc["to"], desc["occurred_at"],
                    json.dumps(desc["custodians"], ensure_ascii=False),
                    desc["message"], snap_json, now, fingerprint,
                ),
            )
            counts["updated"] += 1

    alive = set(current)
    for fingerprint, row in existing.items():
        if fingerprint in alive or row["status"] == ELIMINATED:
            continue
        # 链路编辑后该发现不再存在：处置行保留，仅转为已消除历史
        conn.execute(
            "UPDATE finding_dispositions SET status = ?, eliminated_at = ?, "
            "version = version + 1, updated_at = ? WHERE fingerprint = ?",
            (ELIMINATED, now, now, fingerprint),
        )
        _log_transition(
            conn, fingerprint=fingerprint, sample_id=sample_id,
            action=ACTION_ELIMINATED, actor=SYSTEM_ACTOR, note="",
            from_status=row["status"], to_status=ELIMINATED, created_at=now,
        )
        counts["eliminated"] += 1

    return counts


def reconcile_all(conn: Connection, now: Optional[str] = None) -> None:
    """跨样本队列读取前的防御性对账：逐样本重算。"""
    sample_ids = [r["id"] for r in conn.execute("SELECT id FROM samples ORDER BY id")]
    for sample_id in sample_ids:
        reconcile_findings(conn, sample_id, now=now)


# ---------- 队列查询 ----------

def _row_to_item(row: Any) -> dict[str, Any]:
    try:
        snapshot = json.loads(row["snapshot"] or "{}")
    except json.JSONDecodeError:
        snapshot = {}
    try:
        event_ids = json.loads(row["event_ids"] or "[]")
    except json.JSONDecodeError:
        event_ids = []
    try:
        custodians = json.loads(row["custodians"] or "[]")
    except json.JSONDecodeError:
        custodians = []
    status = row["status"]
    return {
        "fingerprint": row["fingerprint"],
        "sample_id": row["sample_id"],
        "sample_code": row["sample_code"],
        "sample_name": row["sample_name"],
        "code": row["finding_code"],
        "code_text": FINDING_CODE_TEXT.get(row["finding_code"], row["finding_code"]),
        "kind": snapshot.get("kind"),
        "status": status,
        "status_text": STATUS_TEXT.get(status, status),
        "event_ids": event_ids,
        "custodians": custodians,
        "time_from": row["time_from"],
        "time_to": row["time_to"],
        "occurred_at": row["occurred_at"],
        "message": row["message"],
        "handler_name": row["handler_name"],
        "handler_note": row["handler_note"],
        "resolved_at": row["resolved_at"],
        "eliminated_at": row["eliminated_at"],
        "version": row["version"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


_STATUS_ORDER = {OPEN: 0, RESOLVED: 1, ELIMINATED: 2}


def build_findings_queue(
    conn: Connection,
    *,
    status: Optional[str] = OPEN,
    finding_code: Optional[str] = None,
    custodian: Optional[str] = None,
    occurred_from: Optional[str] = None,
    occurred_to: Optional[str] = None,
    sample_id: Optional[int] = None,
    reconcile: bool = True,
) -> dict[str, Any]:
    """跨样本异常处置队列：重算对账后按类型 / 经手人 / 发生时间等条件筛选。"""
    if reconcile:
        if sample_id is not None:
            reconcile_findings(conn, sample_id)
        else:
            reconcile_all(conn)

    where: list[str] = []
    params: list[Any] = []
    if status in _VALID_STATUSES:
        where.append("fd.status = ?")
        params.append(status)
    if finding_code:
        where.append("fd.finding_code = ?")
        params.append(finding_code)
    if sample_id is not None:
        where.append("fd.sample_id = ?")
        params.append(sample_id)
    # 存储时间均为规范化的 YYYY-MM-DD HH:MM:SS，可直接按字符串比较
    if occurred_from:
        where.append("fd.occurred_at >= ?")
        params.append(occurred_from)
    if occurred_to:
        where.append("fd.occurred_at <= ?")
        params.append(occurred_to)
    where_sql = (" WHERE " + " AND ".join(where)) if where else ""

    rows = conn.execute(
        "SELECT fd.*, s.code AS sample_code, s.name AS sample_name "
        "FROM finding_dispositions fd JOIN samples s ON s.id = fd.sample_id"
        f"{where_sql} ORDER BY fd.occurred_at ASC, fd.sample_id ASC, fd.fingerprint",
        params,
    ).fetchall()

    items = [_row_to_item(r) for r in rows]
    if custodian:
        keyword = custodian.strip()
        items = [
            it for it in items
            if any(keyword in name for name in it["custodians"])
        ]

    # 汇总始终反映全量（不带筛选条件），队列头部显示未处理总数
    count_rows = conn.execute(
        "SELECT status, COUNT(*) AS n FROM finding_dispositions GROUP BY status"
    ).fetchall()
    counts = {OPEN: 0, RESOLVED: 0, ELIMINATED: 0}
    for r in count_rows:
        counts[r["status"]] = r["n"]

    return {
        "items": items,
        "summary": {
            "open": counts[OPEN],
            "resolved": counts[RESOLVED],
            "eliminated": counts[ELIMINATED],
            "total": sum(counts.values()),
        },
        "filters": {
            "status": status or "all",
            "finding_code": finding_code or "",
            "custodian": custodian or "",
            "occurred_from": occurred_from or "",
            "occurred_to": occurred_to or "",
            "sample_id": sample_id,
        },
    }


def sample_findings_summary(conn: Connection, sample_id: int) -> dict[str, int]:
    """单样本的处置状态计数（样本详情页入口用）。"""
    counts = {OPEN: 0, RESOLVED: 0, ELIMINATED: 0}
    for r in conn.execute(
        "SELECT status, COUNT(*) AS n FROM finding_dispositions WHERE sample_id = ? "
        "GROUP BY status",
        (sample_id,),
    ).fetchall():
        counts[r["status"]] = r["n"]
    return {
        "open": counts[OPEN],
        "resolved": counts[RESOLVED],
        "eliminated": counts[ELIMINATED],
        "total": sum(counts.values()),
    }


# ---------- 处置写入（乐观锁） ----------

def apply_disposition(
    conn: Connection,
    *,
    fingerprint: str,
    action: str,
    handler_name: str,
    handler_note: str,
    expected_version: int,
    acted_at: Optional[str] = None,
) -> dict[str, Any]:
    """标记已处理 / 重新打开。必须携带客户端看到的指纹版本，过期即 409。"""
    now = acted_at or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    row = conn.execute(
        "SELECT * FROM finding_dispositions WHERE fingerprint = ?", (fingerprint,)
    ).fetchone()
    if row is None:
        raise FindingError("异常发现不存在，可能已随样本删除", status_code=404)

    if row["version"] != expected_version:
        raise FindingError(
            f"该发现的指纹版本已过期（你看到的是 v{expected_version}，"
            f"当前为 v{row['version']}）：处置期间链路可能已被重算或他人已处置，"
            f"请按刷新后的最新状态重试",
            status_code=409,
        )

    old_status = row["status"]
    if action == ACTION_RESOLVED:
        if old_status == RESOLVED:
            raise FindingError("该发现已标记为已处理，请勿重复提交")
        if old_status == ELIMINATED:
            raise FindingError("该发现已随链路重算消除，不能再标记处理")
        conn.execute(
            "UPDATE finding_dispositions SET status = ?, handler_name = ?, "
            "handler_note = ?, resolved_at = ?, version = version + 1, "
            "updated_at = ? WHERE fingerprint = ?",
            (RESOLVED, handler_name, handler_note, now, now, fingerprint),
        )
        _log_transition(
            conn, fingerprint=fingerprint, sample_id=row["sample_id"],
            action=ACTION_RESOLVED, actor=handler_name, note=handler_note,
            from_status=OPEN, to_status=RESOLVED, created_at=now,
        )
    elif action == ACTION_REOPENED:
        if old_status != RESOLVED:
            raise FindingError("仅已处理的发现可以重新打开")
        conn.execute(
            "UPDATE finding_dispositions SET status = ?, handler_name = ?, "
            "handler_note = ?, resolved_at = NULL, version = version + 1, "
            "updated_at = ? WHERE fingerprint = ?",
            (OPEN, handler_name, handler_note, now, fingerprint),
        )
        _log_transition(
            conn, fingerprint=fingerprint, sample_id=row["sample_id"],
            action=ACTION_REOPENED, actor=handler_name, note=handler_note,
            from_status=RESOLVED, to_status=OPEN, created_at=now,
        )
    else:
        raise FindingError(f"不支持的处置动作：{action}", status_code=400)

    fresh = conn.execute(
        "SELECT fd.*, s.code AS sample_code, s.name AS sample_name "
        "FROM finding_dispositions fd JOIN samples s ON s.id = fd.sample_id "
        "WHERE fd.fingerprint = ?",
        (fingerprint,),
    ).fetchone()
    return _row_to_item(fresh)


# ---------- 状态迁移记录 ----------

def list_transitions(
    conn: Connection,
    *,
    sample_id: Optional[int] = None,
    fingerprint: Optional[str] = None,
    limit: int = 200,
) -> list[dict[str, Any]]:
    where: list[str] = []
    params: list[Any] = []
    if sample_id is not None:
        where.append("t.sample_id = ?")
        params.append(sample_id)
    if fingerprint:
        where.append("t.fingerprint = ?")
        params.append(fingerprint)
    where_sql = (" WHERE " + " AND ".join(where)) if where else ""
    limit = max(1, min(int(limit), 1000))

    rows = conn.execute(
        "SELECT t.*, s.code AS sample_code, fd.finding_code, fd.message AS finding_message "
        "FROM finding_transitions t "
        "LEFT JOIN samples s ON s.id = t.sample_id "
        "LEFT JOIN finding_dispositions fd ON fd.fingerprint = t.fingerprint"
        f"{where_sql} ORDER BY t.id DESC LIMIT ?",
        (*params, limit),
    ).fetchall()

    items: list[dict[str, Any]] = []
    for r in rows:
        items.append(
            {
                "id": r["id"],
                "fingerprint": r["fingerprint"],
                "sample_id": r["sample_id"],
                "sample_code": r["sample_code"],
                "action": r["action"],
                "action_text": ACTION_TEXT.get(r["action"], r["action"]),
                "actor": r["actor"],
                "note": r["note"],
                "from_status": r["from_status"],
                "from_status_text": STATUS_TEXT.get(r["from_status"], r["from_status"])
                if r["from_status"]
                else "—",
                "to_status": r["to_status"],
                "to_status_text": STATUS_TEXT.get(r["to_status"], r["to_status"]),
                "finding_code": r["finding_code"],
                "finding_code_text": FINDING_CODE_TEXT.get(r["finding_code"], r["finding_code"])
                if r["finding_code"]
                else "—",
                "finding_message": r["finding_message"] or "",
                "created_at": r["created_at"],
            }
        )
    return items
