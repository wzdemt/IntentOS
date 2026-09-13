"""平台面板 —— 复用原语工厂(factory.registry) + 加载 primitives/ 的 OS 原语。

结构：
- 最上面：项目一句话介绍
- 右上角：system.info 实时状态（常显，唯一显示状态的）
- 主区：原语卡片（名称 + 介绍，不显示结果 / 运行按钮）
- 底部 skills 区：展示「能力」(组合原语的端到端能力)；目前 skills/ 无能力 → 空/预留

运行：python adapters/panel.py   （浏览器 http://127.0.0.1:8898）
"""
from __future__ import annotations

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# 项目根加入 sys.path —— 让 `from core import ...` 在直接运行本文件时可用
_BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BASE not in sys.path:
    sys.path.insert(0, _BASE)

from core import factory

factory.load_primitives(os.path.join(_BASE, "primitives"))

registry = factory.registry
STATE_SCHEMA = factory.STATE_SCHEMA
POLICY = factory.POLICY
_RESULTS: dict[str, dict] = {}


_PROGRESS_JSON = os.path.join(_BASE, "docs", "os-progress.json")


def _load_progress() -> dict:
    """读能力落地进度（由 examples/gen_progress.py 生成）。

    刻意只读 JSON、**不 import 生成器** —— 面板在 adapters 层，生成器是 examples 里的工具脚本，
    按 README 的分层规范，examples 不放被生产路径 import 的模块。生成物是两者之间的接口。
    """
    try:
        with open(_PROGRESS_JSON, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _list_skills() -> list[str]:
    """扫描 skills/ 目录下的能力文件（目前预留为空）。"""
    d = os.path.join(_BASE, "skills")
    if not os.path.isdir(d):
        return []
    return [f for f in sorted(os.listdir(d))
            if f.endswith((".py", ".md")) and not f.startswith("_") and f != "README.md"]


def build_status() -> dict:
    tools = []
    for name, tool in registry._tools.items():
        state = {}
        for field in STATE_SCHEMA.get(name, {}):
            try:
                v = _RESULTS.get(name, {}).get(field)
                if v is not None:
                    state[field] = v
            except Exception:
                state[field] = None
        tools.append({
            "name": name,
            "source": tool.get("source", "native"),
            "description": tool["description"],
            "state": state,
            "needs_approval": POLICY.get(name, {}).get("requires_confirmation", False),
        })
    return {"tools": tools, "skills": _list_skills(), "progress": _load_progress()}


# 启动预跑 system.info（只读实时状态）→ 右上角常显
try:
    _RESULTS["system.info"] = registry.execute("system.info", {})
except Exception:
    pass


# ── dashboard：顶部介绍 + 右上 system.info + 原语介绍卡片 + skills 区 ──
DASHBOARD_HTML = """<!doctype html><html><head><meta charset="utf-8"><title>IntentOS</title>
<style>
::-webkit-scrollbar{width:8px;height:8px}
::-webkit-scrollbar-thumb{background:#33384a;border-radius:4px}
body{font-family:sans-serif;max-width:1000px;margin:24px auto;padding:0 16px;background:#0f1115;color:#e6e6e6}
header{display:flex;justify-content:space-between;align-items:center;gap:16px;flex-wrap:wrap}
h1{font-size:22px;margin:0}
.sysinfo{background:#1a1d24;border:1px solid #2a2e38;border-radius:10px;padding:10px 16px;font-size:13px;color:#8fd3ff}
.sysinfo b{color:#e6e6e6}
.intro{color:#9aa;font-size:13px;margin:10px 0 0}
h2{font-size:16px;margin:28px 0 12px;border-top:1px solid #2a2e38;padding-top:14px}
.src{font-size:11px;padding:2px 8px;border-radius:10px;margin-left:8px;vertical-align:middle}
.src-native{background:#2b3a4a;color:#8fd3ff}.src-agent{background:#3a2b2b;color:#ffb86b}.src-plugin{background:#2b2b3a;color:#c3a6ff}
.appr{font-size:11px;padding:2px 8px;border-radius:10px;background:#5a2b2b;color:#ffb0b0;margin-left:8px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:16px}
.card{background:#1a1d24;border:1px solid #2a2e38;border-radius:10px;padding:14px}
.card h3{margin:0 0 4px;font-size:15px}.card .desc{color:#9aa;font-size:12px}
.skill{background:#1a1d24;border:1px solid #2a2e38;border-radius:8px;padding:10px 14px;margin-bottom:8px}
.skill b{color:#ffb86b}.skill .sd{color:#9aa;font-size:12px}
.skill.none{color:#556}
.pg-head{font-size:14px;margin-bottom:12px}.pg-sub{color:#667;font-size:12px;margin-left:8px}
.pg-dom{background:#1a1d24;border:1px solid #2a2e38;border-radius:10px;margin-bottom:10px;overflow:hidden}
.pg-row{display:flex;justify-content:space-between;align-items:center;gap:12px;padding:10px 14px;cursor:pointer;font-size:13px}
.pg-row code{color:#8fd3ff;letter-spacing:1px}.pg-row b{color:#e6e6e6;min-width:74px;text-align:right}
.pg-tree{display:none;padding:2px 14px 12px;border-top:1px solid #22252e}
.pg-dom.open .pg-tree{display:block}
.pg-grp{color:#ffb86b;font-size:12px;margin:10px 0 6px}
.pg-item{font-size:12px;color:#788;padding:2px 0}.pg-item.done{color:#9fd6a0}
.pg-item code{color:inherit;opacity:.85}.star{color:#ffb86b;font-size:11px}
</style></head><body>
<header>
  <h1>IntentOS</h1>
  <div id="sysinfo" class="sysinfo"></div>
</header>
<p class="intro">AI 意图的语义执行层 —— 让 AI 通过 IR（语义指令）安全、稳定地操作本地系统资源。</p>
<h2>能力落地进度</h2>
<div id="progress"></div>
<h2>原语</h2>
<div class="grid" id="grid"></div>
<h2>能力 Skills</h2>
<div id="skills"></div>
<script>
async function load(){
  const d = await (await fetch('/status')).json();
  // 右上角 system.info 实时状态
  const sys = d.tools.find(t=>t.name==='system.info');
  document.getElementById('sysinfo').innerHTML = sys && sys.state && sys.state.total_mb ?
    `<b>${sys.state.total_mb}</b>MB 总 / 可用 <b>${sys.state.avail_mb}</b>MB / 占用 <b>${sys.state.load}</b>%` :
    '<span style="color:#556">系统状态（读取中…）</span>';
  // 能力 skills（目前预留）
  const sk = document.getElementById('skills');
  sk.innerHTML = (d.skills && d.skills.length) ?
    d.skills.map(s=>`<div class="skill"><b>${s}</b></div>`).join('') :
    '<div class="skill none">暂未注册能力（skills 目录预留，加个能力文件就自动显示）</div>';
  // 能力落地进度（读 docs/os-progress.json —— 跟 docs/os-progress.md 同一份数据）
  const pg = document.getElementById('progress');
  if (!d.progress || !d.progress.domains || !d.progress.domains.length) {
    pg.innerHTML = '<div class="skill none">暂无进度数据 —— 跑一次 python examples/gen_progress.py</div>';
  } else {
    const s = d.progress.summary;
    const bar=(n,t)=>{const c=20,f=t>0?Math.round(c*n/t):0;return '█'.repeat(f)+'░'.repeat(c-f);};
    let h=`<div class="pg-head">已落地 <b>${s.done}</b> / ${s.planned} 条「建议做原语」的能力`
        + `<span class="pg-sub">地图逐行 ${s.all_raw} 条 → 去重后 ${s.all} 条 · 点域名展开</span></div>`;
    d.progress.domains.forEach(dom=>{
      h+=`<div class="pg-dom"><div class="pg-row"><span>${dom.name}</span>`
        +`<code>${bar(dom.done,dom.planned)}</code><b>${dom.done} / ${dom.planned}</b></div><div class="pg-tree">`;
      dom.groups.forEach(g=>{
        const items=g.items.filter(it=>it.planned);
        if(!items.length)return;
        h+=`<div class="pg-grp">${g.name}</div>`;
        items.forEach(it=>{
          h+=`<div class="pg-item ${it.done?'done':''}">${it.done?'✅':'⬜'} `
            +`<code>${it.id||''}</code> ${it.label}${it.star?' <span class="star">★首批</span>':''}</div>`;
        });
      });
      h+='</div></div>';
    });
    pg.innerHTML=h;
    pg.querySelectorAll('.pg-dom').forEach(el=>el.addEventListener('click',()=>el.classList.toggle('open')));
  }
  // 原语卡片：仅名称 + 介绍
  const grid = document.getElementById('grid'); grid.innerHTML='';
  d.tools.filter(t=>t.name!=='system.info').forEach(t=>{
    const card=document.createElement('div'); card.className='card';
    const srcTxt={native:'通用原语',agent:'agent自有',plugin:'插件'}[t.source]||t.source;
    const appr=t.needs_approval?'<span class="appr">需确认</span>':'';
    card.innerHTML=`<h3>${t.name}<span class="src src-${t.source}">${srcTxt}</span>${appr}</h3>
      <div class="desc">${t.description||''}</div>`;
    grid.appendChild(card);
  });
}
load();
</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/status":
            self._send(200, json.dumps(build_status(), ensure_ascii=False).encode("utf-8"),
                       "application/json")
        else:
            self._send(200, DASHBOARD_HTML.encode("utf-8"), "text/html; charset=utf-8")

    def do_POST(self):
        if self.path == "/run":
            try:
                length = int(self.headers.get("Content-Length", 0))
                data = json.loads(self.rfile.read(length) or b"{}")
                name, args = data.get("name", ""), data.get("args", {})
                if POLICY.get(name, {}).get("requires_confirmation"):
                    self._send(200, json.dumps(
                        {"ok": False, "error": "该原语需确认（如清理内存/杀进程），面板不执行"},
                        ensure_ascii=False).encode("utf-8"), "application/json")
                    return
                result = registry.execute(name, args)
                if isinstance(result, dict):
                    _RESULTS[name] = result
                self._send(200, json.dumps({"ok": True, "result": result}, ensure_ascii=False).encode("utf-8"),
                           "application/json")
            except Exception as e:
                self._send(500, json.dumps({"ok": False, "error": str(e)}).encode("utf-8"),
                           "application/json")

    def log_message(self, *a):
        pass


def main():
    port = int(os.environ.get("PANEL_PORT", "8898"))
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"✅ IntentOS 面板已启动：http://127.0.0.1:{port}  (Ctrl+C 停止)")
    server.serve_forever()


if __name__ == "__main__":
    main()
