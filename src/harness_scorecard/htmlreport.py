"""Render a :class:`Scorecard` to a self-contained HTML scorecard.

Dependency-free: a single string template with inline CSS, no external assets and no
JavaScript. Built from the redacted :func:`report.to_dict` view so nothing sensitive
reaches the page, and every interpolated value is HTML-escaped.
"""

from __future__ import annotations

import html
from typing import Any

from harness_scorecard.models import Scorecard
from harness_scorecard.report import to_dict

_GRADE_COLOR = {
    "A": "#1a7f37",
    "B": "#4c9a2a",
    "C": "#b08800",
    "D": "#bc4c00",
    "F": "#cf222e",
}
_STATUS_COLOR = {
    "pass": "#1a7f37",
    "partial": "#b08800",
    "fail": "#cf222e",
    "not_applicable": "#6e7781",
}


def _esc(value: Any) -> str:
    return html.escape(str(value))


def _check_row(check: dict[str, Any]) -> str:
    color = _STATUS_COLOR.get(check["status"], "#6e7781")
    gate = (
        f' <span class="gate">GATE&rarr;{_esc(check["gate_cap"])}</span>'
        if check["is_gate"] and check["gate_cap"]
        else ""
    )
    evidence = "".join(f"<li>{_esc(item)}</li>" for item in check["evidence"])
    evidence_html = f'<ul class="evidence">{evidence}</ul>' if evidence else ""
    fix = (
        f'<div class="fix">fix: {_esc(check["remediation"])}</div>'
        if check["status"] != "pass" and check["remediation"]
        else ""
    )
    return f"""
      <div class="check">
        <div class="check-head">
          <span class="badge" style="background:{color}">{_esc(check["status"].upper())}</span>
          <span class="cid">{_esc(check["id"])}</span>
          <span class="ctitle">{_esc(check["title"])}</span>{gate}
        </div>
        <div class="cmsg">{_esc(check["message"])}</div>
        {evidence_html}
        {fix}
      </div>"""


def _dimension_block(dim: dict[str, Any]) -> str:
    checks = "".join(_check_row(check) for check in dim["checks"])
    return f"""
    <section class="dim">
      <h2>{_esc(dim["id"])} &middot; {_esc(dim["name"])}
        <span class="dimscore">{dim["score"]:.2f} &middot; weight {dim["weight"]}</span>
      </h2>
      {checks}
    </section>"""


def render_html(card: Scorecard) -> str:
    """A self-contained HTML scorecard string."""
    data = to_dict(card)
    grade = data["grade"]
    grade_color = _GRADE_COLOR.get(grade, "#6e7781")

    gates = ""
    if data["gate_caps"]:
        items = "".join(
            f"<li><strong>{_esc(cap['id'])}</strong> caps grade at {_esc(cap['caps_at'])}</li>"
            for cap in data["gate_caps"]
        )
        gates = f'<div class="gates"><h3>Capability gates tripped</h3><ul>{items}</ul></div>'

    caveats = ""
    if data["caveats"]:
        items = "".join(f"<li>{_esc(caveat)}</li>" for caveat in data["caveats"])
        caveats = (
            '<div class="caveats"><h3>Caveats</h3>'
            "<p>A low score on an affected check may be a static-analysis limit, "
            "not a missing guard.</p>"
            f"<ul>{items}</ul></div>"
        )

    pending = ", ".join(_esc(d) for d in data["pending_dimensions"])
    pending_html = (
        f'<p class="pending">Pending dimensions (specced, not yet scored): {pending}</p>'
        if pending
        else ""
    )
    dimensions = "".join(_dimension_block(dim) for dim in data["dimensions"])

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Harness Scorecard &middot; {_esc(data["harness_path"])}</title>
<style>
  :root {{ font-family: -apple-system, system-ui, "Segoe UI", sans-serif; }}
  body {{ margin: 0; background: #f6f8fa; color: #1f2328; }}
  .wrap {{ max-width: 880px; margin: 0 auto; padding: 32px 20px 64px; }}
  header {{ display: flex; align-items: center; gap: 24px; margin-bottom: 8px; }}
  .grade {{ font-size: 64px; font-weight: 800; color: #fff; background: {grade_color};
            width: 96px; height: 96px; border-radius: 16px; display: flex;
            align-items: center; justify-content: center; flex: none; }}
  .meta h1 {{ margin: 0 0 4px; font-size: 20px; }}
  .meta .path {{ color: #57606a; font-family: ui-monospace, monospace; font-size: 13px; }}
  .meta .score {{ margin-top: 6px; font-size: 14px; color: #57606a; }}
  .gates {{ background: #fff1f0; border: 1px solid #ffccc7; border-radius: 8px;
            padding: 12px 16px; margin: 20px 0; }}
  .gates h3 {{ margin: 0 0 6px; color: #cf222e; font-size: 14px; }}
  .gates ul {{ margin: 0; padding-left: 20px; font-size: 14px; }}
  .caveats {{ background: #ddf4ff; border: 1px solid #b6e3ff; border-radius: 8px;
              padding: 12px 16px; margin: 20px 0; }}
  .caveats h3 {{ margin: 0 0 6px; color: #0969da; font-size: 14px; }}
  .caveats p {{ margin: 0 0 6px; font-size: 13px; color: #57606a; }}
  .caveats ul {{ margin: 0; padding-left: 20px; font-size: 14px; }}
  .dim {{ background: #fff; border: 1px solid #d0d7de; border-radius: 8px;
          padding: 12px 18px; margin: 16px 0; }}
  .dim h2 {{ font-size: 16px; margin: 4px 0 12px; display: flex;
             justify-content: space-between; align-items: baseline; }}
  .dimscore {{ font-size: 13px; color: #57606a; font-weight: 500; }}
  .check {{ border-top: 1px solid #eaeef2; padding: 10px 0; }}
  .check-head {{ display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }}
  .badge {{ color: #fff; font-size: 11px; font-weight: 700; padding: 2px 6px;
            border-radius: 4px; }}
  .cid {{ font-family: ui-monospace, monospace; font-size: 12px; color: #57606a; }}
  .ctitle {{ font-weight: 600; font-size: 14px; }}
  .gate {{ font-size: 11px; font-weight: 700; color: #cf222e; }}
  .cmsg {{ font-size: 13px; color: #1f2328; margin: 4px 0 0 2px; }}
  .evidence {{ margin: 4px 0 0 18px; font-size: 12px; color: #57606a; }}
  .fix {{ font-size: 12px; color: #0969da; margin: 4px 0 0 2px; }}
  .pending {{ color: #57606a; font-size: 13px; margin-top: 20px; }}
  footer {{ color: #8c959f; font-size: 12px; margin-top: 24px; }}
</style>
</head>
<body>
  <div class="wrap">
    <header>
      <div class="grade">{_esc(grade)}</div>
      <div class="meta">
        <h1>Harness Scorecard</h1>
        <div class="path">{_esc(data["harness_path"])} &middot; {_esc(data["harness_type"])}</div>
        <div class="score">overall {data["overall_score"]:.2f} / 1.00 &middot;
          scored {data["dimensions_scored"]} of {data["dimensions_total"]} dimensions</div>
      </div>
    </header>
    {caveats}
    {gates}
    {dimensions}
    {pending_html}
    <footer>Rubric v{_esc(data["rubric_version"])} &middot; read-only &middot; redacted</footer>
  </div>
</body>
</html>"""
