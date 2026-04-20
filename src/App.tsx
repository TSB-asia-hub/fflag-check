import { useCallback, useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { ScanFinding, ScanReport, ScanVerdict } from "./types";

type Phase = "idle" | "scanning" | "complete";
type Filter = "all" | "flagged" | "suspicious" | "clean";

const SCANNERS = [
  "processes",
  "file system",
  "client settings",
  "prefetch cache",
  "memory regions",
];

type Toast = { msg: string; kind: "info" | "success" | "error" };

// Tauri v2 injects its invoke bridge at window.__TAURI_INTERNALS__. If this
// is missing, the app is running in a plain browser (e.g. `npm run dev`
// opened at http://localhost:1420) rather than the Tauri webview, and
// `invoke` would throw "Cannot read properties of undefined".
function hasTauriRuntime(): boolean {
  return (
    typeof window !== "undefined" &&
    typeof (window as unknown as { __TAURI_INTERNALS__?: unknown })
      .__TAURI_INTERNALS__ !== "undefined"
  );
}

// Stable per-finding identity so open-state and React keys track the
// finding itself, not its position in the filtered list.
function findingKey(f: ScanFinding): string {
  return `${f.module}|${f.timestamp}|${f.description}`;
}

export default function App() {
  const [phase, setPhase] = useState<Phase>("idle");
  const [report, setReport] = useState<ScanReport | null>(null);
  const [activeScanner, setActiveScanner] = useState(0);
  const [filter, setFilter] = useState<Filter>("all");
  const [openKey, setOpenKey] = useState<string | null>(null);
  const [toast, setToast] = useState<Toast | null>(null);
  const [tauriReady, setTauriReady] = useState<boolean>(() => hasTauriRuntime());

  // The Tauri runtime is injected synchronously in the real webview, but if
  // the first render raced the injection (some loader orderings), re-check
  // on mount. We only set true — never back to false.
  useEffect(() => {
    if (tauriReady) return;
    if (hasTauriRuntime()) setTauriReady(true);
  }, [tauriReady]);

  useEffect(() => {
    if (phase !== "scanning") return;
    const id = window.setInterval(() => {
      setActiveScanner((i) => (i + 1) % SCANNERS.length);
    }, 520);
    return () => window.clearInterval(id);
  }, [phase]);

  useEffect(() => {
    if (!toast) return;
    const id = setTimeout(() => setToast(null), 3000);
    return () => clearTimeout(id);
  }, [toast]);

  // Clear the open row whenever the filter changes, so a stale selection
  // never surfaces on a different finding.
  useEffect(() => {
    setOpenKey(null);
  }, [filter]);

  const runScan = useCallback(async () => {
    if (!hasTauriRuntime()) {
      setToast({
        msg: "Tauri runtime not detected — launch the app with `npm run tauri dev` or the installed .app, not `npm run dev`.",
        kind: "error",
      });
      return;
    }
    setPhase("scanning");
    setReport(null);
    setOpenKey(null);
    setFilter("all");
    setActiveScanner(0);
    try {
      const result = await invoke<ScanReport>("run_scan");
      setReport(result);
      setPhase("complete");
    } catch (err) {
      setToast({ msg: `Scan failed: ${String(err)}`, kind: "error" });
      setPhase("idle");
    }
  }, []);

  const exportReport = useCallback(async () => {
    if (!report) return;
    if (!hasTauriRuntime()) {
      setToast({ msg: "Tauri runtime not detected — cannot export.", kind: "error" });
      return;
    }
    try {
      const path = await invoke<string>("save_report", { report });
      setToast({ msg: `Report saved → ${path}`, kind: "success" });
    } catch (err) {
      setToast({ msg: `Export failed: ${String(err)}`, kind: "error" });
    }
  }, [report]);

  const counts = useMemo(() => {
    if (!report) return { clean: 0, suspicious: 0, flagged: 0, total: 0 };
    return report.findings.reduce(
      (acc, f) => {
        if (f.verdict === "Clean") acc.clean++;
        else if (f.verdict === "Suspicious") acc.suspicious++;
        else acc.flagged++;
        acc.total++;
        return acc;
      },
      { clean: 0, suspicious: 0, flagged: 0, total: 0 },
    );
  }, [report]);

  const ordered = useMemo(() => {
    if (!report) return [];
    const rank: Record<ScanVerdict, number> = {
      Flagged: 0,
      Suspicious: 1,
      Clean: 2,
    };
    const sorted = [...report.findings].sort(
      (a, b) => rank[a.verdict] - rank[b.verdict],
    );
    if (filter === "all") return sorted;
    return sorted.filter((f) => f.verdict.toLowerCase() === filter);
  }, [report, filter]);

  return (
    <div className="app">
      {!tauriReady && (
        <div className="toast toast--error" style={{ position: "static", margin: "12px 16px 0" }}>
          Tauri runtime not detected. Launch the installed app or run{" "}
          <code>npm run tauri dev</code> — the plain Vite dev server can't reach the backend.
        </div>
      )}
      <Toolbar
        phase={phase}
        report={report}
        onScan={runScan}
        onExport={exportReport}
        disabled={!tauriReady}
      />
      <Summary
        phase={phase}
        report={report}
        counts={counts}
        scannerName={SCANNERS[activeScanner]}
      />
      <Workarea
        phase={phase}
        findings={ordered}
        filter={filter}
        onFilter={setFilter}
        openKey={openKey}
        onToggle={(k) => setOpenKey((prev) => (prev === k ? null : k))}
        onScan={runScan}
        counts={counts}
      />
      <StatusBar phase={phase} report={report} />
      {toast && <div className={`toast toast--${toast.kind}`}>{toast.msg}</div>}
    </div>
  );
}

/* ——————————————————————————————————————————————————————————— */

function Toolbar({
  phase,
  report,
  onScan,
  onExport,
  disabled = false,
}: {
  phase: Phase;
  report: ScanReport | null;
  onScan: () => void;
  onExport: () => void;
  disabled?: boolean;
}) {
  const lastScan =
    phase === "scanning"
      ? "in progress…"
      : report
        ? relativeTime(new Date(report.timestamp))
        : "never";

  const os = report?.os_info ?? "—";
  const machine = report?.machine_id ?? "—";

  return (
    <header className="toolbar">
      <div className="toolbar__left">
        <div className="brand">
          <span className="brand__logo" />
          <span>Echo</span>
          <span className="brand__sub">/ Integrity</span>
        </div>
        <div className="toolbar__divider" />
        <div className="toolbar__meta">
          <div className="toolbar__meta-cell">
            <span className="toolbar__meta-label">OS</span>
            <span className="toolbar__meta-value">{os}</span>
          </div>
          <div className="toolbar__meta-cell">
            <span className="toolbar__meta-label">Machine</span>
            <span className="toolbar__meta-value">{truncate(machine, 14)}</span>
          </div>
          <div className="toolbar__meta-cell">
            <span className="toolbar__meta-label">Last</span>
            <span className="toolbar__meta-value">{lastScan}</span>
          </div>
        </div>
      </div>
      <div className="toolbar__right">
        {phase === "complete" && report && (
          <button className="btn btn--ghost" onClick={onExport} disabled={disabled}>
            Export
          </button>
        )}
        <button
          className="btn btn--primary"
          onClick={onScan}
          disabled={phase === "scanning" || disabled}
        >
          {phase === "scanning" ? (
            <>
              <span className="btn__spinner" />
              Scanning
            </>
          ) : phase === "complete" ? (
            "Rescan"
          ) : (
            "Run scan"
          )}
        </button>
      </div>
    </header>
  );
}

/* ——————————————————————————————————————————————————————————— */

function Summary({
  phase,
  report,
  counts,
  scannerName,
}: {
  phase: Phase;
  report: ScanReport | null;
  counts: { clean: number; suspicious: number; flagged: number; total: number };
  scannerName: string;
}) {
  const modifier =
    phase === "scanning"
      ? "summary--scanning"
      : phase === "complete" && report?.overall_verdict === "Clean"
        ? "summary--clean"
        : phase === "complete" && report?.overall_verdict === "Suspicious"
          ? "summary--warn"
          : phase === "complete" && report?.overall_verdict === "Flagged"
            ? "summary--danger"
            : "";

  const verdictLabel =
    phase === "idle"
      ? "—"
      : phase === "scanning"
        ? "Scanning"
        : report?.overall_verdict ?? "—";

  return (
    <div className={`summary ${modifier}`}>
      <div className="summary__cell">
        <span className="summary__label">Verdict</span>
        <div className="summary__verdict">
          <span className="summary__dot" />
          <span>{verdictLabel}</span>
        </div>
      </div>

      <div className="summary__cell summary__cell--divider">
        <span className="summary__label">
          {phase === "scanning" ? "Probing" : "Findings"}
        </span>
        {phase === "scanning" ? (
          <div className="summary__progress">
            <div className="summary__bar">
              <div className="summary__bar-fill" />
            </div>
            <div className="summary__module">
              <span className="summary__module-active">{scannerName}</span>
            </div>
          </div>
        ) : (
          <div className="summary__counts">
            <span className="summary__count summary__count--danger">
              <span className="summary__count-num">
                {String(counts.flagged).padStart(2, "0")}
              </span>
              <span className="summary__count-label">flag</span>
            </span>
            <span className="summary__count summary__count--warn">
              <span className="summary__count-num">
                {String(counts.suspicious).padStart(2, "0")}
              </span>
              <span className="summary__count-label">susp</span>
            </span>
            <span className="summary__count summary__count--clean">
              <span className="summary__count-num">
                {String(counts.clean).padStart(2, "0")}
              </span>
              <span className="summary__count-label">clean</span>
            </span>
          </div>
        )}
      </div>

      <div className="summary__cell">
        <span className="summary__label">Scan</span>
        {report ? (
          <>
            <span className="summary__scanid">
              {truncate(report.scan_id, 18)}
            </span>
            <span className="summary__sub">
              HMAC {truncate(report.hmac_signature, 10)}
            </span>
          </>
        ) : (
          <>
            <span className="summary__scanid">—</span>
            <span className="summary__sub">no report yet</span>
          </>
        )}
      </div>
    </div>
  );
}

/* ——————————————————————————————————————————————————————————— */

function Workarea({
  phase,
  findings,
  filter,
  onFilter,
  openKey,
  onToggle,
  onScan,
  counts,
}: {
  phase: Phase;
  findings: ScanFinding[];
  filter: Filter;
  onFilter: (f: Filter) => void;
  openKey: string | null;
  onToggle: (key: string) => void;
  onScan: () => void;
  counts: { clean: number; suspicious: number; flagged: number; total: number };
}) {
  const chips: { key: Filter; label: string; modifier: string; count: number }[] = [
    { key: "all", label: "All", modifier: "", count: counts.total },
    { key: "flagged", label: "Flag", modifier: "filter-chip--danger", count: counts.flagged },
    { key: "suspicious", label: "Susp", modifier: "filter-chip--warn", count: counts.suspicious },
    { key: "clean", label: "Clean", modifier: "filter-chip--clean", count: counts.clean },
  ];

  const showChrome = phase === "complete" && counts.total > 0;

  return (
    <div className="work">
      {showChrome && (
        <div className="filters">
          <span className="filters__label">Filter</span>
          {chips.map((c) => (
            <button
              key={c.key}
              className={`filter-chip ${c.modifier} ${filter === c.key ? "filter-chip--active" : ""}`}
              onClick={() => onFilter(c.key)}
            >
              {c.modifier && <span className="filter-chip__dot" />}
              {c.label}
              <span style={{ color: "var(--text-muted)", marginLeft: 2 }}>
                {c.count}
              </span>
            </button>
          ))}
        </div>
      )}
      {showChrome && (
        <div className="table-head">
          <span />
          <span>Module</span>
          <span>Description</span>
          <span>Verdict</span>
          <span>Time</span>
          <span />
        </div>
      )}

      {phase === "idle" && (
        <div className="empty">
          <span className="empty__title">No scan yet</span>
          <button className="btn btn--ghost" onClick={onScan}>
            Run scan
          </button>
          <span className="empty__hint">
            Inspects processes · files · settings · prefetch · memory
          </span>
        </div>
      )}

      {phase === "scanning" && (
        <div className="empty">
          <span className="empty__title">Inspecting surfaces…</span>
          <span className="empty__hint">Results will populate shortly</span>
        </div>
      )}

      {phase === "complete" && findings.length === 0 && (
        <div className="empty">
          <span className="empty__title">
            {filter === "all" ? "No findings" : `No ${filter} findings`}
          </span>
          {filter !== "all" && (
            <button className="btn btn--ghost" onClick={() => onFilter("all")}>
              Show all
            </button>
          )}
        </div>
      )}

      {phase === "complete" &&
        findings.map((f) => {
          const key = findingKey(f);
          const open = openKey === key;
          const cls = `row row--${f.verdict.toLowerCase()} ${open ? "row--open" : ""}`;
          return (
            <div key={key} className={cls} onClick={() => onToggle(key)}>
              <span className="row__bar" />
              <span className="row__module">{f.module}</span>
              <span className="row__desc">{f.description}</span>
              <span className="row__verdict">{f.verdict.toLowerCase()}</span>
              <span className="row__time">{shortTime(f.timestamp)}</span>
              <span className="row__caret">›</span>
              <div className="row__details">
                <div className="row__details-inner">
                  {f.details ?? "No additional details."}
                </div>
              </div>
            </div>
          );
        })}
    </div>
  );
}

/* ——————————————————————————————————————————————————————————— */

function StatusBar({
  phase,
  report,
}: {
  phase: Phase;
  report: ScanReport | null;
}) {
  const state =
    phase === "idle"
      ? "Idle"
      : phase === "scanning"
        ? "Inspecting"
        : report?.overall_verdict ?? "Done";

  const dotCls =
    phase === "scanning"
      ? "statusbar__dot statusbar__dot--warn"
      : phase === "complete" && report?.overall_verdict === "Flagged"
        ? "statusbar__dot statusbar__dot--flag"
        : phase === "complete" && report?.overall_verdict === "Suspicious"
          ? "statusbar__dot statusbar__dot--susp"
          : phase === "complete"
            ? "statusbar__dot statusbar__dot--live"
            : "statusbar__dot";

  return (
    <footer className="statusbar">
      <div className="statusbar__group">
        <span>
          <span className={dotCls} />
          {state}
        </span>
        <span className="statusbar__sep">·</span>
        <span>TSBCC v0.1.0</span>
      </div>
      <div className="statusbar__group">
        <span>Local only</span>
        <span className="statusbar__sep">·</span>
        <span>HMAC-SHA256</span>
      </div>
    </footer>
  );
}

/* ——————————————————————————————————————————————————————————— */

function truncate(s: string, n: number): string {
  if (s.length <= n) return s;
  return s.slice(0, n) + "…";
}

function shortTime(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function relativeTime(d: Date): string {
  const diff = Math.floor((Date.now() - d.getTime()) / 1000);
  if (diff < 5) return "just now";
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return d.toLocaleDateString();
}
