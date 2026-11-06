
'use client';

import { useEffect, useState } from 'react';

const API = process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:8000';

type Check = {
  check_id: string;
  title: string;
  status: string;
  evidence: string;
};

type Instance = {
  instance_id: string;
  instance_type: string;
  region: string;
  public_ip: string | null;
  security_groups: string[];
};

type Bucket = {
  bucket_name: string;
  region: string;
  encrypted: boolean | null;
  public: boolean | null;
  public_evidence: string;
};

type Summary = {
  instances?: number;
  buckets?: number;
  passed?: number;
  failed?: number;
  errors?: number;
  generated_at?: string;
};

type ScanHistory = {
  scan_id: string;
  generated_at: string;
  instances: number;
  buckets: number;
  passed: number;
  failed: number;
  errors: number;
  security_score: number | null;
};

function Status({ value }: { value: string }) {
  const cls =
    value === 'PASS'
      ? 'bg-green-100 text-green-800'
      : value === 'FAIL'
      ? 'bg-red-100 text-red-800'
      : value === 'ERROR'
      ? 'bg-orange-100 text-orange-800'
      : 'bg-amber-100 text-amber-800';

  return (
    <span className={`rounded-full px-3 py-1 text-xs font-bold ${cls}`}>
      {value}
    </span>
  );
}

function Metric({
  label,
  value,
  color = 'text-slate-900',
}: {
  label: string;
  value: string | number;
  color?: string;
}) {
  return (
    <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
      <p className="text-sm font-medium text-slate-500">{label}</p>
      <p className={`mt-2 text-3xl font-bold ${color}`}>{value}</p>
    </div>
  );
}

function formatDate(value: string) {
  if (!value) return 'Not available';

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) return value;

  return date.toLocaleString();
}

export default function Home() {
  const [checks, setChecks] = useState<Check[]>([]);
  const [instances, setInstances] = useState<Instance[]>([]);
  const [buckets, setBuckets] = useState<Bucket[]>([]);
  const [summary, setSummary] = useState<Summary>({});
  const [history, setHistory] = useState<ScanHistory[]>([]);
  const [mode, setMode] = useState('loading');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [lastScan, setLastScan] = useState('');

  const passedChecks = checks.filter(c => c.status === 'PASS').length;
  const failedChecks = checks.filter(c => c.status === 'FAIL').length;

  const unknownChecks = checks.filter(
    c => c.status === 'UNKNOWN' || c.status === 'ERROR'
  ).length;

  const evaluatedChecks = passedChecks + failedChecks;

  const securityScore = evaluatedChecks
    ? Math.round((passedChecks / evaluatedChecks) * 100)
    : null;

  async function load() {
    const urls = [
      'health',
      'instances',
      'buckets',
      'cis-results',
      'summary',
      'scan-history',
    ];

    const res = await Promise.all(
      urls.map(x => fetch(`${API}/${x}`, { cache: 'no-store' }))
    );

    if (!res.every(x => x.ok)) {
      throw new Error('API request failed. Is the backend running?');
    }

    const [h, i, b, c, s, historyData] = await Promise.all(
      res.map(x => x.json())
    );

    setMode(h.mode);
    setInstances(i);
    setBuckets(b);
    setChecks(c);
    setSummary(s);
    setHistory(
      (historyData.history || []).filter(
        (item: ScanHistory) =>
          item.passed + item.failed + item.errors > 0
      )
    );

    if (s.generated_at) {
      setLastScan(s.generated_at);
    }
  }

  async function scan() {
    if (busy) return;

    setBusy(true);
    setError('');
    setSuccess('');

    try {
      const r = await fetch(`${API}/scan`, {
        method: 'POST',
      });

      if (!r.ok) {
        const data = await r.json().catch(() => ({}));
        throw new Error(data.detail || 'Scan failed');
      }

      const result = await r.json();

      await load();

      setSuccess(
        result.message || 'Scan completed successfully! Dashboard refreshed.'
      );
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Scan failed');
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => {
    load().catch(e => {
      setError(e.message || 'Unable to connect to backend');
    });
  }, []);

  const scoreColor =
    securityScore === null
      ? 'text-slate-400'
      : securityScore >= 80
      ? 'text-green-600'
      : securityScore >= 50
      ? 'text-amber-600'
      : 'text-red-600';

  return (
    <main className="mx-auto max-w-7xl p-6 md:p-10">
      <header className="mb-8 flex flex-col justify-between gap-5 md:flex-row md:items-center">
        <div>
          <p className="text-sm font-semibold uppercase tracking-widest text-blue-700">
            Cloud Security Platform
          </p>

          <h1 className="mt-2 text-3xl font-bold tracking-tight text-slate-900 md:text-4xl">
            Cloud Posture Scanner
          </h1>

          <p className="mt-2 text-slate-500">
            AWS resource inventory and CIS-inspired security assessment
          </p>
        </div>

        <div className="flex items-center gap-3">
          <span
            className={`rounded-full px-4 py-2 text-xs font-bold uppercase ${
              mode === 'live'
                ? 'bg-green-100 text-green-800'
                : 'bg-slate-200 text-slate-700'
            }`}
          >
            {mode} mode
          </span>

          <button
            onClick={scan}
            disabled={busy}
            className="rounded-lg bg-blue-700 px-5 py-3 font-semibold text-white shadow-sm transition hover:bg-blue-800 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {busy ? 'Scanning...' : 'Run scan'}
          </button>
        </div>
      </header>

      {busy && (
        <div className="mb-5 rounded-lg border border-blue-200 bg-blue-50 p-4 text-blue-700">
          Scan in progress. Discovering AWS resources and checking security...
        </div>
      )}

      {success && (
        <div className="mb-5 rounded-lg border border-green-200 bg-green-50 p-4 text-green-700">
          ✓ {success}
        </div>
      )}

      {error && (
        <div className="mb-5 rounded-lg border border-red-200 bg-red-50 p-4 text-red-700">
          {error}
        </div>
      )}

      <section className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Metric label="EC2 instances" value={summary.instances ?? 0} />
        <Metric label="S3 buckets" value={summary.buckets ?? 0} />
        <Metric label="Checks passed" value={passedChecks} color="text-green-600" />
        <Metric label="Checks failed" value={failedChecks} color="text-red-600" />
      </section>

      <section className="mt-8 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
          <p className="text-sm font-medium text-slate-500">
            Overall Security Score
          </p>

          <div className="mt-3 flex items-end gap-2">
            <span className={`text-5xl font-bold ${scoreColor}`}>
              {securityScore === null ? 'N/A' : securityScore}
            </span>
            <span className="mb-1 text-slate-400">/ 100</span>
          </div>

          <div className="mt-4 h-2 overflow-hidden rounded-full bg-slate-100">
            <div
              className="h-full rounded-full bg-blue-600 transition-all"
              style={{ width: `${securityScore ?? 0}%` }}
            />
          </div>

          <p className="mt-3 text-xs text-slate-500">
            Based only on evaluated PASS and FAIL checks
          </p>
        </div>

        <Metric
          label="Checks requiring attention"
          value={failedChecks}
          color="text-red-600"
        />

        <Metric
          label="Unknown / Error checks"
          value={unknownChecks}
          color="text-amber-600"
        />
      </section>

      <section className="mt-8 rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
        <div className="mb-5 flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-xl font-bold text-slate-900">
              CIS Security Assessment
            </h2>
            <p className="mt-1 text-sm text-slate-500">
              Security findings with evidence from the latest scan
            </p>
          </div>

          <span className="rounded-full bg-slate-100 px-3 py-1 text-xs font-semibold text-slate-600">
            {checks.length} checks
          </span>
        </div>

        <div className="space-y-3">
          {checks.map(c => (
            <div
              key={c.check_id}
              className="rounded-lg border border-slate-200 p-4 transition hover:bg-slate-50"
            >
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="font-semibold text-slate-800">
                  {c.title}
                </div>
                <Status value={c.status} />
              </div>

              <p className="mt-2 text-sm leading-6 text-slate-500">
                Evidence: {c.evidence}
              </p>
            </div>
          ))}

          {!checks.length && (
            <p className="p-4 text-center text-slate-500">
              No security assessment results available.
            </p>
          )}
        </div>
      </section>

      <section className="mt-8 rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
        <div className="mb-5 flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-xl font-bold text-slate-900">
              Scan History
            </h2>
            <p className="mt-1 text-sm text-slate-500">
              Previous security scans stored in Amazon DynamoDB
            </p>
          </div>

          <span className="rounded-full bg-blue-50 px-3 py-1 text-xs font-semibold text-blue-700">
            {history.length} records
          </span>
        </div>

        {history.length > 0 ? (
          <div className="space-y-4">
            {history.map((item, index) => (
              <div
                key={item.scan_id}
                className="rounded-xl border border-slate-200 p-4 transition hover:bg-slate-50"
              >
                <div className="flex flex-col justify-between gap-4 md:flex-row md:items-center">
                  <div>
                    <div className="flex flex-wrap items-center gap-2">
                      <h3 className="font-semibold text-slate-800">
                        Scan #{index + 1}
                      </h3>

                      {index === 0 && (
                        <span className="rounded-full bg-green-100 px-2 py-1 text-xs font-bold text-green-800">
                          Latest
                        </span>
                      )}
                    </div>

                    <p className="mt-1 text-sm text-slate-500">
                      {formatDate(item.generated_at)}
                    </p>

                    <p className="mt-1 break-all font-mono text-xs text-slate-400">
                      ID: {item.scan_id}
                    </p>
                  </div>

                  <div className="flex flex-wrap gap-5">
                    <div>
                      <p className="text-xs text-slate-500">Security Score</p>
                      <p className={`mt-1 text-2xl font-bold ${
                        item.security_score === null
                          ? 'text-slate-400'
                          : item.security_score >= 80
                          ? 'text-green-600'
                          : item.security_score >= 50
                          ? 'text-amber-600'
                          : 'text-red-600'
                      }`}>
                        {item.security_score === null
                          ? 'N/A'
                          : `${item.security_score}/100`}
                      </p>
                    </div>

                    <div>
                      <p className="text-xs text-slate-500">EC2</p>
                      <p className="mt-1 text-xl font-bold text-slate-800">
                        {item.instances}
                      </p>
                    </div>

                    <div>
                      <p className="text-xs text-slate-500">S3</p>
                      <p className="mt-1 text-xl font-bold text-slate-800">
                        {item.buckets}
                      </p>
                    </div>
                  </div>
                </div>

                <div className="mt-4 flex flex-wrap gap-3 border-t border-slate-100 pt-3 text-sm">
                  <span className="font-medium text-green-700">
                    PASS: {item.passed}
                  </span>
                  <span className="font-medium text-red-700">
                    FAIL: {item.failed}
                  </span>
                  <span className="font-medium text-amber-700">
                    ERROR / UNKNOWN: {item.errors}
                  </span>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <p className="rounded-lg bg-slate-50 p-6 text-center text-slate-500">
            No scan history available. Run a live scan to create your first record.
          </p>
        )}
      </section>

      <section className="mt-8 rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
        <h2 className="mb-1 text-xl font-bold text-slate-900">
          EC2 Inventory
        </h2>

        <p className="mb-4 text-sm text-slate-500">
          Discovered Amazon EC2 instances
        </p>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="bg-slate-50 text-slate-500">
              <tr>
                {['Instance ID', 'Type', 'Region', 'Public IP', 'Security groups'].map(x => (
                  <th className="p-3" key={x}>{x}</th>
                ))}
              </tr>
            </thead>

            <tbody>
              {instances.map(x => (
                <tr className="border-t border-slate-100" key={x.instance_id}>
                  <td className="p-3 font-mono">{x.instance_id}</td>
                  <td className="p-3">{x.instance_type}</td>
                  <td className="p-3">{x.region}</td>
                  <td className="p-3">{x.public_ip || '—'}</td>
                  <td className="p-3">{x.security_groups.join(', ') || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>

          {!instances.length && (
            <p className="p-5 text-center text-slate-500">
              No EC2 instances discovered in the connected AWS account.
            </p>
          )}
        </div>
      </section>

      <section className="mt-8 rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
        <h2 className="mb-1 text-xl font-bold text-slate-900">
          S3 Bucket Inventory
        </h2>

        <p className="mb-4 text-sm text-slate-500">
          Storage encryption and public access posture
        </p>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="bg-slate-50 text-slate-500">
              <tr>
                {['Bucket', 'Region', 'Encrypted', 'Public', 'Evidence'].map(x => (
                  <th className="p-3" key={x}>{x}</th>
                ))}
              </tr>
            </thead>

            <tbody>
              {buckets.map(x => (
                <tr className="border-t border-slate-100" key={x.bucket_name}>
                  <td className="p-3 font-mono">{x.bucket_name}</td>
                  <td className="p-3">{x.region}</td>
                  <td className="p-3">
                    {x.encrypted === null ? 'Unknown' : x.encrypted ? 'Yes' : 'No'}
                  </td>
                  <td className="p-3">
                    {x.public === null ? 'Unknown' : x.public ? 'Yes' : 'No'}
                  </td>
                  <td className="p-3">{x.public_evidence}</td>
                </tr>
              ))}
            </tbody>
          </table>

          {!buckets.length && (
            <p className="p-5 text-center text-slate-500">
              No S3 buckets discovered in the connected AWS account.
            </p>
          )}
        </div>
      </section>

      <footer className="mt-8 border-t border-slate-200 pt-5 text-xs text-slate-500">
        <p>
          Last scan: {lastScan || summary.generated_at || 'Not available'}
        </p>
        <p className="mt-2">
          CIS-inspired assignment checks. Demo findings are simulated and are not
          findings from an AWS account.
        </p>
        <p className="mt-1">
          UNKNOWN and ERROR checks are excluded from the security score.
        </p>
      </footer>
    </main>
  );
}
