
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
  generated_at?: string;
};

function Status({ value }: { value: string }) {
  const cls = value === 'PASS'
    ? 'bg-green-100 text-green-800'
    : value === 'FAIL'
    ? 'bg-red-100 text-red-800'
    : 'bg-amber-100 text-amber-800';

  return (
    <span className={`rounded-full px-3 py-1 text-xs font-bold ${cls}`}>
      {value}
    </span>
  );
}

export default function Home() {
  const [checks, setChecks] = useState<Check[]>([]);
  const [instances, setInstances] = useState<Instance[]>([]);
  const [buckets, setBuckets] = useState<Bucket[]>([]);
  const [summary, setSummary] = useState<Summary>({});
  const [mode, setMode] = useState('loading');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [lastScan, setLastScan] = useState('');

  async function load() {
    const urls = [
      'health',
      'instances',
      'buckets',
      'cis-results',
      'summary'
    ];

    const res = await Promise.all(
      urls.map(x => fetch(`${API}/${x}`, { cache: 'no-store' }))
    );

    if (!res.every(x => x.ok)) {
      throw new Error('API request failed. Is the backend running?');
    }

    const [h, i, b, c, s] = await Promise.all(
      res.map(x => x.json())
    );

    setMode(h.mode);
    setInstances(i);
    setBuckets(b);
    setChecks(c);
    setSummary(s);

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
        method: 'POST'
      });

      if (!r.ok) {
        const data = await r.json().catch(() => ({}));
        throw new Error(data.detail || 'Scan failed');
      }

      await load();

      setLastScan(new Date().toLocaleString());
      setSuccess('Scan completed successfully! Dashboard data refreshed.');
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

  return (
    <main className="mx-auto max-w-7xl p-6 md:p-10">
      <header className="mb-8 flex flex-col justify-between gap-4 md:flex-row md:items-center">
        <div>
          <p className="text-sm font-semibold uppercase tracking-widest text-blue-700">
            Cloud Security
          </p>
          <h1 className="mt-2 text-3xl font-bold">
            Cloud Posture Scanner
          </h1>
          <p className="mt-2 text-slate-500">
            AWS resource inventory and CIS-inspired security checks
          </p>
        </div>

        <div className="flex items-center gap-3">
          <span className="rounded-full bg-slate-200 px-3 py-2 text-xs font-bold uppercase">
            {mode} mode
          </span>

          <button
            onClick={scan}
            disabled={busy}
            className="rounded-lg bg-blue-700 px-5 py-3 font-semibold text-white disabled:cursor-not-allowed disabled:opacity-50"
          >
            {busy ? 'Scanning...' : 'Run scan'}
          </button>
        </div>
      </header>

      {busy && (
        <div className="mb-5 rounded-lg border border-blue-200 bg-blue-50 p-4 text-blue-700">
          Scan in progress. Discovering resources and checking security...
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
        {[
          ['EC2 instances', summary.instances ?? 0],
          ['S3 buckets', summary.buckets ?? 0],
          ['Checks passed', summary.passed ?? 0],
          ['Checks failed', summary.failed ?? 0]
        ].map(([label, value]) => (
          <div key={label} className="rounded-xl border bg-white p-5 shadow-sm">
            <p className="text-sm text-slate-500">{label}</p>
            <p className="mt-2 text-3xl font-bold">{value}</p>
          </div>
        ))}
      </section>

      <section className="mt-8 rounded-xl border bg-white p-5 shadow-sm">
        <h2 className="mb-4 text-xl font-bold">CIS security checks</h2>

        <div className="space-y-3">
          {checks.map(c => (
            <div key={c.check_id} className="rounded-lg border p-4">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="font-semibold">{c.title}</div>
                <Status value={c.status} />
              </div>
              <p className="mt-2 text-sm text-slate-500">
                Evidence: {c.evidence}
              </p>
            </div>
          ))}
        </div>
      </section>

      <section className="mt-8 rounded-xl border bg-white p-5 shadow-sm">
        <h2 className="mb-4 text-xl font-bold">EC2 instances</h2>

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
                <tr className="border-t" key={x.instance_id}>
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
            <p className="p-4 text-slate-500">No instances discovered.</p>
          )}
        </div>
      </section>

      <section className="mt-8 rounded-xl border bg-white p-5 shadow-sm">
        <h2 className="mb-4 text-xl font-bold">S3 buckets</h2>

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
                <tr className="border-t" key={x.bucket_name}>
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
            <p className="p-4 text-slate-500">No buckets discovered.</p>
          )}
        </div>
      </section>

      <p className="mt-6 text-xs text-slate-500">
        Last scan: {lastScan || summary.generated_at || 'Not available'}
        {' · '}
        Demo findings are simulated, not findings from an AWS account.
      </p>
    </main>
  );
}
