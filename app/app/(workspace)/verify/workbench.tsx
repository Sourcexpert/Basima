'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import type { AuditEventRecord } from '@/lib/audit/chain';
import { Badge, Callout, Table } from '@/components/ui';

/**
 * Browser-side verification.
 *
 * Everything here runs in the customer's own browser with Web Crypto. Nothing is
 * uploaded, nothing is taken on trust from our server, and the algorithm is the
 * same one published in the package's own instructions: SHA-256 over a canonical
 * serialization, chained through `previous_hash`.
 *
 * This is the strongest form of the promise we make: you do not have to believe
 * our green tick.
 */

const GENESIS = 'GENESIS';

/** Same canonical rule as lib/crypto/hash.ts: sorted keys, undefined dropped. */
function canonicalize(value: unknown): string {
  return JSON.stringify(normalize(value));
}
function normalize(value: unknown): unknown {
  if (value === null) return null;
  if (Array.isArray(value)) return value.map(normalize);
  if (typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      const v = (value as Record<string, unknown>)[key];
      if (v === undefined) continue;
      out[key] = normalize(v);
    }
    return out;
  }
  if (typeof value === 'number' && !Number.isFinite(value)) return String(value);
  return value;
}

function canonicalPayload(e: AuditEventRecord): string {
  return canonicalize({
    id: e.id,
    agreement_id: e.agreementId,
    actor_id: e.actorId,
    event_type: e.eventType,
    object_id: e.objectId,
    occurred_at: e.occurredAt,
    ip_hash: e.ipHash,
    metadata: e.metadata ?? {},
  });
}

async function sha256Hex(text: string): Promise<string> {
  const bytes = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

interface Finding {
  index: number;
  eventType: string;
  ok: boolean;
  linkOk: boolean;
  digestOk: boolean;
  expectedHash: string;
  actualHash: string;
  detail: string;
}

export function VerifyWorkbench({
  initial, options, demo,
}: {
  initial: { agreementRef: string; events: AuditEventRecord[] } | null;
  options: Array<{ id: string; ref: string; title: string }>;
  demo: Array<{ id: string; ref: string; title: string }>;
}) {
  const [text, setText] = useState(() => JSON.stringify(initial?.events ?? [], null, 2));
  const [findings, setFindings] = useState<Finding[] | null>(null);
  const [running, setRunning] = useState(false);
  const [parseError, setParseError] = useState<string | null>(null);
  const [agreementId, setAgreementId] = useState(initial ? options.find((o) => o.ref === initial.agreementRef)?.id ?? '' : '');

  const run = useCallback(async (raw: string) => {
    setRunning(true);
    setParseError(null);
    try {
      const parsed = JSON.parse(raw) as AuditEventRecord[];
      if (!Array.isArray(parsed)) throw new Error('Expected a JSON array of events.');

      const out: Finding[] = [];
      let previousHash: string | null = null;
      for (let i = 0; i < parsed.length; i += 1) {
        const e = parsed[i];
        const expectedLink = previousHash;
        const linkOk = (e.previousHash ?? null) === expectedLink;
        const actual = await sha256Hex(`${e.previousHash ?? GENESIS}\n${canonicalPayload(e)}`);
        const digestOk = actual === e.eventHash;
        out.push({
          index: i,
          eventType: e.eventType,
          ok: linkOk && digestOk,
          linkOk,
          digestOk,
          expectedHash: e.eventHash,
          actualHash: actual,
          detail: !linkOk
            ? `This event commits to “${e.previousHash ?? GENESIS}” but the previous event hashes to “${expectedLink ?? GENESIS}”. Everything from here on is unattested.`
            : !digestOk
              ? `The stored digest does not match the recomputed digest of this event's own fields. This event has been altered.`
              : 'Link verified: digest matches and the previous-hash pointer is correct.',
        });
        if (!(linkOk && digestOk)) break;
        previousHash = e.eventHash;
      }
      setFindings(out);
    } catch (err) {
      setFindings(null);
      setParseError(err instanceof Error ? err.message : 'Could not read that as JSON.');
    } finally {
      setRunning(false);
    }
  }, []);

  const load = useCallback(async (id: string) => {
    setAgreementId(id);
    if (!id) return;
    const res = await fetch(`/api/chain/${id}`);
    const body = await res.json();
    const next = JSON.stringify(body.events ?? [], null, 2);
    setText(next);
    await run(next);
  }, [run]);

  useEffect(() => {
    if (initial) void run(JSON.stringify(initial.events, null, 2));
  }, [initial, run]);

  const failing = findings?.find((f) => !f.ok) ?? null;
  const verifiedCount = useMemo(() => findings?.filter((f) => f.ok).length ?? 0, [findings]);

  return (
    <>
      <div className="split">
        <div>
          <div className="card">
            <div className="card-head">
              <div>
                <h3>Paste a package&rsquo;s events.json</h3>
                <div className="tiny" style={{ marginTop: 2 }}>
                  Or load one of your chains. The check runs in this browser tab only — no data is sent anywhere, and
                  there is nothing to trust us about.
                </div>
              </div>
            </div>

            <div className="btn-row" style={{ marginBottom: 10 }}>
              <select value={agreementId} onChange={(e) => void load(e.target.value)} style={{ maxWidth: 260 }}>
                <option value="">Load one of my chains…</option>
                {demo.map((d) => <option key={d.id} value={d.id}>{d.ref} — {d.title}</option>)}
              </select>
              <button className="btn sm" type="button" onClick={() => void run(text)} disabled={running}>
                {running ? 'Recomputing…' : 'Verify pasted JSON'}
              </button>
              <button
                className="btn sm danger"
                type="button"
                disabled={!text}
                onClick={() => {
                  // Deliberate tamper: flip a character in the first event's
                  // metadata. Use it to see precisely what an edit looks like.
                  const parsed = JSON.parse(text) as AuditEventRecord[];
                  if (parsed[0]) parsed[0].metadata = { ...parsed[0].metadata, tampered: 'one character changed' };
                  const next = JSON.stringify(parsed, null, 2);
                  setText(next);
                  void run(next);
                }}
              >
                Tamper with event 1
              </button>
              <button className="btn sm ghost" type="button" onClick={() => { setText('[]'); setFindings(null); setParseError(null); }}>
                Clear
              </button>
            </div>

            <textarea
              value={text}
              onChange={(e) => setText(e.target.value)}
              spellCheck={false}
              style={{ minHeight: 320, fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace', fontSize: 11.5, lineHeight: 1.5 }}
            />
            {parseError && <div className="callout danger" style={{ marginTop: 10 }}>Could not read that JSON: {parseError}</div>}
          </div>
        </div>

        <div>
          <div className="card">
            <div className="card-head">
              <div><h3>Result</h3></div>
            </div>

            {!findings && !running && (
              <p className="sub" style={{ margin: 0 }}>
                Nothing verified yet. Load a chain or paste an events array, then press verify. Individual links are shown
                one by one so you can see exactly where a break occurs.
              </p>
            )}

            {running && <p className="sub" style={{ margin: 0 }}>Recomputing every digest in your browser…</p>}

            {findings && (
              <>
                <div className={`callout ${failing ? 'danger' : 'ok'}`}>
                  {failing ? (
                    <>
                      <strong>Verification failed at entry {failing.index + 1}</strong> ({failing.eventType}).
                      {' '}{failing.detail}
                      <div style={{ marginTop: 6 }}>
                        This is what a tampered record looks like. Note that in a real package you would see the same
                        result using <span className="mono">verification.json</span> and three lines of any scripting language.
                      </div>
                    </>
                  ) : (
                    <>
                      <strong>Verified in this browser.</strong> {verifiedCount} of {findings.length} link(s) recompute
                      correctly and every pointer matches. No intermediate system was involved in producing this result.
                    </>
                  )}
                </div>

                <div className="section-title"><h3>Link by link</h3></div>
                <Table head={['#', 'Event', 'Digest', 'Pointer', 'Recomputed']}>
                  {findings.map((f) => (
                    <tr key={f.index}>
                      <td className="num">{f.index + 1}</td>
                      <td className="tiny mono">{f.eventType}</td>
                      <td className="tiny">{f.digestOk ? <Badge tone="ok">matches</Badge> : <Badge tone="danger">mismatch</Badge>}</td>
                      <td className="tiny">{f.linkOk ? <Badge tone="ok">correct</Badge> : <Badge tone="danger">broken</Badge>}</td>
                      <td className="tiny mono" style={{ maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                        {f.actualHash.slice(0, 22)}…
                      </td>
                    </tr>
                  ))}
                </Table>
                <p className="tiny">
                  {failing ? 'Verification stops at the first failure: links after a break prove nothing.' : 'All links verified.'}
                </p>
              </>
            )}
          </div>

          <div className="card tight">
            <h3>The published algorithm</h3>
            <pre className="code" style={{ marginTop: 8 }}>{`payload   = canonical_json({ id, agreement_id, actor_id,
              event_type, object_id, occurred_at,
              ip_hash, metadata })      # sorted keys
event_hash = sha256( previous_hash + "\\n" + payload )
             # previous_hash = "GENESIS" for the first event`}</pre>
            <p className="tiny" style={{ marginTop: 8 }}>
              Canonical JSON means keys sorted and insignificant formatting removed, so the same content always hashes to
              the same digest. Any implementation of this recipe, on any platform, produces the digests in your package —
              including a judge&rsquo;s expert reading it years from now.
            </p>
          </div>
        </div>
      </div>
    </>
  );
}
