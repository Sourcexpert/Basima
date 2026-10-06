import { NextResponse } from 'next/server';
import { getUserViewer } from '@/lib/auth/user-auth';
import { store } from '@/lib/data/store';
import { canPerform } from '@/lib/auth/user-access';

/**
 * Read-only chain export for the browser verifier.
 *
 * The caller must already be able to see the agreement (party or owner). The
 * response contains only the event records and the published verification
 * inputs — no document bytes, and no data about anyone outside this agreement.
 */
export async function GET(_request: Request, context: { params: Promise<{ id: string }> }) {
  const viewer = await getUserViewer();
  if (!viewer) return NextResponse.json({ error: 'Sign in required.' }, { status: 401 });

  const { id } = await context.params;
  const s = store();
  const agreement = await s.getAgreementSummary(id);
  if (!agreement) return NextResponse.json({ error: 'Not found.' }, { status: 404 });

  const [parties, signatureEvents, documents] = await Promise.all([
    s.listParties(id),
    s.listSignatureEvents(id),
    s.listDocuments(id),
  ]);
  const decision = canPerform(
    viewer.userId,
    {
      agreement, parties, signatureEvents,
      currentVersion: documents.find((d) => d.versionNumber === agreement.currentVersion) ?? null,
      viewerEmail: viewer.email,
    },
    'view',
  );
  if (!decision.allowed) return NextResponse.json({ error: 'Not available to your account.' }, { status: 403 });

  const events = await s.listAuditEvents({ agreementId: id, limit: 1000 });

  return NextResponse.json(
    {
      agreement: { id: agreement.id, ref: agreement.ref, status: agreement.status, currentVersion: agreement.currentVersion },
      canonical_rule: 'sha256(previous_hash + "\\n" + canonical_json(event fields))',
      events,
    },
    { headers: { 'cache-control': 'no-store' } },
  );
}
