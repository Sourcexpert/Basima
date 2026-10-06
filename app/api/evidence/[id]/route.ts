import { NextResponse } from 'next/server';
import { getUserViewer, userRequestMeta } from '@/lib/auth/user-auth';
import { packageFiles } from '@/lib/services/agreements';
import { appendAgreementEvent } from '@/lib/data/store';
import { buildEvidenceZip } from '@/lib/evidence/zip';

export const dynamic = 'force-dynamic';

/**
 * Evidence package download.
 *
 * Order matters: authenticate -> authorise (party membership, agreement
 * completed) -> assemble the package -> log the export -> stream. The export
 * itself is an event: someone taking a copy of a record is part of its history.
 */
export async function GET(_request: Request, context: { params: Promise<{ id: string }> }) {
  const viewer = await getUserViewer();
  if (!viewer) {
    return NextResponse.json({ error: 'Sign in to download an evidence package.' }, { status: 401 });
  }

  const { id } = await context.params;
  const meta = await userRequestMeta();
  const result = await packageFiles(
    { viewer: { userId: viewer.userId, email: viewer.email, displayName: viewer.displayName }, ...meta },
    id,
  );

  if (!result.ok) {
    const status = /not found/i.test(result.error) ? 404 : 403;
    return NextResponse.json({ error: result.error }, { status });
  }

  const { bundle, agreement } = result;

  await appendAgreementEvent({
    agreementId: id,
    actorId: viewer.userId,
    eventType: 'evidence.package_exported',
    metadata: {
      format: bundle.manifest.format,
      package_version: bundle.manifest.version,
      files: bundle.files.map((f) => f.name),
      chain_root: bundle.chainRoot,
      verification_ok: bundle.verification.ok,
      note: 'Export recorded. The exported files do not change when they are downloaded again.',
    },
    ipHash: meta.ipHash,
    userAgent: meta.userAgent,
  });

  const zip = buildEvidenceZip(bundle.files.map((f) => ({ name: f.name, content: f.content })));
  const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
  const filename = `agree-e_${agreement.ref}_v${agreement.currentVersion}_${stamp}.zip`;

  return new NextResponse(new Uint8Array(zip), {
    status: 200,
    headers: {
      'content-type': 'application/zip',
      'content-disposition': `attachment; filename="${filename}"`,
      'cache-control': 'no-store, max-age=0',
      'x-agree-e-chain-root': bundle.chainRoot,
      'x-agree-e-verification': bundle.verification.ok ? 'passed' : 'failed',
    },
  });
}
