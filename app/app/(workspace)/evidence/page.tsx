import Link from 'next/link';
import { redirect } from 'next/navigation';
import { getUserViewer } from '@/lib/auth/user-auth';
import { userStore } from '@/lib/data/user-store';
import { canPerform } from '@/lib/auth/user-access';
import { verifyChain } from '@/lib/audit/chain';
import { UserActionButton } from '@/components/user-action-form';
import {
  Badge, Callout, Card, Hash, KV, PageHead, StatusBadge, Table, when,
} from '@/components/ui';

export const dynamic = 'force-dynamic';

const FILE_GUIDE: Array<{ name: string; what: string }> = [
  { name: 'document.txt', what: 'The exact frozen version that was signed. Its SHA-256 must equal the digest in the manifest.' },
  { name: 'manifest.json', what: 'What the package contains, which agreement and version it covers, and the digests it asserts.' },
  { name: 'events.json', what: 'Every event in order, each carrying the hash of the event before it. This is the chain itself.' },
  { name: 'signatures.json', what: 'Who signed which version, when, with what method, and against which consent record.' },
  { name: 'verification.json', what: 'The result of our own checks at generation time, including any failing link. We ship our failures too.' },
  { name: 'certificate-data.json', what: 'Structured fields a stamp or certificate would draw on. Its declaration is explicitly pending legal review.' },
];

export default async function EvidencePage({
  searchParams,
}: {
  searchParams: Promise<{ agreement?: string }>;
}) {
  const viewer = await getUserViewer();
  if (!viewer) redirect('/app/login');

  const sp = await searchParams;
  const s = await userStore();
  const myAgreements = await s.listAgreementsForUser(viewer.userId, viewer.email);
  const packages = (await s.listPackages()).filter((p) => myAgreements.some((a) => a.id === p.agreementId));
  const selected = sp.agreement ? myAgreements.find((a) => a.id === sp.agreement) ?? null : null;

  const exportAllowed = selected
    ? canPerform(
        viewer.userId,
        {
          agreement: selected,
          parties: await s.listParties(selected.id),
          signatureEvents: await s.listSignatureEvents(selected.id),
          currentVersion: null,
          viewerEmail: viewer.email,
        },
        'export',
      )
    : null;

  return (
    <>
      <PageHead
        title="Evidence packages"
        lede="An evidence package is the record of an agreement in a form you can hand to someone else. It verifies with a plain script and the SHA-256 algorithm — no agre-e account, no network call, no trust in us required."
        actions={<Link className="btn sm ghost" href="/app/verify">Verify a chain</Link>}
      />

      {selected && exportAllowed && (
        <Card
          title={`Package: ${selected.title}`}
          subtitle={<span><span className="mono">{selected.ref}</span> · <StatusBadge status={selected.status} /></span>}
        >
          {exportAllowed.allowed ? (
            <>
              <div className="callout ok">
                <strong>Ready to export.</strong> The package is generated from the stored chain at the moment you ask for it,
                and the document digest is recomputed rather than copied from a field we could have edited. Generating twice
                produces the same files — packages are keyed to the chain root, not to a timestamp.
              </div>
              <div className="btn-row" style={{ marginTop: 12 }}>
                <a className="btn primary" href={`/api/evidence/${selected.id}`}>Download package (.zip)</a>
                <UserActionButton
                  label="Generate / re-check"
                  spec={{ action: 'generate_package', title: 'Generate the evidence package', hidden: { agreementId: selected.id }, confirmLabel: 'Generate' }}
                />
                <Link className="btn sm" href={`/app/verify?agreement=${selected.id}`}>Verify this chain</Link>
              </div>
            </>
          ) : (
            <Callout tone="warn"><strong>Not available.</strong> {exportAllowed.reason}</Callout>
          )}
        </Card>
      )}

      <div className="split" style={{ marginTop: 16 }}>
        <div>
          <Card title="Your packages" subtitle="One per completed agreement version whose chain has been stamped.">
            <Table head={['Agreement', 'Version', 'Chain root', 'Events', 'Generated', 'Self-check', '']} empty="No packages yet. A package is issued when an agreement completes.">
              {packages.map((p) => {
                const agreement = myAgreements.find((a) => a.id === p.agreementId);
                return (
                  <tr key={p.id}>
                    <td>
                      <div style={{ fontWeight: 560 }}>{agreement?.title ?? p.agreementId}</div>
                      <div className="tiny mono">{agreement?.ref ?? p.agreementId}</div>
                    </td>
                    <td className="num">v{p.versionId.slice(-2)}</td>
                    <td><Hash value={p.chainRoot} chars={20} /></td>
                    <td className="num">{p.eventCount}</td>
                    <td className="tiny nowrap">{when(p.createdAt)}</td>
                    <td>
                      {p.verification.ok
                        ? <Badge tone="ok">passed</Badge>
                        : <Badge tone="danger">failed — do not rely</Badge>}
                    </td>
                    <td className="nowrap">
                      <a className="btn sm" href={`/api/evidence/${p.agreementId}`}>Download</a>
                      <span style={{ marginLeft: 6 }}><Link className="btn sm ghost" href={`/app/verify?agreement=${p.agreementId}`}>Verify</Link></span>
                    </td>
                  </tr>
                );
              })}
            </Table>
          </Card>

          <Card title="What is inside a package" subtitle="Six files. Any of them can be checked with standard tools.">
            <Table head={['File', 'What it is for']}>
              {FILE_GUIDE.map((f) => (
                <tr key={f.name}>
                  <td className="tiny mono nowrap">{f.name}</td>
                  <td className="tiny">{f.what}</td>
                </tr>
              ))}
            </Table>
          </Card>

          <Card title="Check it yourself in three commands" subtitle="No agre-e software, no account, no network.">
            <pre className="code">{`# 1. Document digest — must match "document.sha256" in manifest.json
shasum -a 256 document.txt

# 2. The chain — every event must point at the hash of the one before it
cat events.json | python3 -m json.tool | less

# 3. Our own verdict, including failures, is in
cat verification.json`}</pre>
            <p className="tiny" style={{ marginTop: 8 }}>
              Or open <Link href="/app/verify">Verify a chain</Link> and paste the package contents: the check runs entirely
              in your browser and nothing is uploaded.
            </p>
          </Card>
        </div>

        <div>
          <Card title="Your export rights">
            <p className="sub" style={{ margin: 0 }}>
              You can export any completed agreement at any time, for as long as your account exists, and after it is closed
              by asking support. No plan tier gates this: an evidence package is generated for every completed agreement
              whether or not you are paying us anything.
            </p>
          </Card>

          <Card title="Completed agreements without a package">
            <Table head={['Agreement', 'Completed', '']} empty="None — every completed agreement has a package.">
              {myAgreements
                .filter((a) => a.status === 'completed' && !packages.some((p) => p.agreementId === a.id))
                .map((a) => (
                  <tr key={a.id}>
                    <td className="tiny">
                      <Link href={`/app/agreements/${a.id}`}>{a.title}</Link>
                      <div className="tiny mono">{a.ref}</div>
                    </td>
                    <td className="tiny nowrap">{when(a.completedAt)}</td>
                    <td className="nowrap">
                      <UserActionButton
                        label="Generate"
                        spec={{ action: 'generate_package', title: 'Generate the evidence package', hidden: { agreementId: a.id }, confirmLabel: 'Generate' }}
                      />
                    </td>
                  </tr>
                ))}
            </Table>
          </Card>

          <Card title="Verification is not an opinion" subtitle="What we state, and what we refuse to imply.">
            <KV
              rows={[
                ['We assert', 'this exact document, these signatures, this order, at these times — unaltered since they were written'],
                ['We can prove', 'the stored record recomputes and its links are unbroken'],
                ['We do not assert', 'identity beyond the recorded assurance level'],
                ['We do not assert', 'capacity, voluntariness or absence of duress'],
                ['We do not assert', 'legal validity or enforceability'],
              ]}
            />
            <Callout tone="warn">
              <strong>Integrity is not validity.</strong> A perfectly verified record of an unenforceable agreement is still
              an unenforceable agreement. Our stamp says the record has not changed; it does not say the deal is good.
            </Callout>
          </Card>

          <Card title="Keep your own copy" subtitle="The point of an export is that it survives us.">
            <p className="sub" style={{ margin: 0 }}>
              We recommend storing every completed package somewhere you control — your own drive, your advocate, a shared
              folder with the other party. If our service were unavailable tomorrow, your package would still verify, because
              the check needs only the files and a SHA-256 implementation.
            </p>
          </Card>
        </div>
      </div>
    </>
  );
}
