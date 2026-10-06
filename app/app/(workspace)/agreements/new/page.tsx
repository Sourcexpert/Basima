import Link from 'next/link';
import { redirect } from 'next/navigation';
import { getUserViewer } from '@/lib/auth/user-auth';
import { NewAgreementForm } from './new-form';
import { Callout, Card, PageHead } from '@/components/ui';

export const dynamic = 'force-dynamic';

export default async function NewAgreementPage() {
  const viewer = await getUserViewer();
  if (!viewer) redirect('/app/login');

  return (
    <>
      <PageHead
        title="Start an agreement"
        lede="Write or paste your agreement. We will store it as an immutable version, hash it, and record the digest before anyone signs anything — so the text can never be changed underneath a signature."
        actions={<Link className="btn sm ghost" href="/app/agreements">← My agreements</Link>}
      />

      <div className="split">
        <Card title="The document" subtitle="This text becomes version 1. Everything that follows refers back to it by hash.">
          <NewAgreementForm />
        </Card>

        <div>
          <Card tight title="What happens when you press create">
            <ol className="sub" style={{ margin: 0, paddingLeft: 18 }}>
              <li>The text is hashed with SHA-256 and stored as version 1. Immutable from that moment.</li>
              <li>An <span className="mono">agreement.created</span> event starts the evidence chain, followed by a version event.</li>
              <li>You invite the other parties, each with a role and a signing order.</li>
              <li>Each signer reviews the exact version, records consent, and signs.</li>
              <li>When every required signer has signed, the version freezes, a stamp is issued and an evidence package is generated.</li>
            </ol>
          </Card>

          <Card tight title="Before you start">
            <Callout tone="warn">
              <strong>This is not legal advice.</strong> We do not draft contracts, review terms or tell you whether an
              agreement is enforceable. If the stakes are significant, have an advocate look at the text before you send
              it. Our job is to make sure the record of what you agreed cannot be quietly rewritten.
            </Callout>
            <div className="callout" style={{ marginTop: 10 }}>
              <strong>Avoid putting unnecessary personal data in the text.</strong> Identity numbers, bank details and
              medical information do not belong in a document that will be shared with counterparties. Keep those out of
              the agreement and the record stays cleaner for everyone, including you.
            </div>
          </Card>

          <Card tight title="Working drafts stay yours">
            <p className="sub" style={{ margin: 0 }}>
              Until you invite the first party, a draft is visible only to you. You can create several versions while
              preparing it; nobody outside your account sees any of them.
            </p>
          </Card>
        </div>
      </div>
    </>
  );
}
