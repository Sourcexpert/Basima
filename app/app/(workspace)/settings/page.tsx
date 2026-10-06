import { redirect } from 'next/navigation';
import Link from 'next/link';
import { getUserViewer } from '@/lib/auth/user-auth';
import { userStore } from '@/lib/data/user-store';
import { CURRENT_DISCLOSURE } from '@/lib/data/user-demo-db';
import { UserActionButton } from '@/components/user-action-form';
import { Badge, Callout, Card, KV, PageHead, StatusBadge, Table, day, when } from '@/components/ui';

export const dynamic = 'force-dynamic';

const REQUEST_TYPES = [
  { value: 'access', label: 'Access — show me what you hold about me' },
  { value: 'correction', label: 'Correction — something about me is inaccurate' },
  { value: 'deletion', label: 'Deletion — delete what you can' },
  { value: 'restriction', label: 'Restriction — stop processing while a question is resolved' },
  { value: 'portability', label: 'Portability — give me a machine-readable export' },
];

export default async function SettingsPage() {
  const viewer = await getUserViewer();
  if (!viewer) redirect('/app/login');

  const s = await userStore();
  const [profile, requests, consents, agreements, packages] = await Promise.all([
    s.getUser(viewer.userId),
    s.listDataRequests(viewer.userId),
    s.listConsents(),
    s.listAgreementsForUser(viewer.userId),
    s.listPackages(),
  ]);
  const myConsents = consents.filter((c) => c.userId === viewer.userId);
  const myPackages = packages.filter((p) => agreements.some((a) => a.id === p.agreementId));

  return (
    <>
      <PageHead
        title="Settings and privacy"
        lede="Your account, what we hold about you, and the rights you can exercise here without emailing anyone and waiting."
      />

      <div className="split">
        <div>
          <Card title="Sign-in and security">
            <KV
              rows={[
                ['Name', viewer.displayName],
                ['Email', <span className="mono" key="e">{viewer.email}</span>],
                ['Email verified', profile?.emailVerified ? <Badge key="v" tone="ok">verified</Badge> : <Badge key="v" tone="warn">not verified</Badge>],
                ['Multi-factor authentication', viewer.mfaEnabled ? <Badge key="m" tone="ok">enabled</Badge> : <Badge key="m" tone="warn">not enabled</Badge>],
                ['Account status', <StatusBadge key="s" status={profile?.status ?? 'active'} />],
                ['Password last changed', profile?.passwordChangedAt ? when(profile.passwordChangedAt) : 'no record'],
                ['Account created', profile?.createdAt ? day(profile.createdAt) : '—'],
              ]}
            />

            <div className="btn-row" style={{ marginTop: 14 }}>
              <UserActionButton
                label="Change password"
                variant="primary"
                spec={{
                  action: 'change_password',
                  title: 'Change your password',
                  intro: <>You need your current password. Changing it signs out every other session on your account — if someone else has your old password, this ends their access.</>,
                  fields: [
                    { name: 'currentPassword', label: 'Current password', type: 'text', required: true },
                    { name: 'newPassword', label: 'New password', type: 'text', required: true, help: 'At least 12 characters, mixing upper case, lower case and numbers. Length matters more than symbols.' },
                    { name: 'confirmPassword', label: 'Repeat new password', type: 'text', required: true },
                  ],
                  confirmLabel: 'Change password',
                  disclaimer: <div className="callout warn"><strong>We cannot see your password.</strong> Nobody at agre-e can read, set or recover it. If you lose it, the only route back in is a reset link sent to your email address.</div>,
                }}
              />
              {!viewer.mfaEnabled && (
                <UserActionButton
                  label="Enable MFA"
                  spec={{
                    action: 'noop_mfa_placeholder' as string,
                    title: 'Multi-factor authentication',
                    intro: <>MFA is managed in this demo by the operator console, and in production by your account&rsquo;s authenticator enrolment. This button is intentionally inert here rather than pretending to enrol a second factor.</>,
                    confirmLabel: 'Close',
                  }}
                  disabled
                  disabledReason="Handled by your account's authenticator enrolment; not available in the demo dataset."
                />
              )}
            </div>

            <Callout tone="accent">
              <strong>Why changes sign you out everywhere.</strong> If an attacker has a live session, a password change
              that leaves that session working has protected nothing. New sign-ins are only possible with the new password.
            </Callout>

            <div className="tiny" style={{ marginTop: 10 }}>
              Lost the password rather than changing it? Ask support for a recovery link, then open{' '}
              <Link href="/reset-password" style={{ color: 'var(--accent)' }}>/reset-password</Link>. The link is
              single-use, expires in an hour, and only its one-way digest is stored — whoever issues it cannot read it
              back or use it for you.
            </div>
          </Card>

          <Card title="Your data rights" subtitle="File a request here and it is logged and answered by a person. Nothing is auto-rejected.">
            <div className="btn-row" style={{ marginBottom: 12 }}>
              <UserActionButton
                label="Submit a data request"
                variant="primary"
                spec={{
                  action: 'data_request',
                  title: 'Submit a data-protection request',
                  intro: <>Under the Data Protection Act you can ask us to show you, correct, restrict or delete your personal data, or give it to you in a portable form. We answer in writing within 30 days.</>,
                  fields: [
                    { name: 'type', label: 'What are you asking for?', type: 'select', required: true, options: REQUEST_TYPES },
                    { name: 'detail', label: 'Detail', type: 'textarea', required: true, placeholder: 'Tell us specifically what you are asking about, so the request is not bounced back for clarification.' },
                  ],
                  confirmLabel: 'Submit request',
                  disclaimer: <div className="callout"><strong>One honest caveat.</strong> A deletion request cannot remove an executed agreement, its stamp or its audit events — those are the legal record of something that happened, and erasing them would destroy evidence both sides may need. We can and will delete what is not part of that record, and we will tell you plainly what was deleted and what was kept.</div>,
                }}
              />
            </div>

            <Table head={['Reference', 'Type', 'Submitted', 'Response due', 'State']} empty="You have not submitted any data requests.">
              {[...requests].reverse().map((r) => (
                <tr key={r.id}>
                  <td className="tiny mono">{r.id.slice(-10)}</td>
                  <td className="tiny">{r.type}</td>
                  <td className="tiny nowrap">{day(r.submittedAt)}</td>
                  <td className="tiny nowrap">{day(r.dueAt)}</td>
                  <td className="tiny">
                    <StatusBadge status={r.status === 'in_review' ? 'pending' : r.status} />
                    {r.resolutionNote && <div className="tiny">{r.resolutionNote}</div>}
                  </td>
                </tr>
              ))}
            </Table>
          </Card>

          <Card title="Consent you have given" subtitle="Recorded per act, not bundled into a single acceptance at sign-up.">
            <Table head={['When', 'Scope', 'Disclosure version', 'Agreement']} empty="No consent records yet.">
              {myConsents.map((c) => (
                <tr key={c.id}>
                  <td className="tiny nowrap">{when(c.acceptedAt)}</td>
                  <td className="tiny">{c.scope.replace(/_/g, ' ')}</td>
                  <td className="tiny mono">{c.disclosureVersion}</td>
                  <td className="tiny">
                    <Link href={`/app/agreements/${c.agreementId}`}>
                      {agreements.find((a) => a.id === c.agreementId)?.ref ?? c.agreementId}
                    </Link>
                  </td>
                </tr>
              ))}
            </Table>
            <div className="tiny" style={{ marginTop: 8 }}>
              Current disclosure version: <span className="mono">{CURRENT_DISCLOSURE}</span>. Each signature records the
              version its signer actually saw, so a later change to the wording cannot rewrite what someone agreed to.
            </div>
          </Card>
        </div>

        <div>
          <Card title="What we hold about you">
            <Table head={['Data', 'Kept?', 'Why']}>
              <tr>
                <td className="tiny">Name, email, organisation</td>
                <td className="tiny"><Badge tone="ok">yes</Badge></td>
                <td className="tiny">To identify you as a party and to reach you about your records.</td>
              </tr>
              <tr>
                <td className="tiny">Agreements you are party to</td>
                <td className="tiny"><Badge tone="ok">yes</Badge></td>
                <td className="tiny">The record itself — that is the product.</td>
              </tr>
              <tr>
                <td className="tiny">Signature and consent events</td>
                <td className="tiny"><Badge tone="ok">yes</Badge></td>
                <td className="tiny">Who signed which version, when, and what they were told first.</td>
              </tr>
              <tr>
                <td className="tiny">A keyed digest of your IP on each event</td>
                <td className="tiny"><Badge tone="info">hashed</Badge></td>
                <td className="tiny">Lets someone technical correlate sessions without us storing your address.</td>
              </tr>
              <tr>
                <td className="tiny">Your raw IP address</td>
                <td className="tiny"><Badge tone="ok">no</Badge></td>
                <td className="tiny">Not stored on the evidence record, ever.</td>
              </tr>
              <tr>
                <td className="tiny">A copy of your ID document</td>
                <td className="tiny"><Badge tone="ok">no</Badge></td>
                <td className="tiny">We keep only the level and date of the check, never the document.</td>
              </tr>
              <tr>
                <td className="tiny">Your password</td>
                <td className="tiny"><Badge tone="ok">never visible</Badge></td>
                <td className="tiny">Held as a one-way hash by the authentication service; not readable by any person here.</td>
              </tr>
            </Table>
          </Card>

          <Card title="Your records at a glance">
            <KV
              rows={[
                ['Agreements', `${agreements.length} (${agreements.filter((a) => a.status === 'completed').length} completed)`],
                ['Evidence packages', String(myPackages.length)],
                ['Consent records', String(myConsents.length)],
                ['Data requests open', String(requests.filter((r) => r.status === 'received' || r.status === 'in_review').length)],
                ['Export available', <Link key="x" href="/app/evidence" style={{ color: 'var(--accent)' }}>any completed agreement</Link>],
              ]}
            />
          </Card>

          <Card title="Who can see your agreements">
            <ul className="sub" style={{ margin: 0, paddingLeft: 18 }}>
              <li><strong>You,</strong> always.</li>
              <li><strong>The other parties on that agreement</strong> — they can see the document and who has signed, because they are on it.</li>
              <li><strong>Nobody else.</strong> Our support and billing staff cannot read your agreement content. They can see that a record exists, its status, and whether its chain verifies — nothing more. That is why support will ask you to read something out loud rather than quoting it back to you.</li>
              <li><strong>Nobody at all, ever,</strong> can edit or delete an event that is already on the chain — including us.</li>
            </ul>
            <Callout tone="info">
              <strong>If someone claiming to be us asks for your agreement text,</strong> treat it as a phishing attempt and
              report it. We do not need it, because we are not permitted to read it.
            </Callout>
          </Card>

          <Card title="Closing your account" subtitle="What happens to the record when you leave.">
            <p className="sub" style={{ margin: 0 }}>
              You can ask us to close your account at any time. Completed agreements, their signatures and their evidence
              packages are retained as legal records for the retention period, and any counterparty on them keeps access to
              their own copy. Drafts that were never sent to anyone are deleted. We will tell you which is which before
              anything is removed.
            </p>
            <div className="callout warn" style={{ marginTop: 10 }}>
              Export first. Download the evidence packages you care about before you close an account, so a dispute in
              three years&rsquo; time does not depend on us still being here to hand them to you.
            </div>
          </Card>
        </div>
      </div>
    </>
  );
}
