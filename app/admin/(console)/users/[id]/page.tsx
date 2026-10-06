import Link from 'next/link';
import { notFound, redirect } from 'next/navigation';
import { getViewer } from '@/lib/auth/session';
import { can, roleLabel } from '@/lib/auth/rbac';
import { store } from '@/lib/data/store';
import { ActionButton } from '@/components/action-form';
import {
  Badge, Callout, Card, Hash, Initials, KV, PageHead, StatusBadge, Table, money, relative, when,
} from '@/components/ui';

export const dynamic = 'force-dynamic';

const DEMO_NOW = new Date('2026-10-05T09:20:00.000Z').getTime();
const ROLES = ['owner', 'admin', 'support', 'security', 'billing', 'counsel'] as const;

export default async function UserDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const viewer = await getViewer();
  if (!viewer) redirect('/admin/login');
  if (!can(viewer.role, 'users.read')) redirect('/admin');

  const { id } = await params;
  const s = store();
  const user = await s.getUser(id);
  if (!user) notFound();

  const [sessions, subs, payments, allActions, staff, recoveries] = await Promise.all([
    s.listSessions(user.id),
    s.listSubscriptions({ limit: 1000 }),
    s.listPayments({ limit: 1000 }),
    s.listAdminActions({ limit: 500 }),
    s.listUsers({ limit: 500 }),
    s.listPasswordRecoveries(user.id),
  ]);

  const sub = subs.find((x) => x.userId === user.id) ?? null;
  const userPayments = payments.filter((p) => p.userId === user.id).slice(0, 8);
  const history = allActions.filter((a) => a.targetId === user.id || a.targetLabel.includes(user.email));
  const supervisors = staff.filter((u) => ['owner', 'admin', 'security'].includes(u.role) && u.id !== viewer.userId && u.status === 'active');

  const isPrivileged = ['owner', 'admin', 'support', 'security', 'billing'].includes(user.role);
  const noCap = (c: Parameters<typeof can>[1]) => !can(viewer.role, c);

  return (
    <>
      <PageHead
        title={user.displayName}
        lede={
          <span>
            <span className="mono">{user.email}</span> · {user.organisation ?? 'no organisation'} · {user.country} ·{' '}
            joined {when(user.createdAt)} ({relative(user.createdAt, DEMO_NOW)})
          </span>
        }
        actions={<Link className="btn sm ghost" href="/admin/users">← All users</Link>}
      />

      <div style={{ display: 'flex', gap: 7, flexWrap: 'wrap', marginBottom: 16 }}>
        <span className="chip">{roleLabel(user.role)}</span>
        <StatusBadge status={user.status} />
        {user.emailVerified ? <Badge tone="ok">email verified</Badge> : <Badge tone="warn">email unverified</Badge>}
        {user.mfaEnabled ? <Badge tone="ok">MFA enrolled</Badge> : user.mfaRequired ? <Badge tone="danger">MFA required, not enrolled</Badge> : <Badge tone="neutral">MFA off</Badge>}
        {user.forcePasswordReset && <Badge tone="warn">reset required at next sign-in</Badge>}
        {user.tempCredentialExpiresAt && (
          <Badge tone="danger">
            break-glass credential active{new Date(user.tempCredentialExpiresAt).getTime() < DEMO_NOW ? ' (expired)' : ` · expires ${relative(user.tempCredentialExpiresAt, DEMO_NOW)}`}
          </Badge>
        )}
        {user.failedSignInCount > 0 && <Badge tone="danger">{user.failedSignInCount} failed sign-ins</Badge>}
      </div>

      <div className="split">
        <div>
          <Card
            title="Credential & access controls"
            subtitle="Every control below writes to the append-only admin ledger with your identity, the target, your justification and a chained hash."
          >
            <Table head={['Control', 'What it does', 'Requires', '']}>
              <tr>
                <td className="nowrap"><strong>Send recovery link</strong></td>
                <td className="tiny">
                  Issues a single-use, expiring Supabase recovery link. <em>Email</em> mode sends it to the user.
                  <em> Copy</em> mode shows it once to you for a support call — it is never stored by the console.
                </td>
                <td className="tiny nowrap">justification</td>
                <td className="nowrap">
                  {noCap('password.reset_link') ? <span className="tiny">not in your role</span> : (
                    <ActionButton
                      label="Send link"
                      spec={{
                        action: 'reset_link',
                        title: `Send recovery link to ${user.displayName}`,
                        intro: <>The link is single-use and expires upstream. The user is not notified that an operator initiated it beyond the normal recovery email — say so on the call.</>,
                        hidden: { userId: user.id },
                        fields: [
                          {
                            name: 'delivery', label: 'Delivery', type: 'select', defaultValue: 'email',
                            options: [
                              { value: 'email', label: 'Email the link to the user' },
                              { value: 'copy', label: 'Show a one-time link to me (support call)' },
                            ],
                            help: expressionHint('copy'),
                          },
                        ],
                        reasonPlaceholder: 'e.g. Customer called support after losing their device; identity confirmed by callback on the registered number.',
                        confirmLabel: 'Issue link',
                        intent: 'primary',
                      }}
                    />
                  )}
                </td>
              </tr>
              <tr>
                <td className="nowrap"><strong>Force reset at next sign-in</strong></td>
                <td className="tiny">
                  Flags the account so a new password must be set before anything else. Optionally revokes sessions and
                  requires MFA. The user&rsquo;s current password keeps working until they change it — this does not lock them out mid-task.
                </td>
                <td className="tiny nowrap">justification</td>
                <td className="nowrap">
                  {noCap('password.force_reset') ? <span className="tiny">not in your role</span> : (
                    <ActionButton
                      label="Force reset"
                      spec={{
                        action: 'force_reset',
                        title: `Require a password reset for ${user.displayName}`,
                        intro: <>Use when a credential is suspected compromised. Sessions are revoked by default so the change takes effect immediately.</>,
                        hidden: { userId: user.id },
                        fields: [
                          { name: 'revokeSessions', label: 'Revoke all sessions now', type: 'checkbox', defaultValue: true, help: 'Access tokens stay valid until they expire (≤1 hour); revocation stops renewal.' },
                          { name: 'requireMfa', label: 'Also require MFA enrolment', type: 'checkbox', defaultValue: !user.mfaEnabled },
                        ],
                        reasonPlaceholder: 'e.g. Credential-stuffing attempt detected against this account; owner confirmed by phone.',
                        confirmLabel: 'Require reset',
                      }}
                    />
                  )}
                </td>
              </tr>
              <tr>
                <td className="nowrap"><strong>Revoke sessions</strong></td>
                <td className="tiny">
                  Terminates the user&rsquo;s refresh tokens on every device. Honest caveat shown to you on success:
                  already-issued access tokens remain valid until they expire.
                </td>
                <td className="tiny nowrap">step-up + justification</td>
                <td className="nowrap">
                  {noCap('sessions.revoke') ? <span className="tiny">not in your role</span> : (
                    <ActionButton
                      label="Revoke"
                      spec={{
                        action: 'revoke_sessions',
                        title: `Revoke sessions for ${user.displayName}`,
                        intro: <>Use when a device is lost, sold or shared. Pair with a forced reset if you suspect the credential itself is known to someone else.</>,
                        hidden: { userId: user.id },
                        stepUpHint: true,
                        fields: [{
                          name: 'scope', label: 'Scope', type: 'select', defaultValue: 'global',
                          options: [
                            { value: 'global', label: 'All devices (global)' },
                            { value: 'others', label: 'All devices except the current one' },
                          ],
                        }],
                        reasonPlaceholder: 'e.g. Laptop stolen; owner asked for an immediate sign-out everywhere.',
                        confirmLabel: 'Revoke sessions',
                      }}
                    />
                  )}
                </td>
              </tr>
              <tr>
                <td className="nowrap"><strong>Require MFA</strong></td>
                <td className="tiny">
                  Policy-bound for owner, admin, support, security and billing roles. {isPrivileged ? 'This account is privileged, so MFA should not be optional.' : 'For counsel accounts this is a client-agreed control, not a blanket rule.'}
                </td>
                <td className="tiny nowrap">justification</td>
                <td className="nowrap">
                  {noCap('mfa.manage') ? <span className="tiny">not in your role</span> : (
                    <ActionButton
                      label={user.mfaRequired ? 'Remove requirement' : 'Require MFA'}
                      spec={{
                        action: 'mfa',
                        title: user.mfaRequired ? `Remove the MFA requirement for ${user.displayName}` : `Require MFA for ${user.displayName}`,
                        hidden: { userId: user.id, required: String(!user.mfaRequired) },
                        reasonPlaceholder: 'e.g. Security baseline review: privileged console role must satisfy MFA per §17.',
                        confirmLabel: user.mfaRequired ? 'Remove requirement' : 'Require MFA',
                        intent: user.mfaRequired ? 'danger' : 'primary',
                      }}
                    />
                  )}
                </td>
              </tr>
              <tr>
                <td className="nowrap"><strong>Lock / unlock</strong></td>
                <td className="tiny">Immediate, reversible lock. Locks record the reason and revoke sessions; unlocking clears the failed-attempt counter. A deliberate suspension is separate and needs a higher capability.</td>
                <td className="tiny nowrap">justification</td>
                <td className="nowrap">
                  {noCap('users.suspend') && user.status !== 'locked' ? <span className="tiny">not in your role</span> : (
                    <ActionButton
                      label={user.status === 'locked' ? 'Unlock' : 'Lock'}
                      spec={{
                        action: 'lock',
                        title: user.status === 'locked' ? `Unlock ${user.displayName}` : `Lock ${user.displayName}`,
                        hidden: { userId: user.id, mode: user.status === 'locked' ? 'unlock' : 'lock' },
                        reasonPlaceholder: user.status === 'locked'
                          ? 'e.g. Owner verified identity by video call; unlock and require a fresh reset.'
                          : 'e.g. Automated lock after repeated failures; holding the account while we confirm with the owner.',
                        confirmLabel: user.status === 'locked' ? 'Unlock account' : 'Lock account',
                        intent: user.status === 'locked' ? 'default' : 'danger',
                      }}
                    />
                  )}
                </td>
              </tr>
            </Table>

            <div className="callout danger" style={{ marginTop: 14 }}>
              <strong>What this console will never do.</strong> It cannot display, set, or reveal another person&rsquo;s
              password — not in any role, not with any approval. An evidence product cannot let an operator assume a
              user&rsquo;s identity, because every signature on an agreement would then be arguable. Recovery is the only
              path: link, forced reset, or the supervisor-approved break-glass credential below.
            </div>
          </Card>

          <Card
            title="Break-glass credential"
            subtitle="Time-boxed, single-use, second-person approval, requires acknowledgement"
          >
            <div className="grid cols-3" style={{ marginBottom: 12 }}>
              <div className="card tight"><div className="stat-label">Step-up window</div><div className="stat-value" style={{ fontSize: 18 }}>15 min</div></div>
              <div className="card tight"><div className="stat-label">Max credential life</div><div className="stat-value" style={{ fontSize: 18 }}>120 min</div></div>
              <div className="card tight"><div className="stat-label">Approval</div><div className="stat-value" style={{ fontSize: 18 }}>2nd person</div></div>
            </div>
            <p className="sub" style={{ marginTop: 0 }}>
              Use only when a user cannot complete recovery themselves and a live signing or court deadline is at
              risk. The credential is generated server-side, shown to you exactly once, never stored or logged,
              expires at the TTL, forces a change at first sign-in, and revokes existing sessions. The supervisor is
              recorded by name next to your own.
            </p>
            <ActionButton
              label="Issue break-glass credential"
              size="md"
              disabled={noCap('password.temp_issue') || supervisors.length === 0}
              disabledReason={noCap('password.temp_issue') ? 'Your role does not hold password.temp_issue.' : 'No eligible supervisor is available.'}
              spec={{
                action: 'break_glass',
                title: `Break-glass credential for ${user.displayName}`,
                intro: <>This temporarily restores sign-in access. It does not bypass any agreement, consent or signing requirement.</>,
                hidden: { userId: user.id },
                stepUpHint: true,
                fields: [
                  {
                    name: 'supervisorEmail', label: 'Approving supervisor', type: 'select', required: true,
                    options: supervisors.map((sup) => ({ value: sup.email, label: `${sup.displayName} (${sup.role})` })),
                    help: 'Must be a different person from you. The supervisor is recorded in the ledger alongside your identity.',
                  },
                  {
                    name: 'ttlMinutes', label: 'Credential lifetime (minutes)', type: 'number', required: true,
                    defaultValue: 30, min: 5, max: 120, help: 'Keep it as short as the situation allows.',
                  },
                ],
                reasonPlaceholder: 'e.g. Signer locked out during a live completion with a court filing deadline today; supervisor approved after video identity check.',
                acknowledgement: 'I understand this issues a credential that lets a person sign in as this user, that the user must change it immediately, and that the issuance is permanently attributed to me and my supervisor.',
                confirmLabel: 'Issue credential',
                intent: 'danger',
              }}
            />
          </Card>

          <Card title="Role & account state" subtitle="Least privilege is enforced per action — a role change here immediately changes what the account can reach.">
            <Table head={['Decision', 'Current', 'Control', 'Requires']}>
              <tr>
                <td className="nowrap">Console role</td>
                <td><span className="chip">{roleLabel(user.role)}</span></td>
                <td className="nowrap">
                  {noCap('users.role_change') ? <span className="tiny">not in your role</span> : (
                    <ActionButton
                      label="Change role"
                      spec={{
                        action: 'role',
                        title: `Change role for ${user.displayName}`,
                        intro: <>Capabilities are granted per role: support cannot move money; billing cannot touch credentials; only security may read agreement content, and only through the privileged-access workflow. An owner role can only be granted by another owner.</>,
                        hidden: { userId: user.id },
                        stepUpHint: true,
                        fields: [{
                          name: 'role', label: 'New role', type: 'select', required: true, defaultValue: user.role,
                          options: ROLES.map((r) => ({ value: r, label: roleLabel(r) })),
                        }],
                        reasonPlaceholder: 'e.g. Promotion to Billing: Esther now owns reconciliation and refunds.',
                        confirmLabel: 'Apply role change',
                        intent: 'danger',
                      }}
                    />
                  )}
                </td>
                <td className="tiny nowrap">step-up + justification</td>
              </tr>
              <tr>
                <td className="nowrap">Account state</td>
                <td><StatusBadge status={user.status} /></td>
                <td className="nowrap">
                  {noCap('users.suspend') ? <span className="tiny">not in your role</span> : (
                    <ActionButton
                      label={user.status === 'suspended' ? 'Reinstate' : 'Suspend'}
                      spec={{
                        action: 'suspend',
                        title: user.status === 'suspended' ? `Reinstate ${user.displayName}` : `Suspend ${user.displayName}`,
                        intro: user.status === 'suspended'
                          ? <>Restores sign-in access. Any arrears position is unchanged — commercial state and evidentiary state are separate.</>
                          : <>Suspension blocks sign-in and revokes sessions. It never deletes or alters agreements, stamps, evidence packages or audit events; those stay exportable for the retention period.</>,
                        hidden: { userId: user.id, suspend: String(user.status !== 'suspended') },
                        stepUpHint: true,
                        reasonPlaceholder: 'e.g. Chargeback risk review after three failed cycles; notified customer before applying.',
                        confirmLabel: user.status === 'suspended' ? 'Reinstate account' : 'Suspend account',
                        intent: 'danger',
                      }}
                    />
                  )}
                </td>
                <td className="tiny nowrap">step-up + justification</td>
              </tr>
            </Table>
          </Card>
        </div>

        <div>
          <Card title="Account facts">
            <KV
              rows={[
                ['Account ID', <span className="mono tiny" key="i">{user.id}</span>],
                ['Created', when(user.createdAt)],
                ['Last sign-in', user.lastSignInAt ? `${when(user.lastSignInAt)}` : 'never'],
                ['Password changed', user.passwordChangedAt ? relative(user.passwordChangedAt, DEMO_NOW) : 'never'],
                ['Failed sign-ins', String(user.failedSignInCount)],
                ['Locked until', user.lockedUntil ? when(user.lockedUntil) : '—'],
                ['Agreements owned', String(user.agreementsOwned)],
                ['Extra capabilities', user.extraCapabilities.length ? user.extraCapabilities.join(', ') : 'none'],
              ]}
            />
          </Card>

          <Card title={`Sessions (${sessions.length})`} subtitle="Refresh tokens tracked server-side; IP addresses are stored only as keyed digests.">
            {sessions.length === 0 ? (
              <p className="sub" style={{ margin: 0 }}>No active sessions. Revocation is not the same as sign-out; the user simply has nothing to sign out.</p>
            ) : (
              <Table head={['Device', 'IP digest', 'Last seen', 'Expires']}>
                {sessions.map((sess) => (
                  <tr key={sess.id}>
                    <td className="tiny">
                      {sess.userAgent}
                      <div className="tiny">{sess.mfaSatisfied ? 'MFA satisfied' : 'no MFA at sign-in'}</div>
                    </td>
                    <td><Hash value={sess.ipHash} chars={10} /></td>
                    <td className="tiny nowrap">{relative(sess.lastSeenAt, DEMO_NOW)}</td>
                    <td className="tiny nowrap">{when(sess.expiresAt)}</td>
                  </tr>
                ))}
              </Table>
            )}
          </Card>

          <Card
            title={`Credential recovery (${recoveries.length})`}
            subtitle="Every recovery link issued for this account. The link itself is not stored — only a digest of it — so this is a record of what was issued, not a way to reissue it."
          >
            {recoveries.length === 0 ? (
              <p className="sub" style={{ margin: 0 }}>
                No recovery links have been issued for this account. Use <em>Send reset link</em> above if the account
                holder cannot sign in.
              </p>
            ) : (
              <Table head={['Issued', 'Delivery', 'Expires', 'State']}>
                {recoveries.slice(0, 5).map((r) => {
                  const state = r.consumedAt
                    ? { label: 'spent', tone: 'ok' as const }
                    : new Date(r.expiresAt).getTime() <= DEMO_NOW
                      ? { label: 'expired', tone: 'info' as const }
                      : { label: 'outstanding', tone: 'warn' as const };
                  return (
                    <tr key={r.id}>
                      <td className="tiny nowrap">{relative(r.issuedAt, DEMO_NOW)}</td>
                      <td className="tiny">{r.delivery === 'email' ? 'emailed to the holder' : 'read out on a call'}</td>
                      <td className="tiny nowrap">{when(r.expiresAt)}</td>
                      <td className="tiny"><Badge tone={state.tone}>{state.label}</Badge></td>
                    </tr>
                  );
                })}
              </Table>
            )}
            <div className="tiny" style={{ marginTop: 8 }}>
              An outstanding link is not a risk you can see or revoke from here — it dies on its own within the hour, and
              completing any reset closes every other outstanding link at once.
            </div>
          </Card>

          <Card title="Subscription">
            {sub ? (
              <>
                <KV
                  rows={[
                    ['Plan', `${sub.planName} (${sub.planCode})`],
                    ['Status', <StatusBadge key="s" status={sub.status} />],
                    ['Amount', money(sub.amountMinor, sub.currency)],
                    ['Renews / ends', when(sub.currentPeriodEnd)],
                    ['Rail', sub.provider === 'mpesa' ? 'M-PESA (Daraja)' : 'Flutterwave'],
                    ['Dunning attempts', String(sub.dunningAttempts)],
                  ]}
                />
                <div style={{ marginTop: 10 }}>
                  <Link className="btn sm" href={`/admin/billing?q=${encodeURIComponent(user.email)}`}>Open in billing</Link>
                </div>
              </>
            ) : (
              <p className="sub" style={{ margin: 0 }}>
                No subscription. The account can still hold and export evidence produced under a previous plan —
                downgrading never withdraws access to records already stamped.
              </p>
            )}
          </Card>

          <Card title="Recent payments">
            {userPayments.length === 0 ? <p className="sub" style={{ margin: 0 }}>No payment records.</p> : (
              <Table head={['Reference', 'Rail', 'Amount', 'Status']}>
                {userPayments.map((p) => (
                  <tr key={p.id}>
                    <td className="tiny">
                      <div className="mono">{p.reference}</div>
                      <div className="tiny">{p.mpesaReceipt ?? p.providerRef ?? '—'}</div>
                    </td>
                    <td className="tiny nowrap">{p.provider === 'mpesa' ? 'M-PESA' : 'Flutterwave'}<div className="tiny">{p.method.replace(/_/g, ' ')}</div></td>
                    <td className="nowrap tiny">{money(p.amountMinor, p.currency)}</td>
                    <td><StatusBadge status={p.status} />{p.failureReason && <div className="tiny" style={{ marginTop: 3 }}>{p.failureReason}</div>}</td>
                  </tr>
                ))}
              </Table>
            )}
          </Card>

          <Card title={`Operations history (${history.length})`} subtitle="What operators have done to this account, and why.">
            {history.length === 0 ? (
              <p className="sub" style={{ margin: 0 }}>No privileged actions recorded against this account.</p>
            ) : (
              <div className="timeline">
                {history.map((a) => (
                  <div className={`timeline-item${a.status === 'succeeded' ? ' good' : ' bad'}`} key={a.id}>
                    <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
                      <strong>{a.action.replace(/_/g, ' ')}</strong>
                      <Badge tone={a.status === 'succeeded' ? 'ok' : 'danger'}>{a.status}</Badge>
                    </div>
                    <div className="sub" style={{ marginTop: 3 }}>{a.reason}</div>
                    <div className="tiny" style={{ marginTop: 3 }}>
                      {a.adminEmail} ({a.adminRole}) · {when(a.occurredAt)}
                      {a.stepUp ? ' · step-up verified' : ''}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </Card>
        </div>
      </div>

      <div style={{ marginTop: 18 }}>
        <Callout tone="accent">
          <strong>Privacy note.</strong> The console renders no agreement text, no identity document and no raw IP
          address for this account. Support operates on state and metadata; only a security-role operator may open the
          privileged-access workflow, and that access is recorded against the agreement&rsquo;s own evidence trail as well
          as the admin ledger.
        </Callout>
      </div>
    </>
  );
}

function expressionHint(mode: string) {
  if (mode !== 'copy') return undefined;
  return 'The link is shown to you once. If you close this dialog without reading it out, issue a new one — a second link invalidates nothing about the first.';
}
