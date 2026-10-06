import Link from 'next/link';
import { redirect } from 'next/navigation';
import { getViewer } from '@/lib/auth/session';
import { can } from '@/lib/auth/rbac';
import { store } from '@/lib/data/store';
import { ActionButton } from '@/components/action-form';
import { FilterBar } from '@/components/action-form';
import { Badge, Callout, Card, PageHead, StatusBadge, Table, when, relative, Initials } from '@/components/ui';
import type { Profile } from '@/lib/data/types';

export const dynamic = 'force-dynamic';

const ROLES = ['owner', 'admin', 'support', 'security', 'billing', 'counsel'] as const;
const STATUSES = ['active', 'invited', 'locked', 'suspended', 'deactivated'] as const;
const DEMO_NOW = new Date('2026-10-05T09:20:00.000Z').getTime();

export default async function UsersPage({
  searchParams,
}: {
  searchParams: Promise<{ q?: string; role?: string; status?: string; mfa?: string }>;
}) {
  const viewer = await getViewer();
  if (!viewer) redirect('/admin/login');
  if (!can(viewer.role, 'users.read')) {
    return (
      <>
        <PageHead title="Users & access" lede="Account, credential and role administration." />
        <Callout tone="danger">
          Your role (<span className="mono">{viewer.role}</span>) does not hold the <span className="mono">users.read</span>{' '}
          capability. This is enforced at the server, not by hiding the link.
        </Callout>
      </>
    );
  }

  const params = await searchParams;
  const [all, subscriptions] = await Promise.all([
    store().listUsers({ limit: 2000 }),
    store().listSubscriptions({ limit: 1000 }),
  ]);

  let users = all.filter(
    (u) =>
      (!params.role || u.role === params.role) &&
      (!params.status || u.status === params.status) &&
      (params.mfa !== 'missing' || !u.mfaEnabled) &&
      (!params.q ||
        [u.displayName, u.email, u.organisation ?? '', u.country]
          .join(' ')
          .toLowerCase()
          .includes(params.q.toLowerCase())),
  );
  users = users.sort((a, b) => a.displayName.localeCompare(b.displayName));

  const privileged = (u: Profile) => ['owner', 'admin', 'support', 'security', 'billing'].includes(u.role);
  const withoutMfa = users.filter((u) => privileged(u) && !u.mfaEnabled && u.status === 'active');
  const needsReset = users.filter((u) => u.forcePasswordReset);

  return (
    <>
      <PageHead
        title="Users & access"
        lede="Credentials, sessions, roles and MFA policy. No operator on this screen can read or set another person's password: the console can only send a single-use recovery link, force a reset at next sign-in, revoke sessions, require MFA, lock an account, or issue a supervisor-approved break-glass credential."
        actions={
          can(viewer.role, 'users.invite') ? (
            <ActionButton
              spec={{
                action: 'reset_link',
                title: 'Invite is handled by the user workspace',
                intro: 'Console invitations are issued from the user workspace so the invite email, consent version and organisation tenancy are captured in one place. This console can re-issue credentials for existing accounts.',
                fields: [{ name: 'note', label: 'Note (not submitted)', type: 'text', required: false }],
                reasonRequired: false,
              }}
              label="About invitations"
            />
          ) : undefined
        }
      />

      <div className="grid cols-4" style={{ marginBottom: 16 }}>
        <div className="card tight"><div className="stat-label">Accounts</div><div className="stat-value">{all.length}</div></div>
        <div className="card tight">
          <div className="stat-label">Privileged without MFA</div>
          <div className="stat-value" style={{ color: withoutMfa.length ? 'var(--danger)' : 'var(--ok)' }}>{withoutMfa.length}</div>
        </div>
        <div className="card tight">
          <div className="stat-label">Reset required</div>
          <div className="stat-value" style={{ color: needsReset.length ? 'var(--warn)' : 'var(--muted)' }}>{needsReset.length}</div>
        </div>
        <div className="card tight"><div className="stat-label">Suspended / locked</div><div className="stat-value">{all.filter((u) => ['suspended', 'locked'].includes(u.status)).length}</div></div>
      </div>

      {withoutMfa.length > 0 && (
        <Callout tone="danger">
          <strong>Policy breach.</strong> {withoutMfa.length} active privileged account(s) have MFA disabled:{' '}
          {withoutMfa.slice(0, 4).map((u) => u.email).join(', ')}{withoutMfa.length > 4 ? '…' : ''}. Require enrolment on each
          account, or remove the privileged role — the console offers both, and either is logged.
        </Callout>
      )}

      <div className="section-title">
        <h2>Directory</h2>
        <div className="spacer" />
        <span className="tiny">{users.length} of {all.length} shown</span>
      </div>

      <FilterBar
        basePath="/admin/users"
        values={params}
        filters={[
          { name: 'q', label: 'Search', type: 'text', placeholder: 'name, email, organisation' },
          { name: 'role', label: 'Role', type: 'select', options: ROLES.map((r) => ({ value: r, label: r })) },
          { name: 'status', label: 'Status', type: 'select', options: STATUSES.map((s) => ({ value: s, label: s })) },
          { name: 'mfa', label: 'MFA', type: 'select', options: [{ value: 'missing', label: 'missing' }] },
        ]}
      />

      <div style={{ marginTop: 14 }}>
        <Table
          head={['Account', 'Role', 'Status', 'MFA', 'Last sign-in', 'Subscription', 'Security flags', '']}
          empty="No accounts match those filters."
        >
          {users.map((u) => {
            const sub = subscriptions.find((s) => s.userId === u.id);
            const flags: React.ReactNode[] = [];
            if (u.forcePasswordReset) flags.push(<Badge key="f" tone="warn">reset required</Badge>);
            if (u.tempCredentialExpiresAt) flags.push(<Badge key="t" tone="danger">break-glass</Badge>);
            if (u.failedSignInCount >= 5) flags.push(<Badge key="s" tone="danger">{u.failedSignInCount} failed sign-ins</Badge>);
            if (privileged(u) && !u.mfaEnabled) flags.push(<Badge key="m" tone="danger">MFA missing</Badge>);
            if (u.tempCredentialExpiresAt === null && u.status === 'active' && u.role === 'counsel' && !u.emailVerified) flags.push(<Badge key="e" tone="warn">email unverified</Badge>);

            return (
              <tr key={u.id}>
                <td>
                  <div style={{ display: 'flex', gap: 9, alignItems: 'center' }}>
                    <Initials name={u.displayName} />
                    <div>
                      <div style={{ fontWeight: 570 }}>{u.displayName}</div>
                      <div className="tiny">{u.email}{u.organisation ? ` · ${u.organisation}` : ''} · {u.country}</div>
                    </div>
                  </div>
                </td>
                <td className="nowrap"><span className="chip">{u.role}</span></td>
                <td><StatusBadge status={u.status} /></td>
                <td className="nowrap">
                  {u.mfaEnabled
                    ? <Badge tone="ok">enabled</Badge>
                    : u.mfaRequired
                      ? <Badge tone="danger">required, not enrolled</Badge>
                      : <Badge tone="neutral">off</Badge>}
                </td>
                <td className="tiny nowrap">{u.lastSignInAt ? `${relative(u.lastSignInAt, DEMO_NOW)}` : 'never'}</td>
                <td className="nowrap tiny">
                  {sub ? (
                    <span style={{ display: 'inline-flex', gap: 6, alignItems: 'center' }}>
                      <StatusBadge status={sub.status} /> {sub.planName}
                    </span>
                  ) : <span className="tiny">no subscription</span>}
                </td>
                <td><div style={{ display: 'flex', gap: 5, flexWrap: 'wrap' }}>{flags.length ? flags : <span className="tiny">—</span>}</div></td>
                <td className="nowrap"><Link className="btn sm" href={`/admin/users/${u.id}`}>Manage</Link></td>
              </tr>
            );
          })}
        </Table>
      </div>

      <Callout tone="accent">
        <strong>Retention note.</strong> Account rows carry no agreement content and no raw identity documents. Identity
        verification artefacts live in <span className="mono">identity_verifications</span> as provider references and statuses,
        joined by internal UUIDs, so deleting an account never has to reach into a contract or an evidence package.
      </Callout>
    </>
  );
}
