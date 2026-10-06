import { redirect } from 'next/navigation';
import { authMode, getViewer, stepUpFresh } from '@/lib/auth/session';
import { CAPABILITIES, can, capabilitiesFor, ROLES, REASON_REQUIRED, STEP_UP_REQUIRED, roleLabel } from '@/lib/auth/capabilities';
import { env, mpesaConfigured, flutterwaveConfigured } from '@/lib/env';
import { store } from '@/lib/data/store';
import { ActionButton } from '@/components/action-form';
import { Badge, Callout, Card, KV, PageHead, Table, TabLink } from '@/components/ui';

export const dynamic = 'force-dynamic';

export default async function SettingsPage() {
  const viewer = await getViewer();
  if (!viewer) redirect('/admin/login');
  if (!can(viewer.role, 'settings.manage')) {
    return (
      <>
        <PageHead title="Roles & policy" lede="Capability matrix, elevated-action policy and integration status." />
        <Callout tone="danger">
          Your role (<span className="mono">{viewer.role}</span>) does not hold <span className="mono">settings.manage</span>.
        </Callout>
      </>
    );
  }

  const [users, actions] = await Promise.all([store().listUsers({ limit: 1000 }), store().listAdminActions({ limit: 200 })]);
  const coverage = ROLES.map((role) => ({ role, capabilities: capabilitiesFor(role) }));

  return (
    <>
      <PageHead
        title="Roles & policy"
        lede="The capability matrix is the contract between the console and the rest of the product. It is code, not configuration: changing it is a reviewed change, not a checkbox."
      />

      <div className="tabs">
        <TabLink href="/admin/settings" active>Matrix & policy</TabLink>
        <TabLink href="/admin/audit?tab=admin" active={false}>Recent changes</TabLink>
      </div>

      <div className="grid cols-4" style={{ marginBottom: 16 }}>
        <div className="card tight">
          <div className="stat-label">Backend</div>
          <div className="stat-value" style={{ fontSize: 17 }}>{authMode === 'supabase' ? 'Supabase' : 'Demo dataset'}</div>
          <div className="stat-meta">{authMode === 'supabase' ? 'Auth + RLS active' : 'No credentials detected'}</div>
        </div>
        <div className="card tight">
          <div className="stat-label">M-PESA Daraja</div>
          <div className="stat-value" style={{ fontSize: 17, color: mpesaConfigured ? 'var(--ok)' : 'var(--warn)' }}>{mpesaConfigured ? 'Configured' : 'Not configured'}</div>
          <div className="stat-meta">{env.mpesa.env} environment</div>
        </div>
        <div className="card tight">
          <div className="stat-label">Flutterwave</div>
          <div className="stat-value" style={{ fontSize: 17, color: flutterwaveConfigured ? 'var(--ok)' : 'var(--warn)' }}>{flutterwaveConfigured ? 'Configured' : 'Not configured'}</div>
          <div className="stat-meta">webhook secret hash {env.flutterwave.secretHash ? 'set' : 'missing'}</div>
        </div>
        <div className="card tight">
          <div className="stat-label">Your elevated session</div>
          <div className="stat-value" style={{ fontSize: 17, color: stepUpFresh(viewer) ? 'var(--ok)' : 'var(--warn)' }}>{stepUpFresh(viewer) ? 'Active' : 'Not elevated'}</div>
          <div className="stat-meta">{env.adminStepUpWindowMinutes} minute window</div>
        </div>
      </div>

      <Card
        title="Capability matrix"
        subtitle="Deny by default. A role can only do what its row grants, and every server action re-checks the same matrix before touching data."
      >
        <div className="table-wrap">
          <table className="matrix">
            <thead>
              <tr>
                <th>Capability</th>
                {ROLES.map((r) => <th key={r} style={{ textAlign: 'center' }}>{roleLabel(r)}</th>)}
                <th>Guard</th>
              </tr>
            </thead>
            <tbody>
              {CAPABILITIES.map((cap) => (
                <tr key={cap}>
                  <td className="mono" style={{ fontSize: 11.5 }}>{cap}</td>
                  {ROLES.map((role) => (
                    <td key={role} style={{ textAlign: 'center' }}>
                      {coverage.find((c) => c.role === role)!.capabilities.includes(cap)
                        ? <span className="yes">●</span>
                        : <span className="no">·</span>}
                    </td>
                  ))}
                  <td className="tiny">
                    {STEP_UP_REQUIRED.has(cap) && <Badge tone="warn">step-up</Badge>}
                    {REASON_REQUIRED.has(cap) && <span style={{ marginLeft: 5 }}><Badge tone="info">reason</Badge></span>}
                    {!STEP_UP_REQUIRED.has(cap) && !REASON_REQUIRED.has(cap) && <span className="tiny">—</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="callout accent" style={{ marginTop: 14 }}>
          <strong>Three deliberate omissions.</strong>
          <ul style={{ margin: '6px 0 0', paddingLeft: 18 }}>
            <li>No role holds a capability to read or set a user&rsquo;s plaintext password. Recovery, reset and supervised break-glass are the only paths.</li>
            <li>No role other than <span className="mono">security</span> can reach agreement content, and only through the logged workflow — admin status never implies contract-reading rights.</li>
            <li>No capability exists anywhere to edit or delete an evidence event, an executed version, a stamp or a ledger row.</li>
          </ul>
        </div>
      </Card>

      <div className="grid cols-2" style={{ marginTop: 16 }}>
        <Card title="Elevated-action policy" subtitle="What the console demands before a sensitive action, and why.">
          <Table head={['Requirement', 'Applies to', 'Rationale']}>
            <tr>
              <td className="nowrap">Step-up re-authentication</td>
              <td className="tiny">
                {Array.from(STEP_UP_REQUIRED).slice(0, 6).map((c) => <div className="mono" style={{ fontSize: 11 }} key={c}>{c}</div>)}
                <div className="tiny">+{Math.max(0, STEP_UP_REQUIRED.size - 6)} more</div>
              </td>
              <td className="tiny">A stolen or left-open session must not be enough to move money, read a contract or change a role.</td>
            </tr>
            <tr>
              <td className="nowrap">Written justification</td>
              <td className="tiny">
                {Array.from(REASON_REQUIRED).map((c) => <div className="mono" style={{ fontSize: 11 }} key={c}>{c}</div>)}
              </td>
              <td className="tiny">Support work is judged months later, by someone reconstructing why an account was touched.</td>
            </tr>
            <tr>
              <td className="nowrap">Second person</td>
              <td className="tiny">break-glass credentials · refunds</td>
              <td className="tiny">The two operations that could otherwise be used to steal value or appearance of identity.</td>
            </tr>
            <tr>
              <td className="nowrap">Acknowledgement</td>
              <td className="tiny">break-glass credentials</td>
              <td className="tiny">The operator states, on the record, what they understand the credential enables.</td>
            </tr>
            <tr>
              <td className="nowrap">Idempotency key</td>
              <td className="tiny">all mutation endpoints</td>
              <td className="tiny">A double-submit must not create a second link, refund or credential.</td>
            </tr>
          </Table>
        </Card>

        <Card title="Runtime configuration" subtitle="Read-only view of what this deployment has configured. Secrets are never rendered.">
          <KV
            rows={[
              ['Console URL', env.appUrl],
              ['Session absolute limit', `${env.sessionAbsoluteHours} hours`],
              ['Step-up window', `${env.adminStepUpWindowMinutes} minutes`],
              ['IP hashing pepper', env.ipHashPepper === 'dev-only-pepper' ? <Badge key="p" tone="danger">default (set IP_HASH_PEPPER)</Badge> : <Badge key="p" tone="ok">set</Badge>],
              ['M-PESA environment', env.mpesa.env + (env.mpesa.shortcode ? ` · shortcode ${env.mpesa.shortcode}` : '')],
              ['M-PESA callback', env.mpesa.callbackUrl ?? <span key="c" className="tiny">not set</span>],
              ['Callback token', env.mpesa.callbackToken ? <Badge key="t" tone="ok">set</Badge> : <Badge key="t" tone="warn">not set</Badge>],
              ['Flutterwave webhook path', env.flutterwave.webhookPath],
              ['Supabase service key', <Badge key="s" tone={env.supabaseServiceRoleKey ? 'ok' : 'warn'}>{env.supabaseServiceRoleKey ? 'present (server only)' : 'absent'}</Badge>],
            ]}
          />
          <Callout tone="danger">
            <strong>Secret hygiene.</strong> The service-role key is read only in server modules and is never prefixed
            <span className="mono"> NEXT_PUBLIC_</span>. The console refuses to boot into demo mode when it detects a
            production build without credentials, so a missing secret can never silently become a bypass.
          </Callout>
        </Card>
      </div>

      <Card
        title="Operator directory (console access)"
        subtitle="Who can reach this surface at all, and what they would hold."
        actions={
          <ActionButton
            label="End my elevated session"
            spec={{
              action: 'clear_step_up',
              title: 'End the elevated session',
              intro: <>Clears your step-up window immediately. Sensitive actions will require re-authentication. Useful before walking away from a shared machine.</>,
              reasonRequired: true,
              reasonPlaceholder: 'e.g. Finishing support duty; ending elevated session before handing the workstation over.',
              confirmLabel: 'End elevated session',
            }}
          />
        }
      >
        <Table head={['Operator', 'Role', 'Capabilities held', 'MFA', 'Last sign-in', 'Guardrails']}>
          {users
            .filter((u) => ['owner', 'admin', 'support', 'security', 'billing'].includes(u.role))
            .map((u) => (
              <tr key={u.id}>
                <td className="tiny">{u.displayName}<div className="tiny">{u.email}</div></td>
                <td className="nowrap"><span className="chip">{roleLabel(u.role)}</span></td>
                <td className="tiny">{capabilitiesFor(u.role).length} of {CAPABILITIES.length}</td>
                <td>{u.mfaEnabled ? <Badge tone="ok">enrolled</Badge> : u.status === 'active' ? <Badge tone="danger">missing</Badge> : <Badge tone="neutral">n/a</Badge>}</td>
                <td className="tiny nowrap">{u.lastSignInAt ? new Date(u.lastSignInAt).toISOString().slice(0, 16).replace('T', ' ') : 'never'}</td>
                <td className="tiny">
                  {u.role === 'owner' ? 'cannot be suspended from the console' : ''}
                  {u.role === 'admin' ? 'cannot read contract content' : ''}
                  {u.role === 'support' ? 'cannot move money' : ''}
                  {u.role === 'billing' ? 'cannot touch credentials' : ''}
                  {u.role === 'security' ? 'privileged reads are logged' : ''}
                </td>
              </tr>
            ))}
        </Table>
        <div className="tiny" style={{ marginTop: 10 }}>
          {actions.length} privileged actions recorded in this session&rsquo;s dataset. The three omissions above are enforced by
          construction — they are absent from the capability list, so no role can be granted them even by mistake.
        </div>
      </Card>
    </>
  );
}
