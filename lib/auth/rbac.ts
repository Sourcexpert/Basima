/**
 * Role & capability model for the console (Build Guide §5 and §13).
 *
 * Critical boundary: "Admin status must not automatically grant contract-reading
 * rights." So `admin` and `support` CANNOT read agreement content; only a
 * `security` role with an explicit privileged-access workflow can, and every such
 * access is appended to the audit ledger with a reason.
 */

export const ROLES = ['owner', 'admin', 'support', 'security', 'billing', 'counsel'] as const;
export type Role = (typeof ROLES)[number];

export const CAPABILITIES = [
  'console.access',
  'users.read',
  'users.invite',
  'users.suspend',
  'users.role_change',
  'password.reset_link',
  'password.force_reset',
  'password.temp_issue',
  'sessions.revoke',
  'mfa.manage',
  'audit.admin.read',
  'audit.security.read',
  'agreements.metadata.read',
  'agreements.content.read.privileged',
  'billing.read',
  'billing.plans.manage',
  'billing.subscriptions.manage',
  'billing.payments.manage',
  'billing.refund',
  'settings.manage',
] as const;
export type Capability = (typeof CAPABILITIES)[number];

const ROLE_CAPABILITIES: Record<Role, Capability[]> = {
  // Platform owner: full operational control, but still no silent content access.
  owner: [
    'console.access', 'users.read', 'users.invite', 'users.suspend', 'users.role_change',
    'password.reset_link', 'password.force_reset', 'password.temp_issue', 'sessions.revoke', 'mfa.manage',
    'audit.admin.read', 'audit.security.read', 'agreements.metadata.read',
    'billing.read', 'billing.plans.manage', 'billing.subscriptions.manage', 'billing.payments.manage', 'billing.refund',
    'settings.manage',
  ],
  admin: [
    'console.access', 'users.read', 'users.invite', 'users.suspend', 'users.role_change',
    'password.reset_link', 'password.force_reset', 'sessions.revoke', 'mfa.manage',
    'audit.admin.read', 'agreements.metadata.read',
    'billing.read', 'billing.plans.manage', 'billing.subscriptions.manage',
  ],
  // Support handles account recovery and never sees money movement or contracts.
  support: [
    'console.access', 'users.read', 'password.reset_link', 'password.force_reset', 'sessions.revoke',
    'agreements.metadata.read', 'billing.read',
  ],
  security: [
    'console.access', 'users.read', 'sessions.revoke', 'mfa.manage',
    'audit.admin.read', 'audit.security.read', 'agreements.metadata.read',
    'agreements.content.read.privileged', 'settings.manage',
  ],
  billing: [
    'console.access', 'users.read',
    'billing.read', 'billing.plans.manage', 'billing.subscriptions.manage', 'billing.payments.manage',
    // Refunds belong to the billing function, and remain gated on step-up plus a
    // second approver — the control is the two-person rule, not the role alone.
    'billing.refund',
  ],
  // Counsel is scoped by matter, never by role alone.
  counsel: ['console.access', 'agreements.metadata.read'],
};

export function capabilitiesFor(role: Role, extra: Capability[] = []): Capability[] {
  return Array.from(new Set([...ROLE_CAPABILITIES[role], ...extra]));
}

export function can(role: Role, capability: Capability, extra: Capability[] = []): boolean {
  return capabilitiesFor(role, extra).includes(capability);
}

/**
 * Actions that require a fresh step-up authentication (Build Guide §17:
 * "re-authentication for sensitive actions").
 */
export const STEP_UP_REQUIRED: ReadonlySet<Capability> = new Set<Capability>([
  'password.temp_issue',
  'users.role_change',
  'sessions.revoke',
  'billing.refund',
  'agreements.content.read.privileged',
  'settings.manage',
]);

/** Actions that additionally require a written justification, recorded in the audit ledger. */
export const REASON_REQUIRED: ReadonlySet<Capability> = new Set<Capability>([
  'password.temp_issue',
  'password.force_reset',
  'agreements.content.read.privileged',
  'billing.refund',
  'users.suspend',
]);

export interface Viewer {
  userId: string;
  email: string;
  displayName: string;
  role: Role;
  capabilities: Capability[];
  /** Fresh step-up auth within the last 15 minutes. */
  stepUpVerifiedAt: string | null;
  mfaEnabled: boolean;
}

export type AuthorizeResult =
  | { allowed: true }
  | { allowed: false; status: 401 | 403; error: string; requiresStepUp?: boolean; requiresReason?: boolean };

/**
 * Deny-by-default authorization. Role checks in the browser are never the
 * control — every action calls this on the server first (Build Guide §8).
 */
export function authorize(
  viewer: Viewer | null,
  capability: Capability,
  opts: { reason?: string | null; stepUpWindowMinutes?: number } = {},
): AuthorizeResult {
  if (!viewer) return { allowed: false, status: 401, error: 'Authentication required.' };

  if (!can(viewer.role, capability)) {
    return {
      allowed: false,
      status: 403,
      error: `Role "${viewer.role}" does not hold the "${capability}" capability.`,
    };
  }

  if (STEP_UP_REQUIRED.has(capability)) {
    const window = opts.stepUpWindowMinutes ?? 15;
    const verified = viewer.stepUpVerifiedAt ? new Date(viewer.stepUpVerifiedAt).getTime() : 0;
    const fresh = Date.now() - verified < window * 60_000;
    if (!fresh) {
      return {
        allowed: false, status: 403, requiresStepUp: true,
        error: 'Re-authentication required: this action needs a fresh step-up verification.',
      };
    }
  }

  if (REASON_REQUIRED.has(capability)) {
    const reason = (opts.reason ?? '').trim();
    if (reason.length < 12) {
      return {
        allowed: false, status: 403, requiresReason: true,
        error: 'A written justification (at least 12 characters) is required and will be recorded in the audit ledger.',
      };
    }
  }

  return { allowed: true };
}

export function roleLabel(role: Role): string {
  return ({
    owner: 'Owner',
    admin: 'Administrator',
    support: 'Support',
    security: 'Security',
    billing: 'Billing',
    counsel: 'Counsel',
  })[role];
}
