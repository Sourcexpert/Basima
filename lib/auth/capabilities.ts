/**
 * Re-export of the capability checks so page components can import a single
 * module path without reaching into the RBAC internals. Server components only:
 * `can()` is the same pure function used by authorize().
 */
export { can, capabilitiesFor, roleLabel, ROLES, CAPABILITIES, STEP_UP_REQUIRED, REASON_REQUIRED } from '@/lib/auth/rbac';
export type { Capability, Role, Viewer } from '@/lib/auth/rbac';
