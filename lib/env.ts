/**
 * Server-side configuration. Secrets are read here and NOWHERE else.
 * Build Guide §8: "Never expose SUPABASE_SERVICE_ROLE_KEY to browser code and
 * never prefix it with NEXT_PUBLIC_."
 *
 * The console boots in two honest modes:
 *   • 'supabase'  — SUPABASE_URL + SERVICE_ROLE_KEY + ANON_KEY present.
 *   • 'demo'      — no backend configured. The console runs against a seeded
 *                   in-memory dataset so the UX, authorization and audit paths
 *                   can be exercised. Every screen shows a DEMO badge.
 * There is no third mode in which a missing secret silently becomes a bypass.
 */

function read(name: string): string | null {
  const v = process.env[name];
  if (!v || v.trim().length === 0) return null;
  if (v.includes('REPLACE_ME') || v.includes('your-')) return null;
  return v.trim();
}

function requireInProduction(name: string, value: string | null): string | null {
  if (!value && process.env.NODE_ENV === 'production' && process.env.AGREE_E_DEMO !== '1') {
    // Fail loudly rather than degrade to demo data in production.
    throw new Error(`[agree-e] ${name} is required in production.`);
  }
  return value;
}

export const env = {
  supabaseUrl: read('NEXT_PUBLIC_SUPABASE_URL'),
  supabaseAnonKey: read('NEXT_PUBLIC_SUPABASE_ANON_KEY'),
  supabaseServiceRoleKey: read('SUPABASE_SERVICE_ROLE_KEY'),

  ipHashPepper: read('IP_HASH_PEPPER') ?? 'dev-only-pepper',
  adminStepUpWindowMinutes: Number(read('ADMIN_STEP_UP_WINDOW_MINUTES') ?? 15),
  sessionAbsoluteHours: Number(read('SESSION_ABSOLUTE_HOURS') ?? 12),

  mpesa: {
    env: (read('MPESA_ENV') ?? 'sandbox') as 'sandbox' | 'production',
    consumerKey: read('MPESA_CONSUMER_KEY'),
    consumerSecret: read('MPESA_CONSUMER_SECRET'),
    shortcode: read('MPESA_SHORTCODE'),
    passkey: read('MPESA_PASSKEY'),
    callbackUrl: read('MPESA_CALLBACK_URL'),
    callbackToken: read('MPESA_CALLBACK_TOKEN'),
  },

  flutterwave: {
    publicKey: read('FLW_PUBLIC_KEY'),
    secretKey: read('FLW_SECRET_KEY'),
    secretHash: read('FLW_SECRET_HASH'),
    webhookPath: read('FLW_WEBHOOK_PATH') ?? '/api/webhooks/flutterwave',
  },

  appUrl: read('APP_URL') ?? 'http://localhost:3000',
};

function ensureProductionSecrets() {
  // Next evaluates modules during `next build` too; the guard must fire when a
  // production *server* boots, not while pages are being collected.
  const isBuildPhase = process.env.NEXT_PHASE === 'phase-production-build';
  if (isBuildPhase) return;
  if (process.env.NODE_ENV === 'production' && process.env.AGREE_E_DEMO !== '1') {
    requireInProduction('NEXT_PUBLIC_SUPABASE_URL', env.supabaseUrl);
    requireInProduction('NEXT_PUBLIC_SUPABASE_ANON_KEY', env.supabaseAnonKey);
    requireInProduction('SUPABASE_SERVICE_ROLE_KEY', env.supabaseServiceRoleKey);
    requireInProduction('IP_HASH_PEPPER', read('IP_HASH_PEPPER'));
  }
}
ensureProductionSecrets();

export const mode: 'supabase' | 'demo' =
  env.supabaseUrl && env.supabaseServiceRoleKey && env.supabaseAnonKey ? 'supabase' : 'demo';

export const isDemo = mode === 'demo';
export const supabaseConfigured = mode === 'supabase';
export const mpesaConfigured = Boolean(
  env.mpesa.consumerKey && env.mpesa.consumerSecret && env.mpesa.shortcode && env.mpesa.passkey && env.mpesa.callbackUrl,
);
export const flutterwaveConfigured = Boolean(env.flutterwave.secretKey && env.flutterwave.secretHash);

/**
 * Which payment rails are actually usable on this deployment.
 *
 * The UI must state this honestly rather than offer a button that quietly
 * fabricates a settlement: a rail with no credentials is reported as
 * unconfigured, and the service layer returns `not_configured` for it.
 */
export function paymentRails() {
  return {
    mpesa: {
      configured: mpesaConfigured,
      environment: env.mpesa.env,
      shortcode: env.mpesa.shortcode ? `…${env.mpesa.shortcode.slice(-4)}` : null,
      label: 'M-PESA (Safaricom Daraja)',
    },
    flutterwave: {
      configured: flutterwaveConfigured,
      label: 'Flutterwave (cards, bank transfer)',
    },
  };
}
