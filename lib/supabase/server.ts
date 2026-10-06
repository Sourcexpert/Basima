import { createServerClient, type CookieOptions } from '@supabase/ssr';
import { cookies } from 'next/headers';
import { env, supabaseConfigured } from '@/lib/env';

/**
 * Request-scoped Supabase client carrying the *user's* session (anon key +
 * cookies). Row Level Security applies to everything done through this client —
 * which is exactly what we want for reading the viewer's own profile.
 */
export async function supabaseServer() {
  if (!supabaseConfigured) return null;
  const cookieStore = await cookies();

  return createServerClient(env.supabaseUrl!, env.supabaseAnonKey!, {
    cookies: {
      getAll() {
        return cookieStore.getAll();
      },
      setAll(cookiesToSet: { name: string; value: string; options: CookieOptions }[]) {
        try {
          for (const { name, value, options } of cookiesToSet) {
            cookieStore.set(name, value, {
              ...options,
              httpOnly: true,
              secure: process.env.NODE_ENV === 'production',
              sameSite: 'lax',
              path: '/',
            });
          }
        } catch {
          // Called from a Server Component render: middleware refreshes instead.
        }
      },
    },
  });
}
