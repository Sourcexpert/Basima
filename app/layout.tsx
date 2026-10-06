import type { Metadata, Viewport } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'agre-e · Admin console',
  description: 'Operations, billing, security and support console for agre-e — evidence-first private agreements.',
  robots: { index: false, follow: false },
};

export const viewport: Viewport = { themeColor: '#070b14' };

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
