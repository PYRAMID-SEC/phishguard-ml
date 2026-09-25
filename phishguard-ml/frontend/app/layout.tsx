import type { Metadata } from 'next';
import './globals.css';
export const metadata: Metadata = { title: 'PhishGuard ML', description: 'Machine-learning assisted phishing analysis' };
export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) { return <html lang="en"><body>{children}</body></html>; }
