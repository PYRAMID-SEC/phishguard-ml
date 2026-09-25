'use client';
export type Mode = 'url' | 'email' | 'html' | 'network';
export default function AnalyzerTabs({ mode, setMode }: { mode: Mode; setMode: (mode: Mode) => void }) { return <nav className="panel" style={{ display: 'flex', gap: 3, padding: 5, overflowX: 'auto' }}>{[['url','URL'],['email','EMAIL'],['html','WEBSITE'],['network','IP / DOMAIN']].map(([value, label]) => <button className={`tab ${mode === value ? 'active' : ''}`} key={value} onClick={() => setMode(value as Mode)}>{label}</button>)}</nav>; }
