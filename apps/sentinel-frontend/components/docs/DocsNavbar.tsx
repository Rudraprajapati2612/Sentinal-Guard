'use client';

import { useState, useRef, useEffect } from 'react';
import { Shield, Menu, Search, Github, ArrowUpRight, X } from 'lucide-react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';

const NAV_LINKS = [
  { label: 'Overview',      href: '/docs/introduction' },
  { label: 'Quick Start',   href: '/docs/quick-start' },
  { label: 'API Reference', href: '/docs/rest-endpoints' },
  { label: 'Architecture',  href: '/docs/introduction#architecture' },
];

const SEARCH_INDEX = [
  { label: 'Overview',              href: '/docs/introduction',          group: 'Getting Started' },
  { label: 'Quick Start',           href: '/docs/quick-start',           group: 'Getting Started' },
  { label: 'How Detection Works',   href: '/docs/how-it-works',          group: 'Core Concepts' },
  { label: 'Detection Rules',       href: '/docs/detection-rules',       group: 'Core Concepts' },
  { label: 'SDK Reference',         href: '/docs/sdk-reference',         group: 'Integration' },
  { label: 'Webhook Setup',         href: '/docs/webhook-setup',         group: 'Integration' },
  { label: 'Protocol Registration', href: '/docs/protocol-registration', group: 'Integration' },
  { label: 'REST Endpoints',        href: '/docs/rest-endpoints',        group: 'API Reference' },
  { label: 'WebSocket Feed',        href: '/docs/websocket-feed',        group: 'API Reference' },
  { label: 'Alert Schema',          href: '/docs/alert-schema',          group: 'API Reference' },
  { label: 'FAQ',                   href: '/docs/faq',                   group: 'Resources' },
];

interface Props {
  onMenuClick: () => void;
}

export default function DocsNavbar({ onMenuClick }: Props) {
  const [query, setQuery] = useState('');
  const [open, setOpen] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const dropdownRef = useRef<HTMLDivElement>(null);
  const router = useRouter();

  const results = query.trim()
    ? SEARCH_INDEX.filter(item =>
        item.label.toLowerCase().includes(query.toLowerCase()) ||
        item.group.toLowerCase().includes(query.toLowerCase())
      )
    : [];

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        inputRef.current?.focus();
        setOpen(true);
      }
      if (e.key === 'Escape') {
        setOpen(false);
        setQuery('');
        inputRef.current?.blur();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  useEffect(() => {
    const onClickOutside = (e: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    };
    document.addEventListener('mousedown', onClickOutside);
    return () => document.removeEventListener('mousedown', onClickOutside);
  }, []);

  const handleSelect = (href: string) => {
    router.push(href);
    setQuery('');
    setOpen(false);
    inputRef.current?.blur();
  };

  return (
    <header className="sticky top-0 z-50 border-b border-[#E2E8F0] bg-white/90 backdrop-blur-md">
      <div className="flex h-14 items-center gap-4 px-4 sm:px-6">
        {/* Hamburger (mobile) */}
        <button
          onClick={onMenuClick}
          className="flex h-9 w-9 items-center justify-center rounded-lg border border-[#E2E8F0] text-[#64748B] transition hover:bg-[#F1F5F9] md:hidden"
          aria-label="Toggle sidebar"
        >
          <Menu size={18} />
        </button>

        {/* Logo */}
        <Link href="/" className="flex flex-shrink-0 items-center gap-2">
          <Shield size={22} className="text-[#2563EB]" fill="currentColor" />
          <span className="text-[15px] font-semibold text-[#0F172A]">SentinelGuard</span>
        </Link>

        {/* Search bar */}
        <div ref={dropdownRef} className="relative mx-auto hidden max-w-md flex-1 sm:block">
          <div
            className={`flex items-center gap-2 rounded-lg border bg-[#F8FAFC] px-3 py-1.5 transition-all duration-200 ${
              open ? 'border-[#2563EB] shadow-[0_0_0_3px_rgba(37,99,235,0.1)]' : 'border-[#E2E8F0]'
            }`}
          >
            <Search size={14} className="flex-shrink-0 text-[#94A3B8]" />
            <input
              ref={inputRef}
              type="text"
              value={query}
              onChange={e => { setQuery(e.target.value); setOpen(true); }}
              onFocus={() => setOpen(true)}
              placeholder="Search documentation..."
              className="flex-1 bg-transparent text-[13px] text-[#0F172A] outline-none placeholder:text-[#94A3B8]"
            />
            {query ? (
              <button onClick={() => { setQuery(''); inputRef.current?.focus(); }}>
                <X size={13} className="text-[#94A3B8] hover:text-[#475569]" />
              </button>
            ) : (
              <kbd className="hidden items-center gap-0.5 rounded border border-[#E2E8F0] bg-white px-1.5 py-0.5 text-[10px] font-medium text-[#94A3B8] sm:flex">
                ⌘K
              </kbd>
            )}
          </div>

          {open && results.length > 0 && (
            <div className="absolute top-full mt-1.5 w-full overflow-hidden rounded-xl border border-[#E2E8F0] bg-white shadow-lg">
              {results.map((item, i) => (
                <button
                  key={item.href}
                  onClick={() => handleSelect(item.href)}
                  className="flex w-full items-center justify-between px-4 py-2.5 text-left transition-colors hover:bg-[#F8FAFC]"
                  style={{ animation: `fadeIn 0.15s ease-out ${i * 0.03}s both` }}
                >
                  <span className="text-[13px] font-medium text-[#0F172A]">{item.label}</span>
                  <span className="text-[11px] text-[#94A3B8]">{item.group}</span>
                </button>
              ))}
            </div>
          )}

          {open && query.trim() && results.length === 0 && (
            <div className="absolute top-full mt-1.5 w-full rounded-xl border border-[#E2E8F0] bg-white px-4 py-3 shadow-lg">
              <p className="text-[13px] text-[#94A3B8]">No results for &quot;{query}&quot;</p>
            </div>
          )}
        </div>

        {/* Center nav links */}
        <nav className="hidden items-center gap-1 lg:flex">
          {NAV_LINKS.map((l) => (
            <Link
              key={l.label}
              href={l.href}
              className="rounded-md px-3 py-1.5 text-[13px] font-medium text-[#475569] transition hover:bg-[#F1F5F9] hover:text-[#0F172A]"
            >
              {l.label}
            </Link>
          ))}
        </nav>

        {/* Right actions */}
        <div className="ml-auto flex flex-shrink-0 items-center gap-2">
          <Link
            href="https://github.com/Rudraprajapati2612/Sentinal-Guard"
            target="_blank"
            className="flex items-center gap-1.5 rounded-lg border border-[#E2E8F0] bg-white px-3 py-1.5 text-[13px] font-medium text-[#475569] transition hover:border-[#CBD5E1] hover:text-[#0F172A]"
          >
            <Github size={14} />
            <span className="hidden sm:inline">GitHub</span>
          </Link>
          <Link
            href="/dashboard"
            className="flex items-center gap-1.5 rounded-lg bg-[#2563EB] px-3 py-1.5 text-[13px] font-medium text-white transition hover:bg-[#1D4ED8]"
          >
            <span>Open Dashboard</span>
            <ArrowUpRight size={13} />
          </Link>
        </div>
      </div>
    </header>
  );
}
