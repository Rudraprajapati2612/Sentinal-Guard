'use client';

import { usePathname } from 'next/navigation';
import Link from 'next/link';
import {
  Activity,
  BookOpen,
  ChevronRight,
  Code2,
  Cpu,
  GitCommit,
  HelpCircle,
  PauseCircle,
  Shield,
  Webhook,
  Waves,
  Zap,
} from 'lucide-react';

type SidebarGroup = {
  label: string;
  items: Array<{
    icon: React.ComponentType<{ size?: number; className?: string }>;
    label: string;
    href: string;
  }>;
};

const DOCS_SIDEBAR: SidebarGroup[] = [
  {
    label: 'Getting Started',
    items: [
      { icon: BookOpen, label: 'Overview',    href: '/docs/introduction' },
      { icon: Zap,      label: 'Quick Start', href: '/docs/quick-start' },
    ],
  },
  {
    label: 'Core Concepts',
    items: [
      { icon: Shield, label: 'How Detection Works', href: '/docs/how-it-works' },
      { icon: Cpu,    label: 'Detection Rules',     href: '/docs/detection-rules' },
    ],
  },
  {
    label: 'Integration',
    items: [
      { icon: Code2,       label: 'SDK Reference',         href: '/docs/sdk-reference' },
      { icon: Webhook,     label: 'Webhook Setup',         href: '/docs/webhook-setup' },
      { icon: PauseCircle, label: 'Protocol Registration', href: '/docs/protocol-registration' },
    ],
  },
  {
    label: 'API Reference',
    items: [
      { icon: Activity,  label: 'REST Endpoints',  href: '/docs/rest-endpoints' },
      { icon: Waves,     label: 'WebSocket Feed',  href: '/docs/websocket-feed' },
      { icon: GitCommit, label: 'Alert Schema',    href: '/docs/alert-schema' },
    ],
  },
  {
    label: 'Resources',
    items: [
      { icon: HelpCircle, label: 'FAQ', href: '/docs/faq' },
    ],
  },
];

interface Props {
  onLinkClick: () => void;
}

export default function DocsSidebar({ onLinkClick }: Props) {
  const pathname = usePathname();

  return (
    <div className="flex h-full flex-col px-4 py-6">
      <nav className="flex flex-col gap-5">
        {DOCS_SIDEBAR.map((group) => {
          const isGroupActive = group.items.some(item => pathname === item.href);

          return (
            <div key={group.label}>
              <div className="mb-2 mt-1 flex items-center gap-1.5 px-2">
                {isGroupActive && (
                  <span className="h-1 w-1 rounded-full bg-[#2563EB]" />
                )}
                <p className={`text-[11px] font-semibold uppercase tracking-[0.12em] transition-colors ${
                  isGroupActive ? 'text-[#2563EB]' : 'text-[#94A3B8]'
                }`}>
                  {group.label}
                </p>
              </div>
              <ul className="flex flex-col gap-0.5">
                {group.items.map((item) => {
                  const Icon = item.icon;
                  const isActive = pathname === item.href;

                  return (
                    <li key={item.label}>
                      <Link
                        href={item.href}
                        onClick={onLinkClick}
                        className={`group flex items-center gap-2.5 rounded-lg px-3 py-2 text-[13px] font-medium transition-all duration-150 ${
                          isActive
                            ? 'border-l-2 border-[#2563EB] bg-[#EFF6FF] pl-[10px] text-[#2563EB]'
                            : 'text-[#64748B] hover:bg-[#F8F9FC] hover:text-[#0F172A]'
                        }`}
                      >
                        <Icon
                          size={14}
                          className={isActive ? 'text-[#2563EB]' : 'text-[#94A3B8] group-hover:text-[#64748B]'}
                        />
                        <span className="flex-1">{item.label}</span>
                        {isActive ? <ChevronRight size={12} className="text-[#2563EB]" /> : null}
                      </Link>
                    </li>
                  );
                })}
              </ul>
            </div>
          );
        })}
      </nav>

      <div className="mt-auto pt-6">
        <div className="mb-4 inline-flex items-center gap-2 rounded-lg bg-[#EFF6FF] px-3 py-2">
          <span className="h-1.5 w-1.5 rounded-full bg-[#22C55E]" />
          <span className="text-[11px] font-semibold uppercase tracking-wide text-[#1E40AF]">
            v0.1.0 — Public Beta
          </span>
        </div>

        <div className="rounded-xl border border-[#E2E8F0] bg-white p-4 shadow-sm">
          <p className="text-[12px] font-semibold text-[#0F172A]">Need help?</p>
          <p className="mt-1 text-[11px] leading-relaxed text-[#64748B]">
            Open a GitHub issue — we respond within 24 hours.
          </p>
          <Link
            href="https://github.com/Rudraprajapati2612/Sentinal-Guard/issues"
            target="_blank"
            className="mt-3 block w-full rounded-lg bg-[#2563EB] py-1.5 text-center text-[11px] font-semibold text-white transition hover:bg-[#1D4ED8]"
          >
            Open Issue →
          </Link>
        </div>
      </div>
    </div>
  );
}
