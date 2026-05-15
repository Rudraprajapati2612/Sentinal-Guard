import Link from 'next/link';
import {
  Code2,
  ChevronRight,
  Globe,
  Info,
  Plug,
  Radar,
  ShieldAlert,
  ShieldCheck,
  Siren,
  Zap,
} from 'lucide-react';
import ArchitectureFlow from '@/components/docs/ArchitectureFlow';
import CodeBlock from '@/components/docs/CodeBlock';
import FaqAccordion from '@/components/docs/FaqAccordion';

type TocItem = { id: string; label: string };

export type DocsPageConfig = {
  toc: TocItem[];
  content: React.ReactNode;
};

function Breadcrumb({ items }: { items: string[] }) {
  return (
    <nav className="mb-6 flex items-center gap-1.5 text-[12px] text-[#94A3B8]">
      {items.map((item, index) => {
        const isLast = index === items.length - 1;
        const href = item === 'Docs' ? '/docs/introduction' : undefined;

        return (
          <span key={`${item}-${index}`} className="flex items-center gap-1.5">
            {href && !isLast ? (
              <Link href={href} className="transition hover:text-[#2563EB]">
                {item}
              </Link>
            ) : (
              <span className={isLast ? 'font-medium text-[#0F172A]' : ''}>{item}</span>
            )}
            {!isLast ? <ChevronRight size={12} /> : null}
          </span>
        );
      })}
    </nav>
  );
}

function SectionTitle({ title }: { title: string }) {
  return (
    <div className="border-b border-[#E2E8F0] pb-3">
      <h2 className="text-[20px] font-semibold tracking-tight text-[#0F172A]">{title}</h2>
    </div>
  );
}

function FeatureCard({
  icon,
  title,
  description,
}: {
  icon: string;
  title: string;
  description: string;
}) {
  return (
    <div className="rounded-[12px] border border-[#E2E8F0] bg-white p-5 shadow-sm transition-all duration-200 hover:-translate-y-0.5 hover:border-[#BFDBFE] hover:shadow-md">
      <div className="mb-3 flex items-center gap-3">
        <span className="text-[22px]" aria-hidden="true">
          {icon}
        </span>
        <h3 className="text-[16px] font-semibold text-[#0F172A]">{title}</h3>
      </div>
      <p className="text-[14px] leading-6 text-[#64748B]">{description}</p>
    </div>
  );
}

function TimelineStep({
  time,
  label,
  tone,
  index,
}: {
  time: string;
  label: string;
  tone: 'critical' | 'warning' | 'late';
  index: number;
}) {
  const dotColor =
    tone === 'critical' ? 'bg-[#EF4444]' : tone === 'warning' ? 'bg-[#F59E0B]' : 'bg-[#0F172A]';
  const pulse = tone === 'critical' ? 'animate-pulse' : '';

  return (
    <div
      className="relative flex min-w-[120px] flex-1 flex-col items-center text-center"
      style={{ animation: `slideUp 0.35s ease-out ${index * 0.1}s both` }}
    >
      <span className={`mb-3 h-3 w-3 rounded-full ${dotColor} ${pulse}`} />
      <p className="text-[12px] font-semibold text-[#0F172A]">{time}</p>
      <p className="mt-1 max-w-[120px] text-[12px] leading-5 text-[#64748B]">{label}</p>
    </div>
  );
}

function StatCard({ value, label, accent }: { value: string; label: string; accent?: boolean }) {
  return (
    <div className={`rounded-2xl border px-5 py-5 text-center shadow-sm transition-all duration-200 hover:shadow-md ${
      accent ? 'border-[#BFDBFE] bg-[#EFF6FF]' : 'border-[#E2E8F0] bg-white'
    }`}>
      <p className={`text-[28px] font-bold tracking-tight ${accent ? 'text-[#2563EB]' : 'text-[#0F172A]'}`}>{value}</p>
      <p className="mt-2 text-[13px] leading-5 text-[#64748B]">{label}</p>
    </div>
  );
}

function NextStepCard({
  href,
  icon,
  title,
  desc,
}: {
  href: string;
  icon: React.ReactNode;
  title: string;
  desc: string;
}) {
  return (
    <Link
      href={href}
      className="group flex min-h-[188px] flex-col gap-3 rounded-xl border border-[#E2E8F0] bg-white p-6 shadow-sm transition-all duration-200 hover:border-[#2563EB] hover:shadow-md focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#2563EB] focus-visible:ring-offset-2"
    >
      <div className="mb-1 text-[#2563EB]">{icon}</div>
      <div>
        <p className="text-[15px] font-bold text-[#0F172A]">{title}</p>
        <p className="mt-1 text-[13px] leading-relaxed text-[#64748B]">{desc}</p>
      </div>
      <span className="mt-auto text-[13px] font-medium text-[#2563EB] group-hover:underline">
        Read more →
      </span>
    </Link>
  );
}

function RequirementCard({
  icon,
  title,
  subtext,
}: {
  icon: string;
  title: string;
  subtext: string;
}) {
  return (
    <div className="rounded-xl border border-[#E2E8F0] bg-white p-4 shadow-sm transition-all duration-200 hover:border-[#BFDBFE] hover:shadow-md">
      <div className="flex items-center gap-3">
        <span className="text-[20px]" aria-hidden="true">
          {icon}
        </span>
        <div>
          <p className="text-[14px] font-semibold text-[#0F172A]">{title}</p>
          <p className="text-[12px] text-[#64748B]">{subtext}</p>
        </div>
      </div>
    </div>
  );
}

function RequirementBadge({ required }: { required: boolean }) {
  return required ? (
    <span className="inline-flex rounded-full bg-[#F0FDF4] px-2.5 py-1 text-[11px] font-medium text-[#15803D]">
      ✅ Yes
    </span>
  ) : (
    <span className="inline-flex rounded-full bg-[#F1F5F9] px-2.5 py-1 text-[11px] font-medium text-[#94A3B8]">
      Optional
    </span>
  );
}


function IntroContent() {
  return (
    <article className="mx-auto max-w-4xl px-6 py-10">
      <Breadcrumb items={['Docs', 'Getting Started', 'Introduction']} />

      <div className="mb-12">
        <div className="mb-4 inline-flex items-center rounded-full bg-[#EFF6FF] px-3 py-1.5">
          <span className="text-[11px] font-semibold uppercase tracking-[0.14em] text-[#2563EB]">
            INTRODUCTION
          </span>
        </div>
        <h1 className="max-w-3xl text-[36px] font-bold tracking-tight text-[#0F172A]">
          What is SentinelGuard?
        </h1>
        <p className="mt-4 max-w-3xl text-[16px] leading-7 text-[#64748B]">
          An autonomous exploit detection and circuit-breaker layer for Solana DeFi — built
          to act in under one slot.
        </p>
      </div>

      <section id="the-problem" data-section className="mb-14 scroll-mt-20">
        <SectionTitle title="The Problem" />
        <p className="mt-4 max-w-3xl text-[14px] leading-7 text-[#64748B]">
          Every major DeFi exploit follows the same pattern. A flash loan is initiated, TVL
          drops across 2-3 transactions, and by the time the protocol team coordinates a
          manual pause, funds are already bridged out. The average response window is 4-22
          minutes. SentinelGuard closes that window to under 400ms.
        </p>

        <div className="mt-6 overflow-hidden rounded-2xl bg-white shadow-[0_8px_32px_rgba(15,23,42,0.08)]">
          <div className="px-5 py-6 sm:px-6">
            <div className="relative flex flex-col gap-8 md:flex-row md:items-start md:justify-between md:gap-3">
              <div className="absolute top-1.5 left-0 hidden h-px w-full border-t-2 border-dotted border-[#CBD5E1] md:block" />
              <TimelineStep index={0} time="T+0s"    label='🔴 "Attack begins"'            tone="critical" />
              <TimelineStep index={1} time="T+8s"    label='🔴 "Vault drained"'             tone="critical" />
              <TimelineStep index={2} time="T+4min"  label='🟡 "Team sees Twitter alert"'   tone="warning" />
              <TimelineStep index={3} time="T+18min" label='🟡 "Multisig submitted"'        tone="warning" />
              <TimelineStep index={4} time="T+22min" label='⚫ "Funds bridged — too late"'  tone="late" />
            </div>
          </div>
          <div className="bg-[#EF4444] px-5 py-3 text-[13px] font-semibold text-white sm:px-6">
            22 minutes. $0 recovered.
          </div>
        </div>
      </section>

      <section id="how-it-fixes-it" data-section className="mb-14 scroll-mt-20">
        <SectionTitle title="How SentinelGuard Fixes It" />
        <div className="mt-6 grid grid-cols-1 gap-4 md:grid-cols-2">
          <FeatureCard
            icon="⚡"
            title="Sub-slot Detection"
            description="Watches every transaction via Geyser gRPC stream. Three detection rules score each slot in real time."
          />
          <FeatureCard
            icon="🔒"
            title="Automated On-chain Pause"
            description="When severity exceeds threshold, pause_withdrawals fires on-chain within the same slot. No human needed."
          />
          <FeatureCard
            icon="📡"
            title="Public Threat Feed"
            description="Open WebSocket feed streams live alerts. No API key. Any wallet or aggregator can consume it."
          />
          <FeatureCard
            icon="🔌"
            title="3-line Integration"
            description="Protocols add SentinelGuard via npm SDK. No smart contract rewrite required."
          />
        </div>
      </section>

      <section id="architecture" data-section className="mb-14 scroll-mt-20">
        <SectionTitle title="Architecture at a Glance" />
        <p className="mt-3 max-w-3xl text-[14px] leading-7 text-[#64748B]">
          SentinelGuard turns raw Solana transaction data into threat scoring, automated
          defense, and public alert distribution through a single low-latency pipeline.
        </p>
        <div className="mt-6">
          <ArchitectureFlow />
        </div>
      </section>

      <section id="real-world-reference" data-section className="mb-14 scroll-mt-20">
        <SectionTitle title="Hypothetical Scenario" />
        <div className="mb-4 inline-flex items-center gap-2 rounded-full border border-[#F59E0B]/30 bg-[#FFFBEB] px-3 py-1">
          <span className="h-1.5 w-1.5 rounded-full bg-[#F59E0B]" />
          <span className="text-[11px] font-semibold uppercase tracking-[0.12em] text-[#92400E]">Simulated scenario — not a real event</span>
        </div>
        <div className="mt-2 rounded-2xl border-l-4 border-l-[#2563EB] bg-white p-6 shadow-[0_8px_24px_rgba(15,23,42,0.08)]">
          <div className="flex items-start gap-3">
            <ShieldAlert size={20} className="mt-0.5 flex-shrink-0 text-[#2563EB]" />
            <p className="text-[15px] leading-7 text-[#475569]">
              Imagine a protocol loses $232M in a drain that runs across ~12 transactions over ~8 seconds —
              the pattern of the Drift Protocol class of exploits. SentinelGuard would detect the anomaly after
              transaction 2–3 and pause withdrawals before transaction 4 fires.
            </p>
          </div>
        </div>

        <div className="mt-6 grid grid-cols-1 gap-4 md:grid-cols-3">
          <StatCard value="70-80%" label="Estimated funds that could have been saved" />
          <StatCard value="400ms" label="Time from detection to on-chain pause" accent />
          <StatCard value="Tx 2-3" label="When detection would have triggered" />
        </div>
      </section>

      <section id="next-steps" data-section className="scroll-mt-20">
        <SectionTitle title="Next Steps" />
        <p className="mt-3 text-[14px] leading-7 text-[#64748B]">
          Continue from the architecture overview into setup, rule logic, or protocol integration.
        </p>
        <div className="mt-6 grid grid-cols-1 gap-4 sm:grid-cols-3">
          <NextStepCard
            href="/docs/quick-start"
            icon={<Zap size={24} aria-hidden="true" />}
            title="Quick Start"
            desc="Move from concept to a local running instance and attack simulation."
          />
          <NextStepCard
            href="/docs/detection-rules"
            icon={<Siren size={24} aria-hidden="true" />}
            title="Detection Rules"
            desc="See how Rule 1, Rule 2, and Rule 3 assign severity in real time."
          />
          <NextStepCard
            href="/docs/how-it-works"
            icon={<Radar size={24} aria-hidden="true" />}
            title="How It Works"
            desc="Follow the full monitoring-to-response lifecycle inside the platform."
          />
        </div>
      </section>
    </article>
  );
}

function QuickStartContent() {
  return (
    <article className="mx-auto max-w-4xl px-6 py-10">
      <Breadcrumb items={['Docs', 'Getting Started', 'Quick Start']} />

      <div className="mb-12">
        <div className="mb-4 inline-flex items-center rounded-full bg-[#EFF6FF] px-3 py-1.5">
          <span className="text-[11px] font-semibold uppercase tracking-[0.14em] text-[#2563EB]">
            QUICK START
          </span>
        </div>
        <h1 className="max-w-3xl text-[36px] font-bold tracking-tight text-[#0F172A]">
          Quick Start
        </h1>
        <p className="mt-4 max-w-3xl text-[16px] leading-7 text-[#64748B]">
          Get SentinelGuard monitoring your Solana DeFi protocol in under 5 minutes.
        </p>
      </div>

      <section id="prerequisites" data-section className="mb-12 scroll-mt-20">
        <SectionTitle title="Prerequisites" />
        <div className="mt-5 grid grid-cols-1 gap-4 md:grid-cols-3">
          <RequirementCard icon="🦀" title="Rust 1.75+" subtext="cargo installed" />
          <RequirementCard icon="📦" title="Bun 1.0+" subtext="or Node 18+" />
          <RequirementCard icon="⚓" title="Anchor CLI 0.31" subtext="for program deploy" />
        </div>
      </section>

      <section id="clone-and-install" data-section className="mb-12 scroll-mt-20">
        <SectionTitle title="1. Clone and Install" />
        <div className="mt-5">
          <CodeBlock lang="bash" filename="terminal">
            <span className="text-[#64748B]"># Clone the monorepo</span>{'\n'}
            <span className="text-[#93C5FD]">git clone https://github.com/Rudraprajapati2612/sentinel-guard</span>{'\n'}
            <span className="text-[#93C5FD]">cd sentinel-guard</span>{'\n'}
            {'\n'}
            <span className="text-[#64748B]"># Install JS dependencies</span>{'\n'}
            <span className="text-[#93C5FD]">bun install</span>{'\n'}
            {'\n'}
            <span className="text-[#64748B]"># Build Rust workspace</span>{'\n'}
            <span className="text-[#93C5FD]">cargo build --release</span>
          </CodeBlock>
        </div>
      </section>

      <section id="environment-setup" data-section className="mb-12 scroll-mt-20">
        <SectionTitle title="2. Environment Setup" />
        <p className="mt-4 text-[14px] leading-7 text-[#64748B]">
          Copy the example env file and fill in your keys.
        </p>
        <div className="mt-4">
          <CodeBlock lang="bash" filename="terminal">
            <span className="text-[#93C5FD]">cp watcher/.env.example watcher/.env</span>
          </CodeBlock>
        </div>

        <div className="mt-5 overflow-hidden rounded-xl border border-[#E2E8F0] bg-white">
          <table className="w-full border-collapse text-left">
            <thead className="bg-white">
              <tr className="border-b border-[#E2E8F0]">
                <th className="px-4 py-3 text-[12px] font-semibold uppercase tracking-[0.08em] text-[#64748B]">Variable</th>
                <th className="px-4 py-3 text-[12px] font-semibold uppercase tracking-[0.08em] text-[#64748B]">Required</th>
                <th className="px-4 py-3 text-[12px] font-semibold uppercase tracking-[0.08em] text-[#64748B]">Description</th>
              </tr>
            </thead>
            <tbody>
              {[
                ['HELIUS_API_KEY', true, 'Helius RPC + Geyser access'],
                ['SENTINEL_PROGRAM_ID', true, 'Deployed program address'],
                ['DATABASE_URL', true, 'PostgreSQL connection string'],
                ['REDIS_URL', true, 'Redis for TVL state + cooldowns'],
                ['VAULT_ACCOUNTS', true, 'Comma-separated vault addresses'],
                ['DISCORD_WEBHOOK_URL', false, 'Alert notifications'],
                ['KAFKA_BROKERS', false, 'Durable alert logging'],
                ['MIN_SEVERITY_TO_PAUSE', false, 'Default: 60'],
              ].map(([variable, required, description], index) => (
                <tr
                  key={variable as string}
                  className={`border-b border-[#E2E8F0] last:border-b-0 ${index % 2 === 1 ? 'bg-[#F8F9FC]' : 'bg-white'}`}
                >
                  <td className="px-4 py-3 align-top">
                    <code className="rounded bg-[#EFF6FF] px-1.5 py-0.5 text-[12px] font-medium text-[#2563EB]">
                      {variable}
                    </code>
                  </td>
                  <td className="px-4 py-3 align-top">
                    <RequirementBadge required={required as boolean} />
                  </td>
                  <td className="px-4 py-3 text-[13px] leading-6 text-[#64748B]">{description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section id="start-the-watcher" data-section className="mb-12 scroll-mt-20">
        <SectionTitle title="3. Start the Watcher" />
        <div className="mt-5">
          <CodeBlock lang="bash" filename="terminal">
            <span className="text-[#64748B]"># Start infrastructure</span>{'\n'}
            <span className="text-[#93C5FD]">docker compose up -d</span>{'\n'}
            {'\n'}
            <span className="text-[#64748B]"># Run database migrations</span>{'\n'}
            <span className="text-[#93C5FD]">sqlx migrate run</span>{'\n'}
            {'\n'}
            <span className="text-[#64748B]"># Start the watcher</span>{'\n'}
            <span className="text-[#93C5FD]">cargo run --bin watcher</span>
          </CodeBlock>
        </div>

        <div className="mt-5 rounded-lg border-l-4 border-[#22C55E] bg-[#F0FDF4] p-4">
          <div className="flex items-start gap-3">
            <ShieldCheck size={18} className="mt-0.5 flex-shrink-0 text-[#22C55E]" />
            <div className="min-w-0">
              <p className="text-[14px] font-medium text-[#166534]">If setup is correct, you&apos;ll see:</p>
              <div className="mt-3 overflow-hidden rounded-[10px] bg-[#0F172A] px-4 py-4">
                <pre className="overflow-x-auto text-[13px] leading-6 text-[#E2E8F0]">
{`╔══════════════════════════════════════╗
║  SentinelGuard — Monitoring Active   ║
║  Protocol: your_protocol_address     ║
║  Vault TVL: $1,200,000 USDC          ║
╚══════════════════════════════════════╝
Geyser connected. Watching 1 program.`}
                </pre>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section id="test-with-simulation" data-section className="mb-12 scroll-mt-20">
        <SectionTitle title="4. Test with Attack Simulation" />
        <p className="mt-4 text-[14px] leading-7 text-[#64748B]">
          Run the included attack scenarios to verify detection is working.
        </p>
        <div className="mt-4">
          <CodeBlock lang="bash" filename="terminal">
            <span className="text-[#93C5FD]">bun run tests/attack_scenarios.ts</span>
          </CodeBlock>
        </div>
        <div className="mt-5 rounded-lg border-l-4 border-[#2563EB] bg-[#EFF6FF] p-4">
          <div className="flex items-start gap-3">
            <Info size={18} className="mt-0.5 flex-shrink-0 text-[#2563EB]" />
            <p className="text-[14px] leading-7 text-[#1E40AF]">
              Scenario 13 is the recommended demo scenario — it shows a drain attack being detected
              and the vault paused on-chain before the attacker can withdraw.
            </p>
          </div>
        </div>
      </section>

      <section id="next-steps" data-section className="scroll-mt-20">
        <SectionTitle title="Next Steps" />
        <div className="mt-5 grid grid-cols-1 gap-4 md:grid-cols-3">
          <NextStepCard
            href="/docs/detection-rules"
            icon={<Zap size={24} aria-hidden="true" />}
            title="Detection Rules"
            desc="Understand how Rule 1, 2, and 3 score transactions"
          />
          <NextStepCard
            href="/docs/sdk-reference"
            icon={<Plug size={24} aria-hidden="true" />}
            title="SDK Integration"
            desc="Add SentinelGuard to your protocol in 3 lines"
          />
          <NextStepCard
            href="/docs/websocket-feed"
            icon={<Globe size={24} aria-hidden="true" />}
            title="Public Threat Feed"
            desc="Consume live alerts with no API key required"
          />
        </div>
      </section>

    </article>
  );
}

function HowItWorksContent() {
  return (
    <article className="mx-auto max-w-4xl px-6 py-10">
      <Breadcrumb items={['Docs', 'Core Concepts', 'How Detection Works']} />

      <div className="mb-12">
        <div className="mb-4 inline-flex items-center rounded-full bg-[#EFF6FF] px-3 py-1.5">
          <span className="text-[11px] font-semibold uppercase tracking-[0.14em] text-[#2563EB]">
            HOW IT WORKS
          </span>
        </div>
        <h1 className="max-w-3xl text-[36px] font-bold tracking-tight text-[#0F172A]">
          Detection, Scoring, and Response
        </h1>
        <p className="mt-4 max-w-3xl text-[16px] leading-7 text-[#64748B]">
          SentinelGuard moves from raw transaction to on-chain pause inside a single Solana slot
          — no human in the loop.
        </p>
      </div>

      <section id="signal-intake" data-section className="mb-12 scroll-mt-20">
        <SectionTitle title="Signal Intake" />
        <div className="mt-4 space-y-4">
          <p className="text-[14px] leading-7 text-[#64748B]">
            The watcher subscribes to Solana transaction activity via Helius Geyser gRPC. Every
            slot fires a callback. Each transaction is parsed into a ParsedTransaction struct
            containing token deltas, program IDs, log messages, and signer addresses.
          </p>
          <CodeBlock lang="rust" filename="parsed_transaction.rs">
            <span className="text-[#93C5FD]">struct</span>{' '}
            <span className="text-[#E2E8F0]">ParsedTransaction</span>{' '}
            <span className="text-[#E2E8F0]">{'{'}</span>{'\n'}
            {'    '}<span className="text-[#E2E8F0]">signature</span>: <span className="text-[#93C5FD]">String</span>,{'\n'}
            {'    '}<span className="text-[#E2E8F0]">slot</span>: <span className="text-[#93C5FD]">u64</span>,{'\n'}
            {'    '}<span className="text-[#E2E8F0]">program_ids</span>: <span className="text-[#93C5FD]">Vec</span>&lt;<span className="text-[#E2E8F0]">Pubkey</span>&gt;,{'\n'}
            {'    '}<span className="text-[#E2E8F0]">log_messages</span>: <span className="text-[#93C5FD]">Vec</span>&lt;<span className="text-[#93C5FD]">String</span>&gt;,{'\n'}
            {'    '}<span className="text-[#E2E8F0]">token_deltas</span>: <span className="text-[#E2E8F0]">HashMap</span>&lt;<span className="text-[#E2E8F0]">Pubkey</span>, <span className="text-[#93C5FD]">i64</span>&gt;,{'\n'}
            {'    '}<span className="text-[#E2E8F0]">signer</span>: <span className="text-[#E2E8F0]">Option</span>&lt;<span className="text-[#E2E8F0]">Pubkey</span>&gt;,{'\n'}
            <span className="text-[#E2E8F0]">{'}'}</span>
          </CodeBlock>
          <div className="rounded-lg border-l-[3px] border-[#2563EB] bg-[#EFF6FF] p-4">
            <p className="text-[14px] leading-7 text-[#1E40AF]">
              Helius is used as a Geyser-compatible devnet substitute. In production, this would
              be a direct Yellowstone gRPC connection.
            </p>
          </div>
        </div>
      </section>

      <section id="rolling-window-engine" data-section className="mb-12 scroll-mt-20">
        <SectionTitle title="Rolling Window Engine" />
        <div className="mt-4 space-y-4">
          <p className="text-[14px] leading-7 text-[#64748B]">
            SentinelGuard maintains a 10-slot rolling window per monitored protocol. Each slot,
            TVL is recalculated from token delta aggregation. The window tracks:
          </p>
          <ul className="list-disc space-y-2 pl-5 text-[14px] leading-7 text-[#64748B]">
            <li><span className="font-medium text-[#0F172A]">peak_tvl</span> — highest TVL seen since monitoring started</li>
            <li><span className="font-medium text-[#0F172A]">current_tvl</span> — sum of all token deltas in latest slot</li>
            <li><span className="font-medium text-[#0F172A]">slot_history</span> — ring buffer of last 10 TVL snapshots</li>
            <li><span className="font-medium text-[#0F172A]">bridge_outflow_avg</span> — rolling average of bridge transfers</li>
          </ul>
          <div className="rounded-lg bg-[#F1F5F9] p-4">
            <p className="font-mono text-[11px] font-semibold uppercase tracking-[0.12em] text-[#64748B]">
              Key Invariant
            </p>
            <p className="mt-2 text-[14px] leading-7 text-[#475569]">
              TVL baseline is set from first observed slot with activity &gt; $50k. This prevents
              cold-start false positives on protocol initialization.
            </p>
          </div>
        </div>
      </section>

      <section id="detection-rules" data-section className="mb-12 scroll-mt-20">
        <SectionTitle title="Detection Rules" />
        <div className="mt-4 space-y-5">
          <p className="text-[14px] leading-7 text-[#64748B]">
            Three rules run simultaneously on every slot. The highest score is used — rules do
            not stack.
          </p>

          <div className="rounded-xl border border-[#E2E8F0] border-l-4 border-l-[#F97316] bg-white p-6 shadow-sm transition-all duration-200 hover:shadow-md">
            <div className="flex flex-wrap items-center gap-2">
              <span className="rounded-full bg-[#FFF7ED] px-2.5 py-1 text-[10px] font-bold uppercase tracking-[0.12em] text-[#F97316]">
                Rule 1
              </span>
              <span className="rounded-md bg-[#F1F5F9] px-2.5 py-1 font-mono text-[11px] text-[#475569]">
                FLASH_LOAN_DRAIN
              </span>
              <span className="ml-auto rounded-full bg-[#FFF7ED] px-2.5 py-1 text-[11px] font-medium text-[#F97316]">
                Score: 40–99
              </span>
            </div>
            <h3 className="mt-4 text-[15px] font-bold text-[#0F172A]">Flash Loan Correlation</h3>
            <p className="mt-2 text-[13px] leading-6 text-[#64748B]">
              Detects flash loan instruction via known program IDs (Solend, Marginfi, Orca) or
              log keywords (&apos;flash_loan&apos;, &apos;FlashLoan&apos;), then checks for TVL drop &gt;15% in
              the same 5-slot window using peak_tvl as baseline.
            </p>
            <p className="mt-4 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-[#94A3B8]">
              Score Formula
            </p>
            <div className="mt-2 inline-flex rounded-md bg-[#F1F5F9] px-3 py-2 font-mono text-[12px] text-[#475569]">
              40 + (drop * 100 * confidence_factor) + same_signer_bonus
            </div>
            <div className="mt-4 flex flex-wrap gap-2">
              <span className="rounded-full bg-[#F1F5F9] px-2.5 py-1 text-[11px] text-[#64748B]">
                same-slot signer match: +15 bonus
              </span>
              <span className="rounded-full bg-[#F1F5F9] px-2.5 py-1 text-[11px] text-[#64748B]">
                confidence_factor: 0.5 – 1.0
              </span>
            </div>
          </div>

          <div className="rounded-xl border border-[#E2E8F0] border-l-4 border-l-[#EF4444] bg-white p-6 shadow-sm transition-all duration-200 hover:shadow-md">
            <div className="flex flex-wrap items-center gap-2">
              <span className="rounded-full bg-[#FEF2F2] px-2.5 py-1 text-[10px] font-bold uppercase tracking-[0.12em] text-[#EF4444]">
                Rule 2
              </span>
              <span className="rounded-md bg-[#F1F5F9] px-2.5 py-1 font-mono text-[11px] text-[#475569]">
                TVL_VELOCITY
              </span>
              <span className="ml-auto rounded-full bg-[#FEF2F2] px-2.5 py-1 text-[11px] font-medium text-[#EF4444]">
                Score: 75–99
              </span>
            </div>
            <h3 className="mt-4 text-[15px] font-bold text-[#0F172A]">TVL Velocity Drop</h3>
            <p className="mt-2 text-[13px] leading-6 text-[#64748B]">
              TVL drops ≥20% within the last 3 slots regardless of flash loan presence. Guards:
              TVL must be above $50k and absolute drop must exceed $10k to filter low-liquidity
              noise.
            </p>
            <p className="mt-4 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-[#94A3B8]">
              Score Formula
            </p>
            <div className="mt-2 inline-flex rounded-md bg-[#F1F5F9] px-3 py-2 font-mono text-[12px] text-[#475569]">
              75 + (drop - 0.20) * 100
            </div>
            <div className="mt-4 flex flex-wrap gap-2">
              <span className="rounded-full bg-[#F1F5F9] px-2.5 py-1 text-[11px] text-[#64748B]">
                min TVL: $50,000
              </span>
              <span className="rounded-full bg-[#F1F5F9] px-2.5 py-1 text-[11px] text-[#64748B]">
                min abs drop: $10,000
              </span>
            </div>
          </div>

          <div className="rounded-xl border border-[#E2E8F0] border-l-4 border-l-[#8B5CF6] bg-white p-6 shadow-sm transition-all duration-200 hover:shadow-md">
            <div className="flex flex-wrap items-center gap-2">
              <span className="rounded-full bg-[#F5F3FF] px-2.5 py-1 text-[10px] font-bold uppercase tracking-[0.12em] text-[#8B5CF6]">
                Rule 3
              </span>
              <span className="rounded-md bg-[#F1F5F9] px-2.5 py-1 font-mono text-[11px] text-[#475569]">
                BRIDGE_SPIKE
              </span>
              <span className="ml-auto rounded-full bg-[#F5F3FF] px-2.5 py-1 text-[11px] font-medium text-[#8B5CF6]">
                Score: 85–95
              </span>
            </div>
            <h3 className="mt-4 text-[15px] font-bold text-[#0F172A]">Bridge Outflow Spike</h3>
            <p className="mt-2 text-[13px] leading-6 text-[#64748B]">
              Bridge transfer volume exceeds 10x the rolling average in the current slot.
              Designed to catch exfiltration after a drain even if TVL impact is delayed
              cross-chain.
            </p>
            <p className="mt-4 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-[#94A3B8]">
              Score Formula
            </p>
            <div className="mt-2 inline-flex flex-col rounded-md bg-[#F1F5F9] px-3 py-2 font-mono text-[12px] text-[#475569]">
              <span>10–20x multiplier → 85</span>
              <span>20x+ multiplier → 95</span>
            </div>
          </div>
        </div>
      </section>

      <section id="severity-threshold" data-section className="mb-12 scroll-mt-20">
        <SectionTitle title="Severity Threshold" />
        <div className="mt-4 space-y-4">
          <p className="text-[14px] leading-7 text-[#64748B]">
            After all three rules evaluate, the watcher compares the highest score against
            MIN_SEVERITY_TO_PAUSE (default: 60). Scores below this are logged but do not trigger
            any action.
          </p>
          <div className="overflow-hidden rounded-xl border border-[#E2E8F0] bg-white">
            <table className="w-full border-collapse text-left">
              <thead>
                <tr className="border-b border-[#E2E8F0] bg-white">
                  <th className="px-4 py-3 text-[12px] font-semibold uppercase tracking-[0.08em] text-[#64748B]">Score Range</th>
                  <th className="px-4 py-3 text-[12px] font-semibold uppercase tracking-[0.08em] text-[#64748B]">Classification</th>
                  <th className="px-4 py-3 text-[12px] font-semibold uppercase tracking-[0.08em] text-[#64748B]">Action</th>
                </tr>
              </thead>
              <tbody>
                {[
                  ['40–59', 'LOW', 'Logged to Kafka only', 'bg-white'],
                  ['60–74', 'MEDIUM', 'Alert published, no pause', 'bg-[#FFFBEB]'],
                  ['75–89', 'HIGH', 'Alert + webhook', 'bg-[#FFF7ED]'],
                  ['90–99', 'CRITICAL', 'Alert + webhook + on-chain pause', 'bg-[#FEF2F2]'],
                ].map(([range, classification, action, rowClass]) => (
                  <tr key={range} className={`border-b border-[#E2E8F0] last:border-b-0 ${rowClass}`}>
                    <td className="px-4 py-3 text-[13px] text-[#0F172A]">{range}</td>
                    <td className="px-4 py-3 text-[13px] font-medium text-[#0F172A]">{classification}</td>
                    <td className="px-4 py-3 text-[13px] text-[#64748B]">{action}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </section>

      <section id="alert-lifecycle" data-section className="mb-12 scroll-mt-20">
        <SectionTitle title="Alert Lifecycle" />
        <div className="mt-5 space-y-0">
          {[
            [
              '#2563EB',
              'Transaction Received',
              'Geyser stream fires callback. ParsedTransaction built from slot data. Signer, deltas, program IDs extracted.',
            ],
            [
              '#2563EB',
              'Rule Engine Scores',
              'All 3 rules evaluate simultaneously on 10-slot window. Highest score selected. confidence = 0 if score < 40.',
            ],
            [
              '#F97316',
              'Alert Threshold Check',
              'Score compared to MIN_SEVERITY_TO_PAUSE. Redis key checked for cooldown (key: sentinel:cooldown:{protocol}:{rule}). Duplicate suppressed if within 30s window.',
            ],
            [
              '#EF4444',
              'On-chain Pause',
              'pause_withdrawals CPI submitted using watcher keypair. Anchor program validates signer, sets paused = true on SentinelState PDA. Tx confirmed before webhook fires.',
            ],
            [
              '#22C55E',
              'Webhooks + Kafka',
              'Elysia dispatcher fans out to Discord, Circle, Wormhole via Promise.allSettled. Kafka event published with full alert payload for audit trail.',
            ],
          ].map(([color, title, body], index, array) => (
            <div key={title} className="flex gap-4">
              <div className="flex w-5 flex-col items-center">
                <span
                  className={`mt-1 h-3 w-3 rounded-full ${(color === '#EF4444' || color === '#F97316') ? 'animate-pulse' : ''}`}
                  style={{ backgroundColor: color as string }}
                />
                {index < array.length - 1 ? <div className="mt-2 h-full w-0.5 bg-[#E2E8F0]" /> : null}
              </div>
              <div className="pb-8">
                <h3 className="text-[15px] font-semibold text-[#0F172A]">{title}</h3>
                <p className="mt-2 text-[14px] leading-7 text-[#64748B]">{body}</p>
              </div>
            </div>
          ))}
        </div>
      </section>

      <section id="automated-defense" data-section className="mb-12 scroll-mt-20">
        <SectionTitle title="Automated Defense" />
        <div className="mt-4 space-y-4">
          <p className="text-[14px] leading-7 text-[#64748B]">
            The on-chain pause is the terminal action. Once paused = true is set on the
            SentinelState PDA, the mock_protocol vault rejects all withdrawal instructions until
            an authorized keypair resets it.
          </p>
          <div className="rounded-lg border-l-[3px] border-[#F59E0B] bg-[#FFFBEB] p-4">
            <p className="text-[14px] leading-7 text-[#92400E]">
              The watcher keypair must be pre-authorized in the Anchor program via the
              authorized_watcher field on SentinelState. Deploying without this set causes all
              pause CPIs to fail silently.
            </p>
          </div>
          <CodeBlock lang="rust" filename="sentinel_state.rs">
            <span className="text-[#64748B]">{'// SentinelState PDA layout'}</span>{'\n'}
            <span className="text-[#93C5FD]">pub struct</span>{' '}
            <span className="text-[#E2E8F0]">SentinelState</span>{' '}
            <span className="text-[#E2E8F0]">{'{'}</span>{'\n'}
            {'    '}<span className="text-[#93C5FD]">pub</span> <span className="text-[#E2E8F0]">paused</span>: <span className="text-[#93C5FD]">bool</span>,{'\n'}
            {'    '}<span className="text-[#93C5FD]">pub</span> <span className="text-[#E2E8F0]">authorized_watcher</span>: <span className="text-[#E2E8F0]">Pubkey</span>,{'\n'}
            {'    '}<span className="text-[#93C5FD]">pub</span> <span className="text-[#E2E8F0]">last_alert_slot</span>: <span className="text-[#93C5FD]">u64</span>,{'\n'}
            {'    '}<span className="text-[#93C5FD]">pub</span> <span className="text-[#E2E8F0]">bump</span>: <span className="text-[#93C5FD]">u8</span>,{'\n'}
            <span className="text-[#E2E8F0]">{'}'}</span>
          </CodeBlock>
        </div>
      </section>

      <section id="next-steps" data-section className="scroll-mt-20">
        <SectionTitle title="Next Steps" />
        <div className="mt-6 grid grid-cols-1 gap-4 sm:grid-cols-3">
          <NextStepCard
            href="/docs/detection-rules"
            icon={<Zap size={24} aria-hidden="true" />}
            title="Detection Rules"
            desc="See exact score formulas and guard conditions for all three rules."
          />
          <NextStepCard
            href="/docs/sdk-reference"
            icon={<Code2 size={24} aria-hidden="true" />}
            title="SDK Integration"
            desc="Add SentinelGuard to your protocol in 3 lines."
          />
          <NextStepCard
            href="/docs/how-it-works#alert-lifecycle"
            icon={<Radar size={24} aria-hidden="true" />}
            title="Alert Lifecycle"
            desc="Full flow from slot event to on-chain pause."
          />
        </div>
      </section>
    </article>
  );
}

function DetectionRulesContent() {
  return (
    <article className="mx-auto max-w-4xl px-6 py-10">
      <Breadcrumb items={['Docs', 'Core Concepts', 'Detection Rules']} />

      <div className="mb-12">
        <div className="mb-4 inline-flex items-center rounded-full bg-[#EFF6FF] px-3 py-1.5">
          <span className="text-[11px] font-semibold uppercase tracking-[0.14em] text-[#2563EB]">
            DETECTION RULES
          </span>
        </div>
        <h1 className="max-w-3xl text-[36px] font-bold tracking-tight text-[#0F172A]">
          The Three Core Detection Rules
        </h1>
        <p className="mt-4 max-w-3xl text-[16px] leading-7 text-[#64748B]">
          SentinelGuard does not rely on a single exploit signature. Three rule families run
          simultaneously per slot — highest score wins. Rules do not stack.
        </p>
      </div>

      <section id="flash-loan-drain" data-section className="mb-14 scroll-mt-20">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[#E2E8F0] pb-3">
          <h2 className="text-[24px] font-bold tracking-tight text-[#0F172A]">
            Rule 1: Flash Loan Drain
          </h2>
          <span className="rounded-md bg-[#F1F5F9] px-3 py-1 font-mono text-[12px] text-[#64748B]">
            FLASH_LOAN_DRAIN
          </span>
        </div>
        <p className="mt-4 text-[14px] leading-7 text-[#64748B]">
          Correlates flash loan program invocation with a TVL drop &gt;15% in the same 5-slot
          window.
        </p>

        <div className="mt-5 rounded-xl border border-[#E2E8F0] border-l-4 border-l-[#F97316] bg-white p-6 shadow-sm">
          <p className="mb-3 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-[#94A3B8]">
            Trigger Conditions
          </p>
          <div className="grid gap-6 md:grid-cols-2">
            <div>
              <p className="text-[14px] font-semibold text-[#0F172A]">Flash Loan Detected if:</p>
              <ul className="mt-3 list-disc space-y-2 pl-5 text-[13px] leading-6 text-[#64748B]">
                <li>
                  Program ID matches known list:
                  <ul className="mt-2 list-disc space-y-1 pl-5">
                    <li>Solend: So1endDq2YkqhipRh3WViPa8hdiSpxWy6z3Z6tMCpAo</li>
                    <li>Marginfi: MFv2hWf31Z9kbCa1snEPdcgp168vLs2YzvYWZbe83Er</li>
                    <li>Orca: 9W959DqEETiGZocYWCQPaJ6sBmUzgfxXfqGeTEdp3aQP</li>
                  </ul>
                </li>
                <li>OR log message contains &apos;flash_loan&apos; or &apos;FlashLoan&apos;</li>
              </ul>
            </div>
            <div>
              <p className="text-[14px] font-semibold text-[#0F172A]">TVL Drop Check:</p>
              <ul className="mt-3 list-disc space-y-2 pl-5 text-[13px] leading-6 text-[#64748B]">
                <li>Drop &gt; 15% from peak_tvl baseline</li>
                <li>Within same 5-slot window as flash loan detection</li>
                <li>peak_tvl set from highest observed TVL</li>
              </ul>
            </div>
          </div>
        </div>

        <div className="mt-5 rounded-xl bg-[#0F172A] p-6">
          <p className="mb-3 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-[#94A3B8]">
            Score Formula
          </p>
          <pre className="overflow-x-auto text-[13px] leading-6 text-[#E2E8F0]">
{`base_score = 40
drop_bonus  = tvl_drop_pct * 100 * confidence_factor
signer_bonus = 15  // if flash loan signer == drain signer

final_score = base_score + drop_bonus + signer_bonus

// confidence_factor range: 0.5 – 1.0
// final_score clamped to 99`}
          </pre>
          <div className="mt-4 flex flex-wrap gap-2">
            <span className="rounded-full bg-[#FFF7ED] px-3 py-1 text-[12px] font-medium text-[#F97316]">
              Score: 40–99
            </span>
            <span className="rounded-full bg-[#F1F5F9] px-3 py-1 text-[12px] font-medium text-[#64748B]">
              Window: 5 slots
            </span>
          </div>
        </div>

        <div className="mt-5 rounded-xl border border-[#E2E8F0] bg-[#F8F9FC] p-5">
          <p className="mb-3 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-[#94A3B8]">
            False Positive Guards
          </p>
          <ul className="list-disc space-y-2 pl-5 text-[13px] leading-6 text-[#64748B]">
            <li>
              Jupiter and Raydium swap program IDs are excluded — legitimate swaps triggered false
              positives in v1.3
            </li>
            <li>
              confidence_factor drops to 0.5 if only log keyword match (no program ID match)
            </li>
            <li>
              same_signer_bonus only applied if signer is non-null and matches across both
              instructions
            </li>
          </ul>
        </div>
      </section>

      <section id="tvl-velocity" data-section className="mb-14 scroll-mt-20">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[#E2E8F0] pb-3">
          <h2 className="text-[24px] font-bold tracking-tight text-[#0F172A]">
            Rule 2: TVL Velocity Drop
          </h2>
          <span className="rounded-md bg-[#F1F5F9] px-3 py-1 font-mono text-[12px] text-[#64748B]">
            TVL_VELOCITY
          </span>
        </div>
        <p className="mt-4 text-[14px] leading-7 text-[#64748B]">
          Fires when TVL drops ≥20% across 3 consecutive slots, independent of flash loan
          detection.
        </p>

        <div className="mt-5 rounded-xl border border-[#E2E8F0] border-l-4 border-l-[#EF4444] bg-white p-6 shadow-sm">
          <p className="mb-3 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-[#94A3B8]">
            Trigger Conditions
          </p>
          <ul className="list-disc space-y-2 pl-5 text-[13px] leading-6 text-[#64748B]">
            <li>tvl_drop_pct &gt;= 0.20 in last 3 slots</li>
            <li>current_tvl &gt; $50,000 (low-liquidity filter)</li>
            <li>absolute_drop &gt; $10,000 (noise floor filter)</li>
            <li>No flash loan required — standalone signal</li>
          </ul>
        </div>

        <div className="mt-5 rounded-xl bg-[#0F172A] p-6">
          <p className="mb-3 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-[#94A3B8]">
            Score Formula
          </p>
          <pre className="overflow-x-auto text-[13px] leading-6 text-[#E2E8F0]">
{`base_score = 75
velocity_bonus = (tvl_drop_pct - 0.20) * 100

final_score = base_score + velocity_bonus
// clamped to 99`}
          </pre>
          <div className="mt-4 flex flex-wrap gap-2">
            <span className="rounded-full bg-[#FEF2F2] px-3 py-1 text-[12px] font-medium text-[#EF4444]">
              Score: 75–99
            </span>
            <span className="rounded-full bg-[#F1F5F9] px-3 py-1 text-[12px] font-medium text-[#64748B]">
              Window: 3 slots
            </span>
          </div>
        </div>

        <div className="mt-5 rounded-xl border border-[#E2E8F0] bg-[#F8F9FC] p-5">
          <p className="mb-3 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-[#94A3B8]">
            False Positive Guards
          </p>
          <ul className="list-disc space-y-2 pl-5 text-[13px] leading-6 text-[#64748B]">
            <li>Requires TVL &gt; $50k — ignores micro-protocol noise</li>
            <li>Requires absolute drop &gt; $10k regardless of percentage</li>
            <li>Does not trigger on first 3 slots of monitoring (window not yet full)</li>
          </ul>
        </div>
      </section>

      <section id="bridge-spike" data-section className="mb-14 scroll-mt-20">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[#E2E8F0] pb-3">
          <h2 className="text-[24px] font-bold tracking-tight text-[#0F172A]">
            Rule 3: Bridge Outflow Spike
          </h2>
          <span className="rounded-md bg-[#F1F5F9] px-3 py-1 font-mono text-[12px] text-[#64748B]">
            BRIDGE_SPIKE
          </span>
        </div>
        <p className="mt-4 text-[14px] leading-7 text-[#64748B]">
          Flags post-drain exfiltration — outflow volume exceeds 10x the rolling average in the
          current slot.
        </p>

        <div className="mt-5 rounded-xl border border-[#E2E8F0] border-l-4 border-l-[#8B5CF6] bg-white p-6 shadow-sm">
          <p className="mb-3 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-[#94A3B8]">
            Trigger Conditions
          </p>
          <ul className="list-disc space-y-2 pl-5 text-[13px] leading-6 text-[#64748B]">
            <li>bridge_outflow &gt; bridge_outflow_avg * 10</li>
            <li>bridge_outflow_avg computed over last 10 slots</li>
            <li>Catches exfiltration even if TVL impact is delayed</li>
          </ul>
        </div>

        <div className="mt-5 rounded-xl bg-[#0F172A] p-6">
          <p className="mb-3 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-[#94A3B8]">
            Score Formula
          </p>
          <pre className="overflow-x-auto text-[13px] leading-6 text-[#E2E8F0]">
{`if multiplier >= 20:
    score = 95
elif multiplier >= 10:
    score = 85
else:
    score = 0  // rule does not fire`}
          </pre>
          <div className="mt-4 flex flex-wrap gap-2">
            <span className="rounded-full bg-[#F5F3FF] px-3 py-1 text-[12px] font-medium text-[#8B5CF6]">
              Score: 85–95
            </span>
            <span className="rounded-full bg-[#F1F5F9] px-3 py-1 text-[12px] font-medium text-[#64748B]">
              Multiplier: 10x+
            </span>
          </div>
        </div>

        <div className="mt-5 rounded-xl border border-[#E2E8F0] bg-[#F8F9FC] p-5">
          <p className="mb-3 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-[#94A3B8]">
            False Positive Guards
          </p>
          <ul className="list-disc space-y-2 pl-5 text-[13px] leading-6 text-[#64748B]">
            <li>
              bridge_outflow_avg must have at least 5 slots of history before rule activates
            </li>
            <li>
              Zero-outflow baseline slots are included in average to prevent cold-start spikes
            </li>
          </ul>
        </div>
      </section>

      <section id="severity-model" data-section className="scroll-mt-20">
        <SectionTitle title="Severity Model" />
        <p className="mt-4 text-[14px] leading-7 text-[#64748B]">
          After all three rules evaluate, highest score is taken. Score drives classification
          and automated response.
        </p>

        <div className="mt-5 overflow-hidden rounded-xl border border-[#E2E8F0] bg-white">
          <table className="w-full border-collapse text-left">
            <thead>
              <tr className="border-b border-[#E2E8F0] bg-white">
                <th className="px-4 py-3 text-[12px] font-semibold uppercase tracking-[0.08em] text-[#64748B]">Score</th>
                <th className="px-4 py-3 text-[12px] font-semibold uppercase tracking-[0.08em] text-[#64748B]">Classification</th>
                <th className="px-4 py-3 text-[12px] font-semibold uppercase tracking-[0.08em] text-[#64748B]">Alert Published</th>
                <th className="px-4 py-3 text-[12px] font-semibold uppercase tracking-[0.08em] text-[#64748B]">On-chain Pause</th>
              </tr>
            </thead>
            <tbody>
              {[
                ['0–39', 'NONE', 'No', 'No', 'bg-white'],
                ['40–59', 'LOW', 'No', 'No', 'bg-white'],
                ['60–74', 'MEDIUM', 'Yes', 'No', 'bg-[#FFFBEB]'],
                ['75–89', 'HIGH', 'Yes', 'No', 'bg-[#FFF7ED]'],
                ['90–99', 'CRITICAL', 'Yes', 'Yes', 'bg-[#FEF2F2]'],
              ].map(([score, classification, alertPublished, onChainPause, rowClass]) => (
                <tr key={score} className={`border-b border-[#E2E8F0] last:border-b-0 ${rowClass}`}>
                  <td className="px-4 py-3 text-[13px] text-[#0F172A]">{score}</td>
                  <td className="px-4 py-3 text-[13px] font-medium text-[#0F172A]">{classification}</td>
                  <td className="px-4 py-3 text-[13px] text-[#64748B]">{alertPublished}</td>
                  <td className="px-4 py-3 text-[13px] text-[#64748B]">{onChainPause}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="mt-5 rounded-lg border-l-[3px] border-[#2563EB] bg-[#EFF6FF] p-4">
          <p className="text-[14px] leading-7 text-[#1E40AF]">
            MIN_SEVERITY_TO_PAUSE defaults to 60. Set in config/default.toml. Lowering below 60
            significantly increases false positive pause rate in high-volume pools.
          </p>
        </div>

        <div id="next-steps" data-section className="mt-10">
          <SectionTitle title="Next Steps" />
          <div className="mt-6 grid grid-cols-1 gap-4 sm:grid-cols-3">
            <NextStepCard
              href="/docs/how-it-works"
              icon={<Zap size={24} aria-hidden="true" />}
              title="How Detection Works"
              desc="See the full signal intake and rule engine pipeline."
            />
            <NextStepCard
              href="/docs/sdk-reference"
              icon={<Code2 size={24} aria-hidden="true" />}
              title="SDK Integration"
              desc="Wire SentinelGuard into your protocol in 3 lines."
            />
            <NextStepCard
              href="/docs/how-it-works#alert-lifecycle"
              icon={<Radar size={24} aria-hidden="true" />}
              title="Alert Lifecycle"
              desc="From scored alert to on-chain pause — full flow."
            />
          </div>
        </div>
      </section>
    </article>
  );
}

function ProtocolRegistrationContent() {
  return (
    <article className="mx-auto max-w-4xl px-6 py-10">
      <Breadcrumb items={['Docs', 'Integration', 'Protocol Registration']} />
      <div className="mb-12">
        <div className="mb-4 inline-flex items-center rounded-full bg-[#EFF6FF] px-3 py-1.5">
          <span className="text-[11px] font-semibold uppercase tracking-[0.14em] text-[#2563EB]">INTEGRATION</span>
        </div>
        <h1 className="max-w-3xl text-[36px] font-bold tracking-tight text-[#0F172A]">Protocol Registration</h1>
        <p className="mt-4 max-w-3xl text-[16px] leading-7 text-[#64748B]">Initialize the SentinelState PDA to authorize the off-chain watcher to pause your protocol.</p>
      </div>
      <section id="the-sentinelstate-pda" data-section className="mb-12 scroll-mt-20">
        <SectionTitle title="1. The SentinelState PDA" />
        <p className="mt-4 text-[14px] leading-7 text-[#64748B]">To allow SentinelGuard to protect your vaults, your program must expose a PDA that stores the pause state and the authorized watcher key.</p>
        <div className="mt-5">
          <CodeBlock lang="rust" filename="state.rs">
{`#[account]
pub struct SentinelState {
    pub paused: bool,
    pub authorized_watcher: Pubkey,
    pub last_alert_slot: u64,
    pub bump: u8,
}`}
          </CodeBlock>
        </div>
      </section>
      <section id="initialization-instruction" data-section className="mb-12 scroll-mt-20">
        <SectionTitle title="2. Initialization Instruction" />
        <p className="mt-4 text-[14px] leading-7 text-[#64748B]">Create an instruction that the protocol admin calls once during setup.</p>
        <div className="mt-5">
          <CodeBlock lang="rust" filename="instructions/init.rs">
{`#[derive(Accounts)]
pub struct InitializeSentinel<'info> {
    #[account(mut)]
    pub admin: Signer<'info>,
    #[account(
        init,
        payer = admin,
        space = 8 + 1 + 32 + 8 + 1,
        seeds = [b"sentinel_state"],
        bump
    )]
    pub sentinel_state: Account<'info, SentinelState>,
    pub system_program: Program<'info, System>,
}

pub fn initialize_sentinel(ctx: Context<InitializeSentinel>, watcher_key: Pubkey) -> Result<()> {
    let state = &mut ctx.accounts.sentinel_state;
    state.paused = false;
    state.authorized_watcher = watcher_key;
    state.last_alert_slot = 0;
    state.bump = ctx.bumps.sentinel_state;
    Ok(())
}`}
          </CodeBlock>
        </div>
      </section>

      <section id="pause-instruction" data-section className="mb-12 scroll-mt-20">
        <SectionTitle title="3. Pause Instruction" />
        <p className="mt-4 text-[14px] leading-7 text-[#64748B]">
          Expose a <code>pause_withdrawals</code> instruction that the off-chain watcher calls via CPI when a critical alert fires. The <code>constraint</code> ensures only the authorized watcher keypair can trigger it.
        </p>
        <div className="mt-5">
          <CodeBlock lang="rust" filename="instructions/pause.rs">
{`#[derive(Accounts)]
pub struct PauseWithdrawals<'info> {
    pub watcher: Signer<'info>,
    #[account(
        mut,
        seeds = [b"sentinel_state"],
        bump = sentinel_state.bump,
        constraint = sentinel_state.authorized_watcher == watcher.key()
            @ ErrorCode::UnauthorizedWatcher
    )]
    pub sentinel_state: Account<'info, SentinelState>,
}

pub fn pause_withdrawals(ctx: Context<PauseWithdrawals>) -> Result<()> {
    let state = &mut ctx.accounts.sentinel_state;
    state.paused = true;
    state.last_alert_slot = Clock::get()?.slot;
    Ok(())
}`}
          </CodeBlock>
        </div>
        <div className="mt-4 rounded-lg border-l-[3px] border-[#F59E0B] bg-[#FFFBEB] p-4">
          <p className="text-[14px] leading-7 text-[#92400E]">
            The watcher keypair must match <code>authorized_watcher</code> set during initialization. If the keys don't match, the CPI fails and the pause does not execute.
          </p>
        </div>
      </section>

      <section id="circuit-breaker" data-section className="mb-12 scroll-mt-20">
        <SectionTitle title="4. Circuit Breaker Check" />
        <p className="mt-4 text-[14px] leading-7 text-[#64748B]">
          In every instruction where funds leave your protocol — <code>withdraw</code>, <code>borrow</code>, <code>flash_loan</code> — pass the <code>SentinelState</code> account and assert it is not paused. This is a single <code>require!</code> at the top of the handler.
        </p>
        <div className="mt-5">
          <CodeBlock lang="rust" filename="instructions/withdraw.rs">
{`#[derive(Accounts)]
pub struct Withdraw<'info> {
    // ... your standard accounts ...

    #[account(
        seeds = [b"sentinel_state"],
        bump = sentinel_state.bump
    )]
    pub sentinel_state: Account<'info, SentinelState>,
}

pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    // Circuit breaker — one line blocks all withdrawals when paused
    require!(!ctx.accounts.sentinel_state.paused, ErrorCode::ProtocolPaused);

    // ... rest of your withdrawal logic unchanged ...
    Ok(())
}`}
          </CodeBlock>
        </div>
        <div className="mt-4 rounded-lg border-l-[3px] border-[#22C55E] bg-[#F0FDF4] p-4">
          <p className="text-[14px] leading-7 text-[#166534]">
            Once <code>paused = true</code> is set on the PDA, every subsequent withdrawal reverts instantly with <code>ProtocolPaused</code> — no further action required until an admin resets the state.
          </p>
        </div>
      </section>
    </article>
  );
}

function SdkReferenceContent() {
  return (
    <article className="mx-auto max-w-4xl px-6 py-10">
      <Breadcrumb items={['Docs', 'Integration', 'SDK Reference']} />
      <div className="mb-12">
        <div className="mb-4 inline-flex items-center rounded-full bg-[#EFF6FF] px-3 py-1.5">
          <span className="text-[11px] font-semibold uppercase tracking-[0.14em] text-[#2563EB]">INTEGRATION</span>
        </div>
        <h1 className="max-w-3xl text-[36px] font-bold tracking-tight text-[#0F172A]">SDK Reference</h1>
        <p className="mt-4 max-w-3xl text-[16px] leading-7 text-[#64748B]">
          The <code>@sentinelguard/sdk</code> npm package gives any TypeScript or JavaScript application instant access to SentinelGuard's real-time threat feed — no infrastructure required.
        </p>
      </div>

      {/* Installation */}
      <section id="installation" data-section className="mb-12 scroll-mt-20">
        <SectionTitle title="Installation" />
        <p className="mt-4 text-[14px] leading-7 text-[#64748B]">Install via your preferred package manager.</p>
        <div className="mt-5 space-y-3">
          <CodeBlock lang="bash" filename="npm">
{`npm install @sentinelguard/sdk`}
          </CodeBlock>
          <CodeBlock lang="bash" filename="yarn">
{`yarn add @sentinelguard/sdk`}
          </CodeBlock>
          <CodeBlock lang="bash" filename="bun">
{`bun add @sentinelguard/sdk`}
          </CodeBlock>
        </div>
      </section>

      {/* Quick Start */}
      <section id="quick-start" data-section className="mb-12 scroll-mt-20">
        <SectionTitle title="Quick Start" />
        <p className="mt-4 text-[14px] leading-7 text-[#64748B]">Create a client and start listening for live exploit alerts in seconds.</p>
        <div className="mt-5">
          <CodeBlock lang="typescript" filename="index.ts">
{`import SentinelClient from '@sentinelguard/sdk';

const client = new SentinelClient();

// Subscribe to real-time alerts for your protocol
const unsubscribe = client.subscribe(
  'YOUR_PROTOCOL_ADDRESS',
  (alert) => {
    console.log(\`Alert fired: \${alert.rule_triggered} — severity \${alert.severity}\`);
    console.log(\`At risk: $\${alert.estimated_at_risk_usd.toLocaleString()}\`);
  }
);

// Later, clean up the WebSocket connection
unsubscribe();`}
          </CodeBlock>
        </div>
      </section>

      {/* SentinelClient */}
      <section id="sentinelclient" data-section className="mb-12 scroll-mt-20">
        <SectionTitle title="SentinelClient" />
        <p className="mt-4 text-[14px] leading-7 text-[#64748B]">The main entry point. By default it connects to the hosted SentinelGuard API — pass a custom <code>SentinelConfig</code> to point at a self-hosted instance.</p>
        <div className="mt-5">
          <CodeBlock lang="typescript" filename="client.ts">
{`import SentinelClient, { SentinelConfig } from '@sentinelguard/sdk';

const config: SentinelConfig = {
  apiUrl: 'https://sentinel-guard-three.vercel.app', // optional, this is the default
  wsUrl:  'wss://sentinel-guard-three.vercel.app',   // optional
};

const client = new SentinelClient(config);`}
          </CodeBlock>
        </div>
        <div className="mt-6 overflow-hidden rounded-xl border border-[#E2E8F0] bg-white">
          <table className="w-full text-left text-[13px]">
            <thead className="bg-[#F8F9FC]">
              <tr className="border-b border-[#E2E8F0]">
                <th className="px-4 py-3 text-[12px] font-semibold uppercase tracking-[0.08em] text-[#64748B]">Config Field</th>
                <th className="px-4 py-3 text-[12px] font-semibold uppercase tracking-[0.08em] text-[#64748B]">Type</th>
                <th className="px-4 py-3 text-[12px] font-semibold uppercase tracking-[0.08em] text-[#64748B]">Description</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#E2E8F0] text-[#0F172A]">
              <tr>
                <td className="px-4 py-3 font-mono text-[#2563EB]">apiUrl</td>
                <td className="px-4 py-3 text-[#64748B]">string?</td>
                <td className="px-4 py-3">Base URL for REST endpoints. Defaults to the hosted API.</td>
              </tr>
              <tr>
                <td className="px-4 py-3 font-mono text-[#2563EB]">wsUrl</td>
                <td className="px-4 py-3 text-[#64748B]">string?</td>
                <td className="px-4 py-3">WebSocket base URL. Defaults to the hosted WebSocket server.</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      {/* Methods */}
      <section id="methods" data-section className="mb-12 scroll-mt-20">
        <SectionTitle title="Methods" />

        {/* subscribe */}
        <div className="mt-6 rounded-xl border border-[#E2E8F0] bg-white p-6">
          <h3 className="font-mono text-[15px] font-semibold text-[#0F172A]">
            subscribe(protocolAddress, onAlert) → {'() => void'}
          </h3>
          <p className="mt-2 text-[13px] leading-6 text-[#64748B]">Opens a WebSocket connection to the live feed and calls <code>onAlert</code> each time an alert arrives for the given protocol address. Returns an <code>unsubscribe</code> function that closes the socket.</p>
          <div className="mt-4">
            <CodeBlock lang="typescript" filename="subscribe.ts">
{`const unsubscribe = client.subscribe(
  '9W95BjbZuXdwf6p7X3bHu3wnMb2R5y7A4K',
  (alert) => {
    if (alert.severity >= 80) {
      triggerEmergencyAlert(alert);
    }
  }
);`}
            </CodeBlock>
          </div>
        </div>

        {/* getAlerts */}
        <div className="mt-4 rounded-xl border border-[#E2E8F0] bg-white p-6">
          <h3 className="font-mono text-[15px] font-semibold text-[#0F172A]">
            getAlerts(protocolAddress) → {'Promise<Alert[]>'}
          </h3>
          <p className="mt-2 text-[13px] leading-6 text-[#64748B]">Fetches historical alerts for a specific protocol address via the REST API.</p>
          <div className="mt-4">
            <CodeBlock lang="typescript" filename="getAlerts.ts">
{`const alerts = await client.getAlerts('9W95BjbZuXdwf6p7X3bHu3wnMb2R5y7A4K');
alerts.forEach((a) => console.log(a.rule_triggered, a.created_at));`}
            </CodeBlock>
          </div>
        </div>

        {/* getThreats */}
        <div className="mt-4 rounded-xl border border-[#E2E8F0] bg-white p-6">
          <h3 className="font-mono text-[15px] font-semibold text-[#0F172A]">
            getThreats() → {'Promise<Alert[]>'}
          </h3>
          <p className="mt-2 text-[13px] leading-6 text-[#64748B]">Returns the full public threat feed — all alerts across all protocols. No API key required.</p>
          <div className="mt-4">
            <CodeBlock lang="typescript" filename="getThreats.ts">
{`const threats = await client.getThreats();
console.log(\`\${threats.length} total threats detected\`);`}
            </CodeBlock>
          </div>
        </div>

        {/* isPaused */}
        <div className="mt-4 rounded-xl border border-[#E2E8F0] bg-white p-6">
          <h3 className="font-mono text-[15px] font-semibold text-[#0F172A]">
            isPaused(protocolAddress) → {'Promise<boolean>'}
          </h3>
          <p className="mt-2 text-[13px] leading-6 text-[#64748B]">Checks whether a protocol is currently in a paused state.</p>
          <div className="mt-4">
            <CodeBlock lang="typescript" filename="isPaused.ts">
{`const paused = await client.isPaused('9W95BjbZuXdwf6p7X3bHu3wnMb2R5y7A4K');
if (paused) {
  console.log('Protocol is currently paused — withdrawals locked.');
}`}
            </CodeBlock>
          </div>
        </div>
      </section>

      {/* Alert type */}
      <section id="alert-type" data-section className="mb-12 scroll-mt-20">
        <SectionTitle title="Alert Type" />
        <p className="mt-4 text-[14px] leading-7 text-[#64748B]">All methods that return alerts use the <code>Alert</code> interface exported from the package.</p>
        <div className="mt-5">
          <CodeBlock lang="typescript" filename="types.ts">
{`import { Alert } from '@sentinelguard/sdk';

interface Alert {
  id: string;                      // Unique alert identifier
  protocol: string;                // Protocol public key
  rule_triggered: string;          // e.g. "FLASH_LOAN_DRAIN"
  severity: number;                // Score 0–99
  estimated_at_risk_usd: number;   // USD value at risk
  on_chain_tx: string | null;      // Transaction signature, if available
  slot: number;                    // Solana slot number
  created_at: string;              // ISO 8601 timestamp
}`}
          </CodeBlock>
        </div>
      </section>

      <div className="mt-5 rounded-lg border-l-[3px] border-[#2563EB] bg-[#EFF6FF] p-4">
        <p className="text-[14px] leading-7 text-[#1E40AF]">The SDK ships full TypeScript typings. Both ESM (<code>import</code>) and CommonJS (<code>require</code>) are supported out of the box.</p>
      </div>
    </article>
  );
}

function WebhookSetupContent() {
  return (
    <article className="mx-auto max-w-4xl px-6 py-10">
      <Breadcrumb items={['Docs', 'Integration', 'Webhook Setup']} />
      <div className="mb-12">
        <div className="mb-4 inline-flex items-center rounded-full bg-[#EFF6FF] px-3 py-1.5">
          <span className="text-[11px] font-semibold uppercase tracking-[0.14em] text-[#2563EB]">INTEGRATION</span>
        </div>
        <h1 className="max-w-3xl text-[36px] font-bold tracking-tight text-[#0F172A]">Webhook Setup</h1>
        <p className="mt-4 max-w-3xl text-[16px] leading-7 text-[#64748B]">Receive immediate notifications in Discord or Telegram when an alert fires.</p>
      </div>

      <section id="discord" data-section className="mb-12 scroll-mt-20">
        <SectionTitle title="Discord" />
        <p className="mt-4 text-[14px] leading-7 text-[#64748B]">
          Create a webhook in your Discord server under <strong>Server Settings → Integrations → Webhooks</strong>, copy the URL, and add it to the watcher environment file.
        </p>
        <div className="mt-5">
          <CodeBlock lang="bash" filename="watcher/.env">
{`DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/12345/abcdef..."`}
          </CodeBlock>
        </div>
        <div className="mt-5">
          <CodeBlock lang="json" filename="discord-payload.json">
{`{
  "embeds": [{
    "title": "🚨 SentinelGuard Alert: CRITICAL",
    "description": "Rule TVL_VELOCITY triggered for protocol 9W95...",
    "color": 16711680,
    "fields": [
      { "name": "Alert ID", "value": "a1b2c3d4", "inline": true },
      { "name": "Score",    "value": "95",       "inline": true },
      { "name": "Slot",     "value": "245012344","inline": true },
      { "name": "At Risk",  "value": "$125,000", "inline": false }
    ]
  }]
}`}
          </CodeBlock>
        </div>
      </section>

      <section id="telegram" data-section className="mb-12 scroll-mt-20">
        <SectionTitle title="Telegram" />
        <p className="mt-4 text-[14px] leading-7 text-[#64748B]">
          Create a bot via <strong>@BotFather</strong> on Telegram to get a bot token, then get your chat ID by messaging <strong>@userinfobot</strong>. Add both to the watcher environment file.
        </p>
        <div className="mt-5">
          <CodeBlock lang="bash" filename="watcher/.env">
{`TELEGRAM_BOT_TOKEN="7123456789:AAHdqTcvCH1vGWJxfSeofShs0K84aaaaaa"
TELEGRAM_CHAT_ID="-1001234567890"`}
          </CodeBlock>
        </div>
        <div className="mt-5">
          <CodeBlock lang="json" filename="telegram-payload.json">
{`{
  "chat_id": "-1001234567890",
  "text": "🚨 SentinelGuard Alert: CRITICAL\n\nRule: TVL_VELOCITY\nScore: 95\nAt Risk: $125,000\nSlot: 245012344\nProtocol: 9W95...",
  "parse_mode": "Markdown"
}`}
          </CodeBlock>
        </div>
        <div className="mt-4 rounded-lg border-l-[3px] border-[#2563EB] bg-[#EFF6FF] p-4">
          <p className="text-[14px] leading-7 text-[#1E40AF]">
            For group chats, the <code>chat_id</code> is negative (starts with <code>-100</code>). For direct messages to a user, it is a positive integer.
          </p>
        </div>
      </section>

      <section id="payload-example" data-section className="mb-12 scroll-mt-20">
        <SectionTitle title="Choosing a Channel" />
        <p className="mt-4 text-[14px] leading-7 text-[#64748B]">You can configure both at the same time — the watcher dispatcher fans out to all configured channels via <code>Promise.allSettled</code>, so a failure in one does not block the other.</p>
        <div className="mt-5 rounded-lg border-l-[3px] border-[#F59E0B] bg-[#FFFBEB] p-4">
          <p className="text-[14px] leading-7 text-[#92400E]">
            If neither <code>DISCORD_WEBHOOK_URL</code> nor <code>TELEGRAM_BOT_TOKEN</code> is set, alerts are still logged internally but no external notification is sent.
          </p>
        </div>
      </section>
    </article>
  );
}

function AlertSchemaContent() {
  return (
    <article className="mx-auto max-w-4xl px-6 py-10">
      <Breadcrumb items={['Docs', 'API Reference', 'Alert Schema']} />
      <div className="mb-12">
        <div className="mb-4 inline-flex items-center rounded-full bg-[#EFF6FF] px-3 py-1.5">
          <span className="text-[11px] font-semibold uppercase tracking-[0.14em] text-[#2563EB]">API REFERENCE</span>
        </div>
        <h1 className="max-w-3xl text-[36px] font-bold tracking-tight text-[#0F172A]">Alert Schema</h1>
        <p className="mt-4 max-w-3xl text-[16px] leading-7 text-[#64748B]">The standardized JSON structure emitted by REST and WebSocket endpoints.</p>
      </div>
      <section id="schema-fields" data-section className="mb-12 scroll-mt-20">
        <SectionTitle title="Schema Fields" />
        <div className="mt-5 overflow-hidden rounded-xl border border-[#E2E8F0] bg-white">
          <table className="w-full text-left">
            <thead className="bg-[#F8F9FC]">
              <tr className="border-b border-[#E2E8F0]">
                <th className="px-4 py-3 text-[12px] font-semibold uppercase tracking-[0.08em] text-[#64748B]">Field</th>
                <th className="px-4 py-3 text-[12px] font-semibold uppercase tracking-[0.08em] text-[#64748B]">Type</th>
                <th className="px-4 py-3 text-[12px] font-semibold uppercase tracking-[0.08em] text-[#64748B]">Description</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#E2E8F0] text-[13px] text-[#0F172A]">
              <tr>
                <td className="px-4 py-3 font-mono text-[#2563EB]">id</td>
                <td className="px-4 py-3 text-[#64748B]">string</td>
                <td className="px-4 py-3">Unique hex identifier for the alert.</td>
              </tr>
              <tr>
                <td className="px-4 py-3 font-mono text-[#2563EB]">protocol</td>
                <td className="px-4 py-3 text-[#64748B]">string</td>
                <td className="px-4 py-3">Public key of the monitored protocol.</td>
              </tr>
              <tr>
                <td className="px-4 py-3 font-mono text-[#2563EB]">rule_triggered</td>
                <td className="px-4 py-3 text-[#64748B]">string</td>
                <td className="px-4 py-3">One of: <code>FLASH_LOAN_DRAIN</code>, <code>TVL_VELOCITY</code>, <code>BRIDGE_SPIKE</code>.</td>
              </tr>
              <tr>
                <td className="px-4 py-3 font-mono text-[#2563EB]">severity</td>
                <td className="px-4 py-3 text-[#64748B]">number</td>
                <td className="px-4 py-3">Calculated score (0–99).</td>
              </tr>
              <tr>
                <td className="px-4 py-3 font-mono text-[#2563EB]">estimated_at_risk_usd</td>
                <td className="px-4 py-3 text-[#64748B]">number</td>
                <td className="px-4 py-3">Estimated USD value affected in the slot.</td>
              </tr>
              <tr>
                <td className="px-4 py-3 font-mono text-[#2563EB]">slot</td>
                <td className="px-4 py-3 text-[#64748B]">number</td>
                <td className="px-4 py-3">The Solana slot number where the event occurred.</td>
              </tr>
              <tr>
                <td className="px-4 py-3 font-mono text-[#2563EB]">on_chain_tx</td>
                <td className="px-4 py-3 text-[#64748B]">string | null</td>
                <td className="px-4 py-3">Transaction signature of the automated pause CPI, if executed.</td>
              </tr>
              <tr>
                <td className="px-4 py-3 font-mono text-[#2563EB]">created_at</td>
                <td className="px-4 py-3 text-[#64748B]">string</td>
                <td className="px-4 py-3">ISO 8601 timestamp.</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section id="example-payload" data-section className="mb-12 scroll-mt-20">
        <SectionTitle title="Example Payload" />
        <p className="mt-4 text-[14px] leading-7 text-[#64748B]">A real alert object returned by the REST API or emitted over the WebSocket feed.</p>
        <div className="mt-5">
          <CodeBlock lang="json" filename="alert.json">
{`{
  "id": "a1b2c3d4e5f6",
  "protocol": "9W95BjbZuXdwf6p7X3bHu3wnMb2R5y7A4K",
  "rule_triggered": "TVL_VELOCITY",
  "severity": 87,
  "estimated_at_risk_usd": 125000,
  "on_chain_tx": "5KtPn1LGuxhFiwjxErkxTb57Jvmh4Me5GA4K9v7FWE1vL4jE8D2m8HrZ3bVtBQzPLr",
  "slot": 245012344,
  "created_at": "2026-05-15T10:23:41.000Z"
}`}
          </CodeBlock>
        </div>
      </section>
    </article>
  );
}

function RestEndpointsContent() {
  return (
    <article className="mx-auto max-w-4xl px-6 py-10">
      <Breadcrumb items={['Docs', 'API Reference', 'REST Endpoints']} />
      <div className="mb-12">
        <div className="mb-4 inline-flex items-center rounded-full bg-[#EFF6FF] px-3 py-1.5">
          <span className="text-[11px] font-semibold uppercase tracking-[0.14em] text-[#2563EB]">API REFERENCE</span>
        </div>
        <h1 className="max-w-3xl text-[36px] font-bold tracking-tight text-[#0F172A]">REST Endpoints</h1>
        <p className="mt-4 max-w-3xl text-[16px] leading-7 text-[#64748B]">Fetch historical alerts and TVL history.</p>
      </div>

      <section id="get-api-alerts" data-section className="mb-12 scroll-mt-20">
        <div className="flex items-center gap-3 border-b border-[#E2E8F0] pb-3">
          <span className="rounded bg-[#16A34A] px-2 py-1 text-[11px] font-bold text-white">GET</span>
          <h2 className="text-[20px] font-semibold tracking-tight text-[#0F172A]">/api/alerts</h2>
        </div>
        <p className="mt-4 text-[14px] leading-7 text-[#64748B]">Returns a paginated list of alerts across all monitored protocols.</p>
        <div className="mt-5 overflow-hidden rounded-xl border border-[#E2E8F0] bg-white">
          <table className="w-full text-left text-[13px]">
            <thead className="bg-[#F8F9FC]">
              <tr className="border-b border-[#E2E8F0] text-[#64748B]">
                <th className="px-4 py-2 font-semibold">Query Parameter</th>
                <th className="px-4 py-2 font-semibold">Description</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#E2E8F0]">
              <tr><td className="px-4 py-3 font-mono text-[#0F172A]">limit</td><td className="px-4 py-3 text-[#64748B]">Results per page (default: 25)</td></tr>
              <tr><td className="px-4 py-3 font-mono text-[#0F172A]">offset</td><td className="px-4 py-3 text-[#64748B]">Pagination offset (default: 0)</td></tr>
              <tr><td className="px-4 py-3 font-mono text-[#0F172A]">protocol</td><td className="px-4 py-3 text-[#64748B]">Filter by protocol pubkey</td></tr>
              <tr><td className="px-4 py-3 font-mono text-[#0F172A]">rule_triggered</td><td className="px-4 py-3 text-[#64748B]">Filter by rule string</td></tr>
              <tr><td className="px-4 py-3 font-mono text-[#0F172A]">min_severity</td><td className="px-4 py-3 text-[#64748B]">Filter by minimum score</td></tr>
              <tr><td className="px-4 py-3 font-mono text-[#0F172A]">search</td><td className="px-4 py-3 text-[#64748B]">Search by Alert ID or tx hash</td></tr>
            </tbody>
          </table>
        </div>
        <div className="mt-5">
          <CodeBlock lang="bash" filename="curl">
{`curl "https://sentinel-guard-three.vercel.app/api/alerts?limit=5&min_severity=75"`}
          </CodeBlock>
        </div>
        <div className="mt-4">
          <CodeBlock lang="json" filename="response">
{`[
  {
    "id": "a1b2c3d4e5f6",
    "protocol": "9W95BjbZuXdwf6p7X3bHu3wnMb2R5y7A4K",
    "rule_triggered": "TVL_VELOCITY",
    "severity": 87,
    "estimated_at_risk_usd": 125000,
    "on_chain_tx": "5KtPn1LGuxhFiwjxErkxTb57Jvmh4Me5GA4K9v7FWE1vL4jE8D2m8HrZ3bVtBQzPLr",
    "slot": 245012344,
    "created_at": "2026-05-15T10:23:41.000Z"
  }
]`}
          </CodeBlock>
        </div>
      </section>

      <section id="get-api-tvl" data-section className="mb-12 scroll-mt-20">
        <div className="flex items-center gap-3 border-b border-[#E2E8F0] pb-3">
          <span className="rounded bg-[#16A34A] px-2 py-1 text-[11px] font-bold text-white">GET</span>
          <h2 className="text-[20px] font-semibold tracking-tight text-[#0F172A]">/api/tvl</h2>
        </div>
        <p className="mt-4 text-[14px] leading-7 text-[#64748B]">Returns TVL snapshot history for a protocol, ordered by slot ascending. Use this to chart TVL over time.</p>
        <div className="mt-5 overflow-hidden rounded-xl border border-[#E2E8F0] bg-white">
          <table className="w-full text-left text-[13px]">
            <thead className="bg-[#F8F9FC]">
              <tr className="border-b border-[#E2E8F0] text-[#64748B]">
                <th className="px-4 py-2 font-semibold">Query Parameter</th>
                <th className="px-4 py-2 font-semibold">Description</th>
              </tr>
            </thead>
            <tbody>
              <tr><td className="px-4 py-3 font-mono text-[#0F172A]">protocol</td><td className="px-4 py-3 text-[#64748B]">Required. Protocol pubkey to fetch.</td></tr>
            </tbody>
          </table>
        </div>
        <div className="mt-5">
          <CodeBlock lang="bash" filename="curl">
{`curl "https://sentinel-guard-three.vercel.app/api/tvl?protocol=9W95BjbZuXdwf6p7X3bHu3wnMb2R5y7A4K"`}
          </CodeBlock>
        </div>
        <div className="mt-4">
          <CodeBlock lang="json" filename="response">
{`[
  { "slot": 245012300, "tvl_usd": 1200000, "timestamp": "2026-05-15T10:20:00.000Z" },
  { "slot": 245012320, "tvl_usd": 1195000, "timestamp": "2026-05-15T10:20:08.000Z" },
  { "slot": 245012344, "tvl_usd": 980000,  "timestamp": "2026-05-15T10:20:17.000Z" }
]`}
          </CodeBlock>
        </div>
      </section>
    </article>
  );
}

function WebSocketFeedContent() {
  return (
    <article className="mx-auto max-w-4xl px-6 py-10">
      <Breadcrumb items={['Docs', 'API Reference', 'WebSocket Feed']} />
      <div className="mb-12">
        <div className="mb-4 inline-flex items-center rounded-full bg-[#EFF6FF] px-3 py-1.5">
          <span className="text-[11px] font-semibold uppercase tracking-[0.14em] text-[#2563EB]">API REFERENCE</span>
        </div>
        <h1 className="max-w-3xl text-[36px] font-bold tracking-tight text-[#0F172A]">WebSocket Feed</h1>
        <p className="mt-4 max-w-3xl text-[16px] leading-7 text-[#64748B]">Consume real-time threats with zero latency.</p>
      </div>
      <section id="sdk-recommended" data-section className="mb-12 scroll-mt-20">
        <SectionTitle title="Recommended: Use the SDK" />
        <p className="mt-4 text-[14px] leading-7 text-[#64748B]">
          The <code>@sentinelguard/sdk</code> package wraps the WebSocket connection and handles reconnection, JSON parsing, and protocol filtering for you. This is the recommended approach for most integrations.
        </p>
        <div className="mt-5">
          <CodeBlock lang="typescript" filename="subscribe.ts">
{`import SentinelClient from '@sentinelguard/sdk';

const client = new SentinelClient();

const unsubscribe = client.subscribe(
  'YOUR_PROTOCOL_ADDRESS',
  (alert) => {
    console.log(\`Alert: \${alert.rule_triggered} — severity \${alert.severity}\`);
  }
);`}
          </CodeBlock>
        </div>
        <div className="mt-4 rounded-lg border-l-[3px] border-[#2563EB] bg-[#EFF6FF] p-4">
          <p className="text-[14px] leading-7 text-[#1E40AF]">
            See the <a href="/docs/sdk-reference" className="underline font-medium">SDK Reference</a> for the full API including <code>getAlerts()</code>, <code>getThreats()</code>, and <code>isPaused()</code>.
          </p>
        </div>
      </section>

      <section id="connection" data-section className="mb-12 scroll-mt-20">
        <SectionTitle title="Raw WebSocket (Advanced)" />
        <p className="mt-4 text-[14px] leading-7 text-[#64748B]">
          Connect directly to the feed endpoint if you need full control or are working in a non-JS environment. No API key is required.
        </p>
        <div className="mt-5">
          <CodeBlock lang="javascript" filename="client.js">
{`const ws = new WebSocket('wss://sentinel-guard-three.vercel.app/feed');

ws.onmessage = (event) => {
  const alert = JSON.parse(event.data);
  console.log(\`New alert! Score: \${alert.severity}\`);
};`}
          </CodeBlock>
        </div>
        <div className="mt-5 rounded-lg border-l-[3px] border-[#F59E0B] bg-[#FFFBEB] p-4">
          <p className="text-[14px] leading-7 text-[#92400E]">Messages match the <a href="/docs/alert-schema" className="underline font-medium">Alert Schema</a>. Pings are sent every 30 seconds to keep the connection alive. You are responsible for reconnect logic when using the raw WebSocket.</p>
        </div>
      </section>
    </article>
  );
}

function FaqContent() {
  return (
    <article className="mx-auto max-w-4xl px-6 py-10">
      <Breadcrumb items={['Docs', 'Resources', 'FAQ']} />
      <div className="mb-12">
        <div className="mb-4 inline-flex items-center rounded-full bg-[#EFF6FF] px-3 py-1.5">
          <span className="text-[11px] font-semibold uppercase tracking-[0.14em] text-[#2563EB]">RESOURCES</span>
        </div>
        <h1 className="max-w-3xl text-[36px] font-bold tracking-tight text-[#0F172A]">Frequently Asked Questions</h1>
      </div>
      <section id="faq-list" data-section>
        <FaqAccordion />
      </section>
    </article>
  );
}

export const DOCS_PAGES: Record<string, DocsPageConfig> = {
  introduction: {
    toc: [
      { id: 'the-problem', label: 'The Problem' },
      { id: 'how-it-fixes-it', label: 'How It Fixes It' },
      { id: 'architecture', label: 'Architecture' },
      { id: 'real-world-reference', label: 'Real World Reference' },
      { id: 'next-steps', label: 'Next Steps' },
    ],
    content: <IntroContent />,
  },
  'quick-start': {
    toc: [
      { id: 'prerequisites', label: 'Prerequisites' },
      { id: 'clone-and-install', label: 'Clone and Install' },
      { id: 'environment-setup', label: 'Environment Setup' },
      { id: 'start-the-watcher', label: 'Start the Watcher' },
      { id: 'test-with-simulation', label: 'Test with Simulation' },
      { id: 'next-steps', label: 'Next Steps' },
    ],
    content: <QuickStartContent />,
  },
  'how-it-works': {
    toc: [
      { id: 'signal-intake', label: 'Signal Intake' },
      { id: 'rolling-window-engine', label: 'Rolling Window Engine' },
      { id: 'detection-rules', label: 'Detection Rules' },
      { id: 'severity-threshold', label: 'Severity Threshold' },
      { id: 'alert-lifecycle', label: 'Alert Lifecycle' },
      { id: 'automated-defense', label: 'Automated Defense' },
      { id: 'next-steps', label: 'Next Steps' },
    ],
    content: <HowItWorksContent />,
  },
  'detection-rules': {
    toc: [
      { id: 'flash-loan-drain', label: 'Flash Loan Drain' },
      { id: 'tvl-velocity', label: 'TVL Velocity' },
      { id: 'bridge-spike', label: 'Bridge Spike' },
      { id: 'severity-model', label: 'Severity Model' },
    ],
    content: <DetectionRulesContent />,
  },
  'sdk-reference': {
    toc: [
      { id: 'installation', label: 'Installation' },
      { id: 'quick-start', label: 'Quick Start' },
      { id: 'sentinelclient', label: 'SentinelClient' },
      { id: 'methods', label: 'Methods' },
      { id: 'alert-type', label: 'Alert Type' },
    ],
    content: <SdkReferenceContent />,
  },
  'webhook-setup': {
    toc: [
      { id: 'discord', label: 'Discord' },
      { id: 'telegram', label: 'Telegram' },
      { id: 'payload-example', label: 'Choosing a Channel' },
    ],
    content: <WebhookSetupContent />,
  },
  'protocol-registration': {
    toc: [
      { id: 'the-sentinelstate-pda', label: '1. SentinelState PDA' },
      { id: 'initialization-instruction', label: '2. Initialization' },
      { id: 'pause-instruction', label: '3. Pause Instruction' },
      { id: 'circuit-breaker', label: '4. Circuit Breaker' },
    ],
    content: <ProtocolRegistrationContent />,
  },
  'rest-endpoints': {
    toc: [
      { id: 'get-api-alerts', label: 'GET /api/alerts' },
      { id: 'get-api-tvl', label: 'GET /api/tvl' },
    ],
    content: <RestEndpointsContent />,
  },

  'websocket-feed': {
    toc: [
      { id: 'sdk-recommended', label: 'Recommended: SDK' },
      { id: 'connection', label: 'Raw WebSocket' },
    ],
    content: <WebSocketFeedContent />,
  },
  'alert-schema': {
    toc: [
      { id: 'schema-fields', label: 'Schema Fields' },
      { id: 'example-payload', label: 'Example Payload' },
    ],
    content: <AlertSchemaContent />,
  },
  'faq': {
    toc: [
      { id: 'faq-list', label: 'Questions' },
    ],
    content: <FaqContent />,
  },
};
