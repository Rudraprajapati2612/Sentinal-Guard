'use client';

import { useState } from 'react';
import { ChevronDown } from 'lucide-react';

const FAQS = [
  {
    q: 'Does SentinelGuard require changes to my smart contract?',
    a: 'Yes, two minimal additions are required: (1) a SentinelState PDA initialized once by your admin, and (2) a single require! guard at the top of each withdrawal instruction. No other program logic needs to change.',
  },
  {
    q: 'What happens if the watcher goes offline?',
    a: 'Your protocol continues to function normally. SentinelGuard operates entirely off-chain — its downtime cannot halt or disrupt legitimate user transactions. You simply lose automated pausing until the watcher is restarted.',
  },
  {
    q: 'How do I resume the protocol after an automated pause?',
    a: 'An authorized administrator key must sign a transaction that sets paused = false on the SentinelState PDA. The watcher does not auto-resume — a human must explicitly approve the unpause after reviewing the alert.',
  },
  {
    q: 'What happens to in-flight transactions when a pause occurs?',
    a: 'Any withdrawal transaction that lands after the pause CPI is confirmed will revert with ProtocolPaused. Transactions that were already finalized before the pause complete normally. There is no retroactive effect.',
  },
  {
    q: 'How fast is the pause action?',
    a: 'The watcher consumes a Geyser gRPC stream and evaluates slots in real time. End-to-end — from the malicious transaction hitting the RPC to the pause CPI landing on-chain — the reaction time is typically under 400ms.',
  },
  {
    q: 'Which Solana networks are supported?',
    a: 'The watcher is network-agnostic. Point HELIUS_API_KEY and SENTINEL_PROGRAM_ID at devnet, testnet, or mainnet-beta and it works identically. The public hosted instance runs on devnet for demonstration purposes.',
  },
  {
    q: 'Is there a cost to use SentinelGuard?',
    a: 'The SDK and public threat feed are free. Running the self-hosted watcher requires a Helius API key (free tier covers devnet) and your own PostgreSQL + Redis infrastructure. There is no per-alert fee.',
  },
  {
    q: 'Can I lower the pause threshold below 60 to be more aggressive?',
    a: 'You can via MIN_SEVERITY_TO_PAUSE, but scores below 60 represent LOW-confidence signals where false positive rates increase significantly — especially in high-volume pools with frequent large swaps. We recommend staying at 60 or above in production.',
  },
];

export default function FaqAccordion() {
  const [openIndex, setOpenIndex] = useState<number | null>(null);

  return (
    <div className="divide-y divide-[#E2E8F0] rounded-xl border border-[#E2E8F0] bg-white overflow-hidden">
      {FAQS.map(({ q, a }, i) => {
        const isOpen = openIndex === i;
        return (
          <div key={q}>
            <button
              onClick={() => setOpenIndex(isOpen ? null : i)}
              className="flex w-full items-center justify-between gap-4 px-6 py-4 text-left transition-colors hover:bg-[#F8F9FC]"
            >
              <span className="text-[15px] font-semibold text-[#0F172A]">{q}</span>
              <ChevronDown
                size={16}
                className={`flex-shrink-0 text-[#94A3B8] transition-transform duration-200 ${isOpen ? 'rotate-180' : ''}`}
              />
            </button>
            <div
              className="overflow-hidden transition-all duration-300 ease-in-out"
              style={{ maxHeight: isOpen ? '300px' : '0px' }}
            >
              <p className="px-6 pb-5 pt-1 text-[14px] leading-7 text-[#64748B]">{a}</p>
            </div>
          </div>
        );
      })}
    </div>
  );
}
