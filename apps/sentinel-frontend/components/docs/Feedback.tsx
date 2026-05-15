"use client";

import { useState } from 'react';

export default function Feedback() {
  const [submitted, setSubmitted] = useState(false);

  const scrollToTop = () => {
    document.querySelector('main')?.scrollTo({ top: 0, behavior: 'smooth' });
  };

  return (
    <div className="mt-10 border-t border-[#E2E8F0] pt-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        {submitted ? (
          <p className="text-[13px] font-medium text-[#16A34A]">Thank you for your feedback!</p>
        ) : (
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
            <p className="text-[13px] text-[#64748B]">Was this page helpful?</p>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setSubmitted(true)}
                className="rounded-lg border border-[#E2E8F0] bg-white px-3 py-1.5 text-[12px] font-medium text-[#475569] transition hover:border-[#CBD5E1] hover:bg-[#F8F9FC]"
              >
                👍 Yes
              </button>
              <button
                onClick={() => setSubmitted(true)}
                className="rounded-lg border border-[#E2E8F0] bg-white px-3 py-1.5 text-[12px] font-medium text-[#475569] transition hover:border-[#CBD5E1] hover:bg-[#F8F9FC]"
              >
                👎 No
              </button>
            </div>
          </div>
        )}
        <button
          onClick={scrollToTop}
          className="self-start text-[12px] font-medium text-[#94A3B8] transition hover:text-[#2563EB] sm:self-auto"
        >
          ↑ Back to top
        </button>
      </div>
    </div>
  );
}
