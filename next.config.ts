import type { NextConfig } from "next";

const config: NextConfig = {
  reactStrictMode: true,
  // Never ship past a type or lint error: this is security infrastructure.
  poweredByHeader: false,
  // The project keeps its own agent guide in claude.md; stop `next dev` writing AGENTS.md.
  agentRules: false,
  // No floating Next.js badge in dev; errors still surface in the terminal and console.
  devIndicators: false,
};

export default config;
