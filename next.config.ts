import type { NextConfig } from "next";

const config: NextConfig = {
  reactStrictMode: true,
  // Never ship past a type or lint error: this is security infrastructure.
  poweredByHeader: false,
};

export default config;
