import next from "eslint-config-next";

/**
 * eslint-config-next exports a flat-config array in v16, so it is spread
 * directly rather than called.
 */
const config = [
  { ignores: [".next/**", "node_modules/**", "out/**", "next-env.d.ts"] },
  ...next,
];

export default config;
