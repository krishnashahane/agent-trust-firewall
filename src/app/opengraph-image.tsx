import { ImageResponse } from "next/og";

/**
 * The social preview card.
 *
 * Rendered to a real PNG rather than served as SVG: X, Slack, LinkedIn and
 * iMessage all refuse SVG previews, so an SVG here would look identical to
 * having no card at all — which is the bug this fixes.
 *
 * The design mirrors the product's own blocked-verdict card so the preview
 * shows what the site actually does, not a generic logo.
 */
export const runtime = "nodejs";
export const alt =
  "Agent Trust Firewall - a firewall for AI agents. Proves who is calling, cryptographically, and blocks rogue agent calls before they run.";
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

export default function OpengraphImage() {
  return new ImageResponse(
    (
      <div
        style={{
          width: "100%",
          height: "100%",
          display: "flex",
          flexDirection: "column",
          justifyContent: "space-between",
          background: "#fcfcfd",
          padding: "72px 80px",
          fontFamily: "sans-serif",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
          {/* Drawn, not typed. ImageResponse fetches a web font for any glyph
            * outside the bundled set, and a checkmark character made the build
            * reach for a font it could not download. An inline SVG has no such
            * dependency and renders identically everywhere. */}
          <svg width="34" height="34" viewBox="0 0 24 24" fill="none">
            <rect width="24" height="24" rx="6.5" fill="#2f5cff" />
            <path
              d="M7 12.4l3.2 3.2L17 8.8"
              stroke="#ffffff"
              strokeWidth="2.2"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
          <div style={{ fontSize: 25, fontWeight: 600, color: "#0d0f14" }}>
            Agent Trust Firewall
          </div>
        </div>

        <div style={{ display: "flex", flexDirection: "column" }}>
          <div
            style={{
              fontSize: 78,
              fontWeight: 700,
              letterSpacing: -2.6,
              color: "#0d0f14",
              lineHeight: 1.05,
            }}
          >
            A firewall for AI agents.
          </div>
          <div
            style={{
              marginTop: 22,
              fontSize: 27,
              color: "#565d6b",
              lineHeight: 1.45,
              maxWidth: 880,
            }}
          >
            Proves who is calling, cryptographically, and blocks rogue agent calls
            before they run.
          </div>
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 18 }}>
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 16,
              background: "#fdecec",
              border: "1px solid #f4c9c9",
              borderRadius: 12,
              padding: "14px 20px",
              alignSelf: "flex-start",
            }}
          >
            <div
              style={{ width: 9, height: 9, borderRadius: 99, background: "#c22a2a" }}
            />
            <div style={{ fontSize: 21, fontWeight: 600, color: "#c22a2a" }}>
              Blocked
            </div>
            <div style={{ fontSize: 19, color: "#0d0f14" }}>
              payments.charge / $9,900.00
            </div>
          </div>
          <div style={{ fontSize: 18, color: "#838b99" }}>
            Schnorr ZK identity / Merkle capabilities / live threat intel /
            hash-chained audit
          </div>
        </div>
      </div>
    ),
    size,
  );
}
