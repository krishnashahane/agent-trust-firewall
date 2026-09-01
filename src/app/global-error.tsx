"use client";

/**
 * Last-resort boundary: catches failures in the root layout itself, where the
 * normal error boundary cannot mount. It has to render its own <html>/<body>,
 * and cannot rely on the design tokens, so the styles here are deliberately
 * self-contained rather than token-driven.
 */
export default function GlobalError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  return (
    <html lang="en">
      <body
        style={{
          margin: 0,
          minHeight: "100vh",
          display: "grid",
          placeItems: "center",
          background: "#fcfcfd",
          color: "#0d0f14",
          fontFamily:
            "ui-sans-serif, system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif",
        }}
      >
        <main style={{ maxWidth: 460, padding: 24, textAlign: "center" }}>
          <h1 style={{ fontSize: 18, fontWeight: 600, margin: 0 }}>
            Agent Trust Firewall failed to start
          </h1>
          <p style={{ fontSize: 13.5, lineHeight: 1.6, color: "#565d6b" }}>
            The application shell itself errored. Reloading usually clears it.
          </p>
          <button
            type="button"
            onClick={reset}
            style={{
              marginTop: 12,
              padding: "8px 14px",
              fontSize: 13,
              fontWeight: 500,
              color: "#fff",
              background: "#2f5cff",
              border: 0,
              borderRadius: 8,
              cursor: "pointer",
            }}
          >
            Try again
          </button>
          {error.digest ? (
            <p style={{ marginTop: 20, fontSize: 11, color: "#838b99" }}>
              reference {error.digest}
            </p>
          ) : null}
        </main>
      </body>
    </html>
  );
}
