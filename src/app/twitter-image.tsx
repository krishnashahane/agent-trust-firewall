/**
 * The Twitter/X card reuses the Open Graph artwork.
 *
 * `runtime` is declared here rather than re-exported: Next requires that field
 * to be statically analysable in the file that declares the route, and a
 * re-export fails the build.
 */
export { default, alt, size, contentType } from "./opengraph-image";

export const runtime = "nodejs";
