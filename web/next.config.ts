import type { NextConfig } from "next";

const apiBase = process.env.API_URL || "http://localhost:3000";

const nextConfig: NextConfig = {
  reactCompiler: true,
  trailingSlash: true,
  images: { unoptimized: true },
};

if (process.env.NODE_ENV === "production") {
  nextConfig.output = "export";
} else {
  nextConfig.rewrites = async () => ({
    // beforeFiles rewrites run before the trailingSlash redirect,
    // preventing 308s on API fetch calls.
    beforeFiles: [
      { source: "/admin/:path*", destination: `${apiBase}/admin/:path*` },
      { source: "/auth/:path*", destination: `${apiBase}/auth/:path*` },
      { source: "/xrpc/:path*", destination: `${apiBase}/xrpc/:path*` },
      { source: "/health", destination: `${apiBase}/health` },
      { source: "/config", destination: `${apiBase}/config` },
      { source: "/oauth/:path*", destination: `${apiBase}/oauth/:path*` },
      { source: "/external-auth/:path*", destination: `${apiBase}/external-auth/:path*` },
    ],
    afterFiles: [],
    fallback: [],
  });
}

export default nextConfig;
