import type { NextConfig } from "next";

const apiBase = process.env.API_URL || "http://localhost:3000";
const aipBase = process.env.AIP_PROXY_URL || "http://localhost:8080";

const nextConfig: NextConfig = {
  reactCompiler: true,
  images: { unoptimized: true },
};

if (process.env.NODE_ENV === "production") {
  nextConfig.output = "export";
} else {
  nextConfig.rewrites = async () => [
    { source: "/admin/:path*", destination: `${apiBase}/admin/:path*` },
    { source: "/xrpc/:path*", destination: `${apiBase}/xrpc/:path*` },
    { source: "/health", destination: `${apiBase}/health` },
    { source: "/aip/:path*", destination: `${aipBase}/:path*` },
    { source: "/config", destination: `${apiBase}/config` },
  ];
}

export default nextConfig;
