import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  reactCompiler: true,
  images: { unoptimized: true },
};

if (process.env.NODE_ENV === "production") {
  nextConfig.output = "export";
} else {
  nextConfig.rewrites = async () => [
    { source: "/admin/:path*", destination: "http://localhost:3000/admin/:path*" },
    { source: "/xrpc/:path*", destination: "http://localhost:3000/xrpc/:path*" },
    { source: "/health", destination: "http://localhost:3000/health" },
  ];
}

export default nextConfig;
