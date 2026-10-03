import type { NextConfig } from "next";

// /api/* is proxied to the FastAPI backend. Locally that is :8000; on Vercel
// set BACKEND_URL to the deployed backend (Render, Hetzner, or a tunnel).
const backend = process.env.BACKEND_URL ?? "http://127.0.0.1:8000";

const nextConfig: NextConfig = {
  async rewrites() {
    return [{ source: "/api/:path*", destination: `${backend}/api/:path*` }];
  },
};

export default nextConfig;
