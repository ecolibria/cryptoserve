/** @type {import('next').NextConfig} */
const nextConfig = {
  output: "standalone",
  images: {
    remotePatterns: [
      {
        protocol: "https",
        hostname: "avatars.githubusercontent.com",
      },
    ],
  },
  async rewrites() {
    // Use API_URL for server-side (Docker container-to-container)
    // Falls back to NEXT_PUBLIC_API_URL or localhost for local dev
    const apiUrl = process.env.API_URL || process.env.NEXT_PUBLIC_API_URL || "http://localhost:8003";
    return [
      {
        // Proxy API requests to backend to avoid cross-origin cookie issues
        source: "/api/:path*",
        destination: `${apiUrl}/api/:path*`,
      },
      {
        // Proxy auth requests to backend
        source: "/auth/:path*",
        destination: `${apiUrl}/auth/:path*`,
      },
      {
        // Proxy SDK requests to backend
        source: "/sdk/:path*",
        destination: `${apiUrl}/sdk/:path*`,
      },
    ];
  },
};

export default nextConfig;
