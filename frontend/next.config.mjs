/** @type {import('next').NextConfig} */
const nextConfig = {
  images: {
    remotePatterns: [
      {
        protocol: "https",
        hostname: "avatars.githubusercontent.com",
      },
    ],
  },
  async rewrites() {
    return [
      {
        // Proxy API requests to backend to avoid cross-origin cookie issues
        source: "/api/:path*",
        destination: `${process.env.NEXT_PUBLIC_API_URL || "http://localhost:8003"}/api/:path*`,
      },
      {
        // Proxy auth requests to backend
        source: "/auth/:path*",
        destination: `${process.env.NEXT_PUBLIC_API_URL || "http://localhost:8003"}/auth/:path*`,
      },
    ];
  },
};

export default nextConfig;
