/** @type {import('next').NextConfig} */
const nextConfig = {
    cacheHandler: require.resolve('./cache-handler.js'),
    cacheMaxMemorySize: 0, // disable default in-memory caching
}

module.exports = nextConfig;
