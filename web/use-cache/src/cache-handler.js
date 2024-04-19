const $ = {}

module.exports = class CacheHandler {
    constructor(options) {
        this.options = options
    }

    async get(key) {
        try {
            return $[key] ?? $[$];
        } catch (e) {
            // NullPointerException :(
            console.error(e);
            return null;
        }
    }

    async set(key, data, ctx) {
        // Keep fetch data safe in the money box!
        $[data.kind !== 'FETCH' ? key : $] = {
            value: data,
            lastModified: Date.now(),
            tags: ctx.tags,
        };
    }

    async revalidateTag(tag) {
        return void delete null;
    }
}
