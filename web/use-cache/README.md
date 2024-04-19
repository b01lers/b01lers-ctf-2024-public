# Writeup for use-cache by ky28059
> `"use cache"`

We're given a pretty standard Next.js project, except it defines a [custom cache handler](https://nextjs.org/docs/app/building-your-application/deploying#configuring-caching)
in `cache-handler.js`.

On the frontend, we're given a form that can pass arbitrary data to some `cachedFetchAction` on the backend.
```tsx
const [state, formAction] = useFormState(cachedFetchAction, null);

return (
    <form
        ref={formRef}
        action={(data) => {
            formAction(data);
            formRef.current?.reset();
        }}
    >
```
Looking in `fetch.ts`, the fetch server action seems to make a fetch to our given URL with our JSON payload and the
flag in the POST body.
```ts
'use server'

import { unstable_cache } from 'next/cache';

const FLAG = process.env.FLAG ?? 'bctf{test_flag}';


async function flagFetch(url: string, body: {}) {
    try {
        const res = await fetch(url, {
            method: 'POST',
            body: JSON.stringify({...body, flag: FLAG})
        });
        return res.text();
    } catch {
        return 'An error occurred :(';
    }
}

export const cachedFetch = unstable_cache(
    flagFetch,
    [FLAG]
);

export const cachedFetchAction = async (_: any, data: FormData) => {
    // Deserialize that pesky JSON data
    const body = coolerJsonParse(data.get('body')!.toString().trim());

    return cachedFetch(
        data.get('url')!.toString(),
        body
    );
}
```
Seems easy, right?

Unfortunately, no matter what URL we fetch all we end up with is
```json
{"message":"Received your flag!"}
```
Looking in `cache-handler.js`,
```js
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
```
In JavaScript, using an object as a key causes JS to stringify it first. Furthermore, the `.toString()` for *any* plain
object returns `'[object Object]'`.
```js
> const obj = {}
undefined
> obj[obj] = 5
5
> obj
{ '[object Object]': 5 }
> obj[{}]
5
```
Then, we can notice a few things:
- All fetches are cached under the same key, namely the object `$` which gets stringified to `[object Object]`.
- When we try to make another fetch, it will check `$[$]` first to see if the fetch is already in the cache. If it is,
it will immediately return the cached response data without making another fetch.

Because all fetches are cached under the same key, only the first `cachedFetch` we make on the backend will actually go
through; the rest will hit the cache.

Even less fortunately, when we load the index page we immediately populate the fetch cache with the response of the
`/api/flag` route handler (the `{message: 'Received your flag!'}` response from earlier).
```tsx
export default async function CacheJail() {
    // $$$
    await cachedFetch(
        'http://localhost:3000/api/flag',
        { balance: 9999 }
    );

    return (
        <main className="flex items-center justify-center h-screen bg-gradient-to-br from-orange-500 via-red-500 to-pink-500">
            <div className="w-full max-w-lg text-white bg-black/30 px-10 py-8 shadow-lg rounded-md">
                <h1 className="text-2xl font-bold mb-1">
                    POST-r
                </h1>
                <p className="text-sm mb-3 text-white/75">
                    The free, online POST request service!
                </p>
                <FetchForm />
            </div>
        </main>
    )
}
```
However, a big hint lies in the cache handler's `get()` method:
```js
async get(key) {
    try {
        return $[key] ?? $[$];
    } catch (e) {
        // NullPointerException :(
        console.error(e);
        return null;
    }
}
```
Reading the [cache handler API docs](https://nextjs.org/docs/app/api-reference/next-config-js/incrementalCacheHandlerPath),
if we can get `get()` to return `null`, it will signal to Next.js that the cache is empty for the given key and the fetch
will go through. There are no `NullPointerException`s for object access in JavaScript, but what other errors can we
trigger to get the `catch` clause to run and escape the cache?

A second big hint lies in the `cachedFetchAction()` source:
```ts
export const cachedFetchAction = async (_: any, data: FormData) => {
    // Deserialize that pesky JSON data
    const body = coolerJsonParse(data.get('body')!.toString().trim());

    return cachedFetch(
        data.get('url')!.toString(),
        body
    );
}
```
Here, notice that
- The JSON deserialization happens *outside* of the cached logic.
- We use our own custom JSON deserialization function, instead of `JSON.parse()`.

so the vulnerability is very likely in that exact function.
```ts
// Reinvent the wheel and make it square
function coolerJsonParse(str: string, ret: any = {}) {
    if (str[0] !== '{' || str.at(-1) !== '}')
        return {};

    const matches = str.slice(1, str.length - 1).matchAll(/(?:^|,)\s*"(\w+)"\s*:\s*(\d+|"\w+"|\{.+?})/g);
    for (const [, field, value] of matches) {
        if (value.startsWith('"')) {
            ret[field] = value.slice(1, value.length - 1);
        } else if (value.startsWith('{')) {
            if (!(field in ret)) ret[field] = {};
            coolerJsonParse(value, ret[field]);
        } else {
            ret[field] = Number(value);
        }
    }

    return ret;
}
```
The final hint is this specific line in the JSON parser:
```ts
            if (!(field in ret)) ret[field] = {};
```
Why do we check if the field is in `ret` before creating it, if `ret` starts out as an empty object? For what values would
```ts
field in {}
```
return true?
```js
> '__proto__' in {}
true
```
It's prototype pollution.

Specifically, the "object as key of object" stringification mentioned earlier relies on the return value of `Object.toString()`,
which can be overridden for all objects by assigning to `{}.__proto__.toString`.
```js
> const obj = {}
undefined
> obj[obj] = 5
5
> {}.__proto__.toString = () => 'hii'
[Function (anonymous)]
> obj[obj]
undefined
> obj[obj] = 3
3
> obj
{ '[object Object]': 5, hii: 3 }
```
While our JSON parser doesn't allow us to assign a custom function to `toString`, we *can* assign a number or string value
to it. Then, when we try to index `$[$]`, JavaScript will try to invoke a string or number and raise a TypeError, running
our `catch` clause and returning `null`. Next.js will then get that the cache is empty, and our fetch will go through.

You can use any webhook as the URL to fetch, and the simplest JSON payload looks something like
```json
{"__proto__": {"toString": 5}}
```
(Luckily, [real `JSON.parse()` is not vulnerable to the same attack.](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/JSON/parse#description))
