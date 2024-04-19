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
