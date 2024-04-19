'use client'

import { useRef } from 'react';
import { useFormState } from 'react-dom';
import { cachedFetchAction } from '@/app/fetch';


export default function FetchForm() {
    const formRef = useRef<HTMLFormElement>(null);
    const [state, formAction] = useFormState(cachedFetchAction, null);

    return (
        <form
            ref={formRef}
            action={(data) => {
                formAction(data);
                formRef.current?.reset();
            }}
        >
            <input
                className="px-3 py-1.5 rounded border mb-2 w-full bg-transparent border-white/50 placeholder:text-white/50 focus:outline-none focus:ring-[3px]"
                placeholder="URL to fetch"
                name="url"
                id="url"
                type="text"
                required
            />
            <textarea
                className="px-3 py-1.5 rounded border mb-2 w-full bg-transparent border-white/50 placeholder:text-white/50 focus:outline-none focus:ring-[3px]"
                placeholder="POST body (in JSON format)"
                name="body"
                id="body"
                required
            />

            {state && (
                <pre className="bg-black/20 rounded px-4 py-2 mb-3 w-full whitespace-pre-wrap break-words line-clamp-6">
                    {state}
                </pre>
            )}

            <button type="submit" className="bg-blue-500 hover:shadow-lg transition duration-200 text-white font-semibold px-4 py-2 rounded">
                Submit fetch
            </button>
        </form>
    )
}
