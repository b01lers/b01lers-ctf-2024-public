import { cachedFetch } from '@/app/fetch';
import FetchForm from '@/app/FetchForm';


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
