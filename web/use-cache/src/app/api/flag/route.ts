import { NextResponse } from 'next/server';


export async function POST(req: Request) {
    try {
        const {balance, flag} = await req.json();
        console.log(`Received balance = ${balance}, flag = ${flag}`);

        return NextResponse.json({ message: 'Received your flag!' });
    } catch {
        console.log('Got a malformed request :(')
        return NextResponse.json({ message: 'An error occurred...' }, { status: 500 })
    }
}
