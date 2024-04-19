import type { ReactNode } from 'react';
import type { Metadata } from 'next';
import { Inter } from 'next/font/google';

import './globals.css';


const inter = Inter({ subsets: ['latin'] });

export const metadata: Metadata = {
    title: 'POST-r',
    description: 'The free, online POST request service!',
}

export default function RootLayout(props: { children: ReactNode }) {
    return (
        <html lang="en">
            <body className={inter.className}>
                {props.children}
            </body>
        </html>
    )
}
