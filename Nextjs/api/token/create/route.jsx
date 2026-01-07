import EncryptedServer from '@/lib/EncryptedServer'
import { NextResponse } from 'next/server'
export async function GET() {
    return NextResponse.json({ message: 'token fetched', token:EncryptedServer.generatePublicPrivateKey()})
}