import { NextResponse } from 'next/server';
import { SignJWT } from 'jose';
export async function middleware(req) {
  const t = await new SignJWT({ sub: 'middleware' }).setProtectedHeader({ alg: 'HS256' }).sign(new TextEncoder().encode(process.env.JWT_SECRET));
  const res = NextResponse.next(); res.headers.set('x-proxy-token', t); return res;
}
export const config = { matcher: '/' };
