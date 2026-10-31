import { SignJWT } from 'jose';
export async function GET() {
  const t = await new SignJWT({ sub: 'edge' }).setProtectedHeader({ alg: 'HS256' }).sign(new TextEncoder().encode(process.env.JWT_SECRET));
  return Response.json({ t });
}
export const runtime = 'edge';
