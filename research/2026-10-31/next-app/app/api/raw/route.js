import { createHmac } from 'node:crypto';
export async function GET() { return Response.json({ h: createHmac('sha256', process.env.JWT_SECRET).update('hello').digest('hex') }); }
