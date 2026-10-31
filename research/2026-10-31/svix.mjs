import { Webhook } from 'svix';
console.log(new Webhook(process.env.SVIX_SECRET).sign('msg_1', new Date(1700000000000), '{"a":1}'));
