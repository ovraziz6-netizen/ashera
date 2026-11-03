import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';

const allowedOrigins = new Set([
  'https://ovraziz6-netizen.github.io',
  'http://localhost:5500',
  'http://127.0.0.1:5500',
]);

Deno.serve(async request => {
  const origin = request.headers.get('origin') ?? '';
  const corsHeaders = {
    'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Origin': allowedOrigins.has(origin) ? origin : 'null',
    'Content-Type': 'application/json',
    'Vary': 'Origin',
  };
  const respond = (status: number, message: string) =>
    new Response(JSON.stringify({ error: message }), { status, headers: corsHeaders });

  if (!allowedOrigins.has(origin)) return respond(403, 'Origin is not allowed.');
  if (request.method === 'OPTIONS') return new Response('ok', { headers: corsHeaders });
  if (request.method !== 'POST') return respond(405, 'Method not allowed.');

  const authorization = request.headers.get('authorization') ?? '';
  const token = authorization.match(/^Bearer\s+(.+)$/i)?.[1];
  if (!token) return respond(401, 'Authentication required.');

  const supabaseUrl = Deno.env.get('SUPABASE_URL');
  const serviceRoleKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY');
  if (!supabaseUrl || !serviceRoleKey) {
    console.error('Required Supabase function environment variables are missing.');
    return respond(500, 'Password management is not configured.');
  }

  const supabase = createClient(supabaseUrl, serviceRoleKey, {
    auth: { autoRefreshToken: false, persistSession: false },
  });

  const { data: userData, error: authError } = await supabase.auth.getUser(token);
  if (authError || !userData.user) return respond(401, 'Invalid session.');

  const { data: admin, error: adminError } = await supabase
    .from('ashera_members')
    .select('role, active')
    .eq('user_id', userData.user.id)
    .maybeSingle();
  if (adminError) {
    console.error('Could not verify the administrator membership.', adminError);
    return respond(500, 'Could not verify administrator access.');
  }
  if (!admin || admin.role !== 'admin' || admin.active !== true) {
    return respond(403, 'Administrator access required.');
  }

  let body: { username?: unknown; password?: unknown };
  try {
    body = await request.json();
  } catch {
    return respond(400, 'Invalid request body.');
  }
  if (body.username !== 'user' || typeof body.password !== 'string') {
    return respond(400, 'A valid user and password are required.');
  }
  const passwordBytes = new TextEncoder().encode(body.password).byteLength;
  if (body.password.length < 10 || passwordBytes > 72) {
    return respond(400, 'Password must be at least 10 characters and no more than 72 bytes.');
  }

  const { data: member, error: memberError } = await supabase
    .from('ashera_members')
    .select('user_id')
    .eq('username', 'user')
    .eq('role', 'user')
    .maybeSingle();
  if (memberError) {
    console.error('Could not find the user membership.', memberError);
    return respond(500, 'Could not load the user account.');
  }
  if (!member) return respond(404, 'User account not found.');

  const { error: updateError } = await supabase.auth.admin.updateUserById(member.user_id, {
    password: body.password,
  });
  if (updateError) {
    console.error('Supabase rejected the password update.', updateError);
    return respond(400, 'Supabase could not update the password.');
  }

  return new Response(JSON.stringify({ success: true }), { status: 200, headers: corsHeaders });
});
