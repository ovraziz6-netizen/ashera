-- Create the cloud data tables and role-based access rules.
-- Create Auth users in Supabase first:
--   admin@ashera.local
--   user@ashera.local
-- Then use the final INSERT statements to register them in ashera_members.

create table if not exists public.ashera_members (
  user_id uuid primary key references auth.users (id) on delete cascade,
  username text not null unique check (username in ('admin', 'user')),
  role text not null check (role in ('admin', 'user')),
  active boolean not null default true,
  created_at timestamptz not null default now()
);

create table if not exists public.ashera_data (
  id integer primary key check (id = 1),
  payload jsonb not null,
  updated_at timestamptz not null default now()
);

alter table public.ashera_members enable row level security;
alter table public.ashera_data enable row level security;

revoke all on public.ashera_members from anon, authenticated;
revoke all on public.ashera_data from anon, authenticated;
grant select, update on public.ashera_members to authenticated;
grant select, insert, update on public.ashera_data to authenticated;

create or replace function public.ashera_is_admin()
returns boolean
language sql
stable
security definer
set search_path = public, auth
as $$
  select exists (
    select 1
    from public.ashera_members
    where user_id = auth.uid()
      and role = 'admin'
      and active = true
  );
$$;

create or replace function public.ashera_is_active_member()
returns boolean
language sql
stable
security definer
set search_path = public, auth
as $$
  select exists (
    select 1
    from public.ashera_members
    where user_id = auth.uid()
      and active = true
  );
$$;

revoke all on function public.ashera_is_admin() from public, anon;
revoke all on function public.ashera_is_active_member() from public, anon;
grant execute on function public.ashera_is_admin() to authenticated;
grant execute on function public.ashera_is_active_member() to authenticated;

drop policy if exists "Only the listed admin can access family data" on public.ashera_data;
drop policy if exists "Members can read own membership" on public.ashera_members;
drop policy if exists "Admins can update member status" on public.ashera_members;
drop policy if exists "Active members can access family data" on public.ashera_data;
create policy "Members can read own membership"
  on public.ashera_members
  for select
  to authenticated
  using (user_id = (select auth.uid()) or (select public.ashera_is_admin()));

create policy "Admins can update member status"
  on public.ashera_members
  for update
  to authenticated
  using ((select public.ashera_is_admin()))
  with check ((select public.ashera_is_admin()));

create policy "Active members can access family data"
  on public.ashera_data
  for all
  to authenticated
  using ((select public.ashera_is_active_member()))
  with check ((select public.ashera_is_active_member()));

-- After creating and confirming both Auth users, run once:
-- insert into public.ashera_members (user_id, username, role)
-- select id, 'admin', 'admin' from auth.users
-- where lower(email) = 'admin@ashera.local'
-- on conflict (user_id) do update set username = excluded.username, role = excluded.role, active = true;
--
-- insert into public.ashera_members (user_id, username, role)
-- select id, 'user', 'user' from auth.users
-- where lower(email) = 'user@ashera.local'
-- on conflict (user_id) do update set username = excluded.username, role = excluded.role, active = true;
