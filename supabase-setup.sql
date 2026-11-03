-- Run this in the Supabase SQL Editor after creating the Auth user:
--   email: admin@ashera.local
--   password: choose and keep it private
-- The browser app accepts "admin" as the username.

create table if not exists public.ashera_admins (
  user_id uuid primary key references auth.users (id) on delete cascade
);

create table if not exists public.ashera_data (
  id integer primary key check (id = 1),
  payload jsonb not null,
  updated_at timestamptz not null default now()
);

alter table public.ashera_admins enable row level security;
alter table public.ashera_data enable row level security;

revoke all on public.ashera_admins from anon, authenticated;
revoke all on public.ashera_data from anon, authenticated;
grant select on public.ashera_admins to authenticated;
grant select, insert, update on public.ashera_data to authenticated;

drop policy if exists "Admin can read own membership" on public.ashera_admins;
create policy "Admin can read own membership"
  on public.ashera_admins
  for select
  to authenticated
  using (user_id = (select auth.uid()));

drop policy if exists "Only the listed admin can access family data" on public.ashera_data;
create policy "Only the listed admin can access family data"
  on public.ashera_data
  for all
  to authenticated
  using (
    exists (
      select 1
      from public.ashera_admins
      where user_id = (select auth.uid())
    )
  )
  with check (
    exists (
      select 1
      from public.ashera_admins
      where user_id = (select auth.uid())
    )
  );

insert into public.ashera_admins (user_id)
select id
from auth.users
where lower(email) = 'admin@ashera.local'
on conflict (user_id) do nothing;

do $$
begin
  if not exists (
    select 1
    from public.ashera_admins a
    join auth.users u on u.id = a.user_id
    where lower(u.email) = 'admin@ashera.local'
  ) then
    raise exception 'Create the admin@ashera.local Auth user first, then run this script again.';
  end if;
end
$$;
