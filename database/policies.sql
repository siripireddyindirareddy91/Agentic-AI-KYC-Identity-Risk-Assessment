alter table public.records enable row level security;
revoke all on public.records from anon, authenticated;
