-- =====================================================================
-- IFAR Registration (online application) module
-- Run once in the Supabase SQL editor. Depends on: is_super_admin()
-- =====================================================================

-- ---------- Tables ----------------------------------------------------

create table if not exists public.ifar_application_counters (
  year int primary key,
  last_value int not null default 0
);
alter table public.ifar_application_counters enable row level security;
-- no policies: only SECURITY DEFINER functions touch it

create table if not exists public.ifar_applications (
  id uuid primary key default gen_random_uuid(),
  reference_no text unique not null,
  public_token text unique not null
    default (replace(gen_random_uuid()::text,'-','') || replace(gen_random_uuid()::text,'-','')),
  recruiter_id uuid not null references auth.users(id),
  recruiter_name text,
  recruiter_email text,
  candidate_email text not null,
  candidate_name text,
  note text,
  status text not null default 'INVITED'
    check (status in ('INVITED','OPENED','DRAFT','SUBMITTED','SENT_TO_AD','RETURNED','CLOSED')),
  form_data jsonb not null default '{}'::jsonb,
  files jsonb not null default '{}'::jsonb,        -- {slot: [{path,name,type,size}]}
  applicant_signature text,
  return_reason text,
  return_flags text[] not null default '{}',
  returned_by text,
  returned_by_role text,                            -- 'IFAR' | 'AD'
  returned_at timestamptz,
  official_use jsonb not null default '{}'::jsonb,  -- filled by AD
  pdf_path text,
  expires_at timestamptz not null default (now() + interval '30 days'),
  opened_at timestamptz,
  last_saved_at timestamptz,
  submitted_at timestamptz,
  sent_to_ad_at timestamptz,
  closed_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index if not exists ifar_applications_recruiter_idx on public.ifar_applications(recruiter_id, created_at desc);
create index if not exists ifar_applications_status_idx on public.ifar_applications(status);

create table if not exists public.ifar_application_audit_events (
  id uuid primary key default gen_random_uuid(),
  application_id uuid not null references public.ifar_applications(id) on delete cascade,
  event_type text not null,
  actor_type text,          -- IFAR | CANDIDATE | AD | SYSTEM
  actor_label text,
  metadata jsonb not null default '{}'::jsonb,
  occurred_at timestamptz not null default now()
);
create index if not exists ifar_app_audit_idx on public.ifar_application_audit_events(application_id, occurred_at);

alter table public.ifar_applications enable row level security;
alter table public.ifar_application_audit_events enable row level security;

-- ---------- Internal helpers ---------------------------------------

create or replace function public.next_ifar_application_ref()
returns text language plpgsql security definer set search_path = public as $$
declare
  y int := extract(year from (now() at time zone 'Asia/Kuala_Lumpur'))::int;
  n int;
begin
  insert into ifar_application_counters(year, last_value) values (y, 1)
  on conflict (year) do update set last_value = ifar_application_counters.last_value + 1
  returning last_value into n;
  return 'IFARAPP-' || y || '-' || lpad(n::text, 4, '0');
end $$;
revoke all on function public.next_ifar_application_ref() from public, anon, authenticated;

create or replace function public._ifar_audit(p_app uuid, p_type text, p_actor_type text, p_label text, p_meta jsonb default '{}'::jsonb)
returns void language sql security definer set search_path = public as $$
  insert into ifar_application_audit_events(application_id, event_type, actor_type, actor_label, metadata)
  values (p_app, p_type, p_actor_type, p_label, coalesce(p_meta, '{}'::jsonb));
$$;
revoke all on function public._ifar_audit(uuid,text,text,text,jsonb) from public, anon, authenticated;

-- Insert trigger: server decides reference no, expiry, status, owner
create or replace function public.ifar_applications_before_insert()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  new.reference_no := next_ifar_application_ref();
  new.status := 'INVITED';
  new.expires_at := now() + interval '30 days';
  if auth.uid() is not null then new.recruiter_id := auth.uid(); end if;
  return new;
end $$;
drop trigger if exists trg_ifar_applications_before_insert on public.ifar_applications;
create trigger trg_ifar_applications_before_insert before insert on public.ifar_applications
for each row execute function public.ifar_applications_before_insert();

create or replace function public.ifar_applications_after_insert()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  perform _ifar_audit(new.id, 'CREATED', 'IFAR', new.recruiter_name,
    jsonb_build_object('candidate_email', new.candidate_email));
  return new;
end $$;
drop trigger if exists trg_ifar_applications_after_insert on public.ifar_applications;
create trigger trg_ifar_applications_after_insert after insert on public.ifar_applications
for each row execute function public.ifar_applications_after_insert();

-- ---------- RLS policies (direct table access) ----------------------
-- Recruiters: read own, create own, delete own while not yet submitted.
-- All state changes go through the RPCs below.

drop policy if exists ifar_app_recruiter_select on public.ifar_applications;
create policy ifar_app_recruiter_select on public.ifar_applications
  for select to authenticated using (recruiter_id = auth.uid());

drop policy if exists ifar_app_recruiter_insert on public.ifar_applications;
create policy ifar_app_recruiter_insert on public.ifar_applications
  for insert to authenticated with check (recruiter_id = auth.uid());

drop policy if exists ifar_app_recruiter_delete on public.ifar_applications;
create policy ifar_app_recruiter_delete on public.ifar_applications
  for delete to authenticated
  using (recruiter_id = auth.uid() and status in ('INVITED','OPENED','DRAFT'));

drop policy if exists ifar_app_admin_select on public.ifar_applications;
create policy ifar_app_admin_select on public.ifar_applications
  for select to authenticated using (public.is_super_admin() and sent_to_ad_at is not null);

drop policy if exists ifar_audit_recruiter_select on public.ifar_application_audit_events;
create policy ifar_audit_recruiter_select on public.ifar_application_audit_events
  for select to authenticated using (
    exists (select 1 from public.ifar_applications a
            where a.id = application_id and a.recruiter_id = auth.uid()));

drop policy if exists ifar_audit_admin_select on public.ifar_application_audit_events;
create policy ifar_audit_admin_select on public.ifar_application_audit_events
  for select to authenticated using (
    public.is_super_admin() and exists (select 1 from public.ifar_applications a
            where a.id = application_id and a.sent_to_ad_at is not null));

-- ---------- Candidate RPCs (token based, callable without login) ----

create or replace function public.get_ifar_application_by_token(p_token text)
returns jsonb language plpgsql security definer set search_path = public as $$
declare a ifar_applications%rowtype; editable boolean;
begin
  select * into a from ifar_applications where public_token = p_token;
  if not found then raise exception 'This link is not valid.'; end if;

  editable := a.status in ('INVITED','OPENED','DRAFT','RETURNED');

  if not editable then
    return jsonb_build_object('reference_no', a.reference_no, 'status', a.status, 'locked', true,
      'expired', false, 'recruiter_name', a.recruiter_name, 'submitted_at', a.submitted_at);
  end if;

  if a.expires_at < now() then
    return jsonb_build_object('reference_no', a.reference_no, 'status', a.status, 'locked', false,
      'expired', true, 'recruiter_name', a.recruiter_name);
  end if;

  if a.status = 'INVITED' then
    update ifar_applications set status = 'OPENED', opened_at = now(), updated_at = now() where id = a.id;
    perform _ifar_audit(a.id, 'CANDIDATE_OPENED', 'CANDIDATE', coalesce(nullif(a.candidate_name,''), a.candidate_email));
    a.status := 'OPENED';
  end if;

  return jsonb_build_object(
    'reference_no', a.reference_no, 'status', a.status, 'locked', false, 'expired', false,
    'candidate_email', a.candidate_email, 'candidate_name', a.candidate_name,
    'recruiter_name', a.recruiter_name,
    'form_data', a.form_data, 'files', a.files, 'applicant_signature', a.applicant_signature,
    'return_reason', a.return_reason, 'return_flags', to_jsonb(a.return_flags),
    'returned_by_role', a.returned_by_role,
    'expires_at', a.expires_at, 'last_saved_at', a.last_saved_at);
end $$;

create or replace function public.save_ifar_application_draft(
  p_token text, p_form_data jsonb, p_files jsonb, p_signature text)
returns jsonb language plpgsql security definer set search_path = public as $$
declare a ifar_applications%rowtype; first_save boolean;
begin
  select * into a from ifar_applications where public_token = p_token for update;
  if not found then raise exception 'This link is not valid.'; end if;
  if a.status not in ('INVITED','OPENED','DRAFT','RETURNED') then
    raise exception 'This application can no longer be edited.';
  end if;
  if a.expires_at < now() then raise exception 'This link has expired.'; end if;
  if pg_column_size(coalesce(p_form_data,'{}'::jsonb)) > 300000 then raise exception 'Form data too large.'; end if;
  if length(coalesce(p_signature,'')) > 400000 then raise exception 'Signature too large.'; end if;
  if exists (
    select 1 from jsonb_each(coalesce(p_files,'{}'::jsonb)) e, jsonb_array_elements(e.value) f
    where (f->>'path') is null or (f->>'path') not like a.id::text || '/%'
  ) then raise exception 'Invalid file reference.'; end if;

  first_save := a.status in ('INVITED','OPENED');
  update ifar_applications set
    form_data = coalesce(p_form_data,'{}'::jsonb),
    files = coalesce(p_files,'{}'::jsonb),
    applicant_signature = nullif(p_signature,''),
    status = case when first_save then 'DRAFT' else status end,
    last_saved_at = now(), updated_at = now()
  where id = a.id;
  if first_save then
    perform _ifar_audit(a.id, 'DRAFT_SAVED', 'CANDIDATE', coalesce(nullif(a.candidate_name,''), a.candidate_email));
  end if;
  return jsonb_build_object('ok', true, 'saved_at', now());
end $$;

create or replace function public.submit_ifar_application(
  p_token text, p_form_data jsonb, p_files jsonb, p_signature text)
returns jsonb language plpgsql security definer set search_path = public as $$
declare a ifar_applications%rowtype; k text; resub boolean;
begin
  select * into a from ifar_applications where public_token = p_token for update;
  if not found then raise exception 'This link is not valid.'; end if;
  if a.status not in ('INVITED','OPENED','DRAFT','RETURNED') then
    raise exception 'This application has already been submitted.';
  end if;
  if a.expires_at < now() then raise exception 'This link has expired.'; end if;

  foreach k in array array['name','nric','mobile','nationality','race','religion','marital','corrAddress','occupation','email'] loop
    if coalesce(trim(p_form_data->>k),'') = '' then raise exception 'Incomplete application: % is required.', k; end if;
  end loop;
  if coalesce(trim(p_form_data#>>'{nok,name}'),'') = '' then raise exception 'Incomplete application: next of kin is required.'; end if;
  if coalesce(trim(p_form_data#>>'{bank,accountNo}'),'') = '' then raise exception 'Incomplete application: bank account is required.'; end if;
  if coalesce(trim(p_form_data#>>'{bank,taxNo}'),'') = '' then raise exception 'Incomplete application: income tax number is required.'; end if;
  if jsonb_array_length(coalesce(p_form_data->'references','[]'::jsonb)) < 2 then raise exception 'Incomplete application: at least 2 references are required.'; end if;
  if jsonb_array_length(coalesce(p_form_data->'employment','[]'::jsonb)) < 1 then raise exception 'Incomplete application: employment history is required.'; end if;
  if jsonb_array_length(coalesce(p_form_data->'education','[]'::jsonb)) < 1 then raise exception 'Incomplete application: education background is required.'; end if;
  foreach k in array array['nric_front','nric_back','certificates','prof_cert'] loop
    if jsonb_array_length(coalesce(p_files->k,'[]'::jsonb)) < 1 then raise exception 'Incomplete application: document % is missing.', k; end if;
  end loop;
  if coalesce(p_signature,'') = '' then raise exception 'Incomplete application: signature is required.'; end if;
  if exists (
    select 1 from jsonb_each(coalesce(p_files,'{}'::jsonb)) e, jsonb_array_elements(e.value) f
    where (f->>'path') is null or (f->>'path') not like a.id::text || '/%'
  ) then raise exception 'Invalid file reference.'; end if;

  resub := a.status = 'RETURNED';
  update ifar_applications set
    form_data = p_form_data, files = p_files, applicant_signature = p_signature,
    status = 'SUBMITTED', submitted_at = now(), last_saved_at = now(), updated_at = now(),
    return_reason = null, return_flags = '{}'
  where id = a.id;
  perform _ifar_audit(a.id, case when resub then 'CANDIDATE_RESUBMITTED' else 'CANDIDATE_SUBMITTED' end,
    'CANDIDATE', coalesce(nullif(p_form_data->>'name',''), a.candidate_email));
  return jsonb_build_object('ok', true);
end $$;

grant execute on function public.get_ifar_application_by_token(text) to anon, authenticated;
grant execute on function public.save_ifar_application_draft(text,jsonb,jsonb,text) to anon, authenticated;
grant execute on function public.submit_ifar_application(text,jsonb,jsonb,text) to anon, authenticated;

-- ---------- Recruiter (IFAR) RPCs -----------------------------------

create or replace function public.recruiter_return_ifar_application(p_id uuid, p_reason text, p_flags text[])
returns void language plpgsql security definer set search_path = public as $$
declare a ifar_applications%rowtype;
begin
  select * into a from ifar_applications where id = p_id and recruiter_id = auth.uid() for update;
  if not found then raise exception 'Application not found.'; end if;
  if a.status not in ('SUBMITTED','SENT_TO_AD') then raise exception 'Only a submitted application can be returned.'; end if;
  if coalesce(trim(p_reason),'') = '' then raise exception 'A reason is required.'; end if;
  update ifar_applications set status = 'RETURNED', return_reason = trim(p_reason),
    return_flags = coalesce(p_flags,'{}'), returned_by = a.recruiter_name, returned_by_role = 'IFAR',
    returned_at = now(), expires_at = now() + interval '30 days', updated_at = now()
  where id = a.id;
  perform _ifar_audit(a.id, 'RETURNED', 'IFAR', a.recruiter_name,
    jsonb_build_object('reason', trim(p_reason), 'flags', to_jsonb(coalesce(p_flags,'{}')), 'from_status', a.status));
end $$;

create or replace function public.recruiter_send_ifar_application_to_ad(p_id uuid, p_pdf_path text)
returns void language plpgsql security definer set search_path = public as $$
declare a ifar_applications%rowtype;
begin
  select * into a from ifar_applications where id = p_id and recruiter_id = auth.uid() for update;
  if not found then raise exception 'Application not found.'; end if;
  if a.status <> 'SUBMITTED' then raise exception 'Only a submitted application can be sent to AD.'; end if;
  if p_pdf_path is null or p_pdf_path not like a.id::text || '/final/%' then raise exception 'Invalid PDF path.'; end if;
  update ifar_applications set status = 'SENT_TO_AD', sent_to_ad_at = now(), pdf_path = p_pdf_path, updated_at = now()
  where id = a.id;
  perform _ifar_audit(a.id, 'SENT_TO_AD', 'IFAR', a.recruiter_name);
end $$;

create or replace function public.recruiter_extend_ifar_application(p_id uuid)
returns timestamptz language plpgsql security definer set search_path = public as $$
declare a ifar_applications%rowtype; ne timestamptz := now() + interval '30 days';
begin
  select * into a from ifar_applications where id = p_id and recruiter_id = auth.uid() for update;
  if not found then raise exception 'Application not found.'; end if;
  if a.status not in ('INVITED','OPENED','DRAFT','RETURNED') then raise exception 'This application is no longer open.'; end if;
  update ifar_applications set expires_at = ne, updated_at = now() where id = a.id;
  perform _ifar_audit(a.id, 'EXTENDED', 'IFAR', a.recruiter_name, jsonb_build_object('expires_at', ne));
  return ne;
end $$;

grant execute on function public.recruiter_return_ifar_application(uuid,text,text[]) to authenticated;
grant execute on function public.recruiter_send_ifar_application_to_ad(uuid,text) to authenticated;
grant execute on function public.recruiter_extend_ifar_application(uuid) to authenticated;

-- ---------- Admin (AD) RPCs ----------------------------------------

create or replace function public.admin_return_ifar_application(p_id uuid, p_reason text, p_flags text[])
returns void language plpgsql security definer set search_path = public as $$
declare a ifar_applications%rowtype;
begin
  if not public.is_super_admin() then raise exception 'Not authorised.'; end if;
  select * into a from ifar_applications where id = p_id for update;
  if not found then raise exception 'Application not found.'; end if;
  if a.status <> 'SENT_TO_AD' then raise exception 'Only an application with AD can be returned.'; end if;
  if coalesce(trim(p_reason),'') = '' then raise exception 'A reason is required.'; end if;
  update ifar_applications set status = 'RETURNED', return_reason = trim(p_reason),
    return_flags = coalesce(p_flags,'{}'), returned_by = 'AD', returned_by_role = 'AD',
    returned_at = now(), expires_at = now() + interval '30 days', updated_at = now()
  where id = a.id;
  perform _ifar_audit(a.id, 'RETURNED', 'AD', 'AD',
    jsonb_build_object('reason', trim(p_reason), 'flags', to_jsonb(coalesce(p_flags,'{}'))));
end $$;

create or replace function public.admin_save_official_use(p_id uuid, p_official jsonb)
returns void language plpgsql security definer set search_path = public as $$
begin
  if not public.is_super_admin() then raise exception 'Not authorised.'; end if;
  update ifar_applications set official_use = coalesce(p_official,'{}'::jsonb), updated_at = now()
  where id = p_id and status = 'SENT_TO_AD';
  if not found then raise exception 'Application is not with AD.'; end if;
  perform _ifar_audit(p_id, 'OFFICIAL_USE_SAVED', 'AD', 'AD');
end $$;

create or replace function public.admin_close_ifar_application(p_id uuid, p_official jsonb, p_pdf_path text)
returns void language plpgsql security definer set search_path = public as $$
begin
  if not public.is_super_admin() then raise exception 'Not authorised.'; end if;
  if p_pdf_path is null or p_pdf_path not like p_id::text || '/final/%' then raise exception 'Invalid PDF path.'; end if;
  update ifar_applications set status = 'CLOSED', official_use = coalesce(p_official,'{}'::jsonb),
    pdf_path = p_pdf_path, closed_at = now(), updated_at = now()
  where id = p_id and status = 'SENT_TO_AD';
  if not found then raise exception 'Application is not with AD.'; end if;
  perform _ifar_audit(p_id, 'CLOSED', 'AD', 'AD');
end $$;

grant execute on function public.admin_return_ifar_application(uuid,text,text[]) to authenticated;
grant execute on function public.admin_save_official_use(uuid,jsonb) to authenticated;
grant execute on function public.admin_close_ifar_application(uuid,jsonb,text) to authenticated;

-- ---------- Storage ------------------------------------------------
-- Private bucket. Candidates upload through signed upload URLs issued by the
-- edge function (token-checked); recruiters/admin read through these policies.

insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('ifar-application-files', 'ifar-application-files', false, 20971520,
        array['image/jpeg','image/png','application/pdf'])
on conflict (id) do update set public = false, file_size_limit = excluded.file_size_limit,
  allowed_mime_types = excluded.allowed_mime_types;

drop policy if exists ifar_files_select on storage.objects;
create policy ifar_files_select on storage.objects for select to authenticated using (
  bucket_id = 'ifar-application-files' and exists (
    select 1 from public.ifar_applications a
    where a.id::text = (storage.foldername(name))[1]
      and (a.recruiter_id = auth.uid() or (public.is_super_admin() and a.sent_to_ad_at is not null))));

drop policy if exists ifar_files_insert_final on storage.objects;
create policy ifar_files_insert_final on storage.objects for insert to authenticated with check (
  bucket_id = 'ifar-application-files'
  and (storage.foldername(name))[2] = 'final'
  and exists (
    select 1 from public.ifar_applications a
    where a.id::text = (storage.foldername(name))[1]
      and (a.recruiter_id = auth.uid() or (public.is_super_admin() and a.sent_to_ad_at is not null))));

drop policy if exists ifar_files_delete_owner on storage.objects;
create policy ifar_files_delete_owner on storage.objects for delete to authenticated using (
  bucket_id = 'ifar-application-files' and exists (
    select 1 from public.ifar_applications a
    where a.id::text = (storage.foldername(name))[1] and a.recruiter_id = auth.uid()));
