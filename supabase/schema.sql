-- RTAFET Training — database schema
-- All tables are locked (RLS on, no policies). Clients only call the SECURITY DEFINER functions below,
-- which check the unit access code, member PIN sessions and tutor sessions.
create extension if not exists pgcrypto with schema extensions;

create sequence if not exists member_seq start 1;

create table if not exists members(
  id text primary key default 'M'||lpad(nextval('member_seq')::text,3,'0'),
  rank text not null, first text not null, last text not null,
  unit text default '', type text default '', note text default '',
  star boolean default false, pending boolean default false, deleted boolean default false,
  pin_hash text, fail_count int default 0, locked_until timestamptz,
  vmarks jsonb default '{}'::jsonb, created_at timestamptz default now());
create table if not exists sessions(
  token uuid primary key default gen_random_uuid(),
  member_id text references members(id) on delete cascade,
  is_tutor boolean default false, created_at timestamptz default now(),
  expires_at timestamptz default now() + interval '30 days');
create table if not exists attempts(
  id bigserial primary key, member_id text references members(id) on delete set null,
  created_at timestamptz default now(), data jsonb not null);
create table if not exists settings(key text primary key, value text);
create table if not exists exam_sets(id text primary key, title text, data jsonb not null, updated_at timestamptz default now());
create table if not exists room(id int primary key default 1, state jsonb default '{}'::jsonb, paper jsonb, updated_at timestamptz default now());
alter table members add column if not exists cert text default '';
alter table members add column if not exists cert_note text default '';
insert into room(id) values (1) on conflict do nothing;
insert into settings(key,value) values ('tutor_pin_hash', 'unset') on conflict do nothing;
insert into settings(key,value) values ('unit_code', 'change-me') on conflict do nothing;
insert into settings(key,value) values ('tutor_fail', '0') on conflict do nothing;

alter table members enable row level security;
alter table sessions enable row level security;
alter table attempts enable row level security;
alter table settings enable row level security;
alter table exam_sets enable row level security;
alter table room enable row level security;
revoke all on members, sessions, attempts, settings, exam_sets, room from anon, authenticated;

-- ---------- helpers ----------
create or replace function _sess(p_token uuid) returns sessions language sql security definer set search_path=public, extensions as $$
  select * from sessions where token=p_token and expires_at>now() $$;
create or replace function _member_id(p_token uuid) returns text language plpgsql security definer set search_path=public, extensions as $$
declare s sessions; begin s:=_sess(p_token); if s.token is null or s.member_id is null then raise exception 'not_logged_in'; end if; return s.member_id; end $$;
create or replace function _tutor(p_token uuid) returns void language plpgsql security definer set search_path=public, extensions as $$
declare s sessions; begin s:=_sess(p_token); if s.token is null or not s.is_tutor then raise exception 'not_tutor'; end if; end $$;
create or replace function _any(p_token uuid) returns sessions language plpgsql security definer set search_path=public, extensions as $$
declare s sessions; begin s:=_sess(p_token); if s.token is null then raise exception 'not_logged_in'; end if; return s; end $$;
create or replace function _code_ok(p_code text) returns void language plpgsql security definer set search_path=public, extensions as $$
begin if lower(trim(coalesce(p_code,''))) <> lower((select value from settings where key='unit_code')) then raise exception 'bad_code'; end if; end $$;
create or replace function _member_json(m members) returns jsonb language sql immutable as $$
  select jsonb_build_object('id',m.id,'rank',m.rank,'first',m.first,'last',m.last,'unit',m.unit,'type',m.type,'note',m.note,
    'star',m.star,'pending',m.pending,'cert',coalesce(m.cert,''),'cert_note',coalesce(m.cert_note,''),'pin',m.pin_hash is not null,'created',(extract(epoch from m.created_at)*1000)::bigint) $$;

-- ---------- public (unit code) ----------
create or replace function rt_ping() returns text language sql security definer set search_path=public, extensions as $$ select 'ok'::text $$;
create or replace function rt_roster_public(p_code text) returns jsonb language plpgsql security definer set search_path=public, extensions as $$
begin perform _code_ok(p_code);
  return coalesce((select jsonb_agg(jsonb_build_object('id',id,'rank',rank,'first',first,'last',last,'unit',unit,'cert',coalesce(cert,''),'pin',pin_hash is not null) order by id)
    from members where not deleted), '[]'::jsonb); end $$;

create or replace function rt_login(p_code text, p_id text, p_pin text) returns jsonb language plpgsql security definer set search_path=public, extensions as $$
declare m members; t uuid;
begin perform _code_ok(p_code);
  if p_pin !~ '^\d{6}$' then raise exception 'bad_pin_format'; end if;
  select * into m from members where id=p_id and not deleted; if m.id is null then raise exception 'no_member'; end if;
  if m.locked_until is not null and m.locked_until>now() then raise exception 'locked'; end if;
  if m.pin_hash is null then update members set pin_hash=crypt(p_pin, gen_salt('bf')), fail_count=0 where id=m.id;
  elsif crypt(p_pin, m.pin_hash) <> m.pin_hash then
    update members set fail_count=fail_count+1, locked_until=case when fail_count+1>=5 then now()+interval '15 minutes' else null end where id=m.id;
    raise exception 'bad_pin';
  else update members set fail_count=0, locked_until=null where id=m.id; end if;
  insert into sessions(member_id) values (m.id) returning token into t;
  return jsonb_build_object('token',t,'id',m.id); end $$;

create or replace function rt_signup(p_code text, p_rank text, p_first text, p_last text, p_unit text, p_type text, p_pin text) returns jsonb language plpgsql security definer set search_path=public, extensions as $$
declare nid text; t uuid;
begin perform _code_ok(p_code);
  if p_pin !~ '^\d{6}$' then raise exception 'bad_pin_format'; end if;
  if coalesce(trim(p_first),'')='' or coalesce(trim(p_last),'')='' then raise exception 'bad_name'; end if;
  if exists(select 1 from members where first=trim(p_first) and last=trim(p_last) and not deleted) then raise exception 'duplicate'; end if;
  insert into members(rank,first,last,unit,type,pending,pin_hash) values (trim(p_rank),trim(p_first),trim(p_last),coalesce(p_unit,''),coalesce(p_type,''),true,crypt(p_pin,gen_salt('bf')))
    returning id into nid;
  insert into sessions(member_id) values (nid) returning token into t;
  return jsonb_build_object('token',t,'id',nid); end $$;

create or replace function rt_tutor_login(p_pin text) returns jsonb language plpgsql security definer set search_path=public, extensions as $$
declare h text; f int; t uuid;
begin
  select value::int into f from settings where key='tutor_fail';
  if f>=10 then raise exception 'locked'; end if;
  select value into h from settings where key='tutor_pin_hash';
  if crypt(coalesce(p_pin,''), h) <> h then update settings set value=(f+1)::text where key='tutor_fail'; raise exception 'bad_pin'; end if;
  update settings set value='0' where key='tutor_fail';
  insert into sessions(is_tutor) values (true) returning token into t;
  return jsonb_build_object('token',t); end $$;

-- ---------- member ----------
create or replace function rt_me(p_token uuid) returns jsonb language plpgsql security definer set search_path=public, extensions as $$
declare mid text; m members;
begin mid:=_member_id(p_token); select * into m from members where id=mid;
  return jsonb_build_object('member',_member_json(m),'vmarks',m.vmarks,
    'attempts',coalesce((select jsonb_agg(data || jsonb_build_object('memberId',member_id) order by created_at) from attempts where member_id=mid),'[]'::jsonb)); end $$;
create or replace function rt_save_attempt(p_token uuid, p_data jsonb) returns void language plpgsql security definer set search_path=public, extensions as $$
declare mid text; begin mid:=_member_id(p_token);
  if (select count(*) from attempts where member_id=mid and created_at>now()-interval '1 minute')>=10 then raise exception 'too_many'; end if;
  insert into attempts(member_id,data) values (mid, p_data - 'memberId'); end $$;
create or replace function rt_set_vmark(p_token uuid, p_word text, p_mark text) returns void language plpgsql security definer set search_path=public, extensions as $$
declare mid text; begin mid:=_member_id(p_token);
  update members set vmarks = case when p_mark is null or p_mark='' then vmarks - p_word else jsonb_set(vmarks, array[p_word], to_jsonb(p_mark)) end where id=mid; end $$;
create or replace function rt_logout(p_token uuid) returns void language sql security definer set search_path=public, extensions as $$ delete from sessions where token=p_token $$;

-- ---------- tutor ----------
create or replace function rt_tutor_all(p_token uuid) returns jsonb language plpgsql security definer set search_path=public, extensions as $$
begin perform _tutor(p_token);
  return jsonb_build_object(
    'roster', coalesce((select jsonb_agg(_member_json(m) order by m.id) from members m where not m.deleted),'[]'::jsonb),
    'attempts', coalesce((select jsonb_agg(a.data || jsonb_build_object('memberId',a.member_id) order by a.created_at) from attempts a join members m on m.id=a.member_id where not m.deleted),'[]'::jsonb),
    'code', (select value from settings where key='unit_code')); end $$;
create or replace function rt_tutor_add_members(p_token uuid, p_rows jsonb) returns int language plpgsql security definer set search_path=public, extensions as $$
declare r jsonb; n int:=0;
begin perform _tutor(p_token);
  for r in select * from jsonb_array_elements(p_rows) loop
    if coalesce(r->>'first','')='' or coalesce(r->>'last','')='' then continue; end if;
    if exists(select 1 from members where first=r->>'first' and last=r->>'last' and not deleted) then continue; end if;
    insert into members(rank,first,last,unit,type,note) values (coalesce(r->>'rank',''),r->>'first',r->>'last',coalesce(r->>'unit',''),coalesce(r->>'type',''),coalesce(r->>'note',''));
    n:=n+1; end loop;
  return n; end $$;
create or replace function rt_tutor_update_member(p_token uuid, p_id text, p_patch jsonb) returns void language plpgsql security definer set search_path=public, extensions as $$
begin perform _tutor(p_token);
  if p_patch ? 'star' then update members set star=(p_patch->>'star')::boolean where id=p_id; end if;
  if p_patch ? 'type' then update members set type=coalesce(p_patch->>'type','') where id=p_id; end if;
  if p_patch ? 'cert' then update members set cert=coalesce(p_patch->>'cert',''), cert_note=coalesce(p_patch->>'cert_note','') where id=p_id; end if;
  if p_patch ? 'pending' then update members set pending=(p_patch->>'pending')::boolean where id=p_id; end if;
  if p_patch ? 'reset_pin' then update members set pin_hash=null, fail_count=0, locked_until=null where id=p_id; delete from sessions where member_id=p_id; end if;
  if p_patch ? 'delete' then update members set deleted=true where id=p_id; delete from sessions where member_id=p_id; end if; end $$;
create or replace function rt_tutor_set_pin(p_token uuid, p_pin text) returns void language plpgsql security definer set search_path=public, extensions as $$
begin perform _tutor(p_token); if p_pin !~ '^\d{6}$' then raise exception 'bad_pin_format'; end if;
  update settings set value=crypt(p_pin, gen_salt('bf')) where key='tutor_pin_hash';
  delete from sessions where is_tutor and token<>p_token; end $$;
create or replace function rt_tutor_set_code(p_token uuid, p_code text) returns void language plpgsql security definer set search_path=public, extensions as $$
begin perform _tutor(p_token); if length(trim(coalesce(p_code,'')))<4 then raise exception 'bad_code_format'; end if;
  update settings set value=trim(p_code) where key='unit_code'; end $$;
create or replace function rt_tutor_examsets(p_token uuid) returns jsonb language plpgsql security definer set search_path=public, extensions as $$
begin perform _tutor(p_token); return coalesce((select jsonb_agg(data order by id) from exam_sets),'[]'::jsonb); end $$;
create or replace function rt_tutor_put_examset(p_token uuid, p_set jsonb) returns void language plpgsql security definer set search_path=public, extensions as $$
begin perform _tutor(p_token);
  if coalesce(p_set->>'id','')='' or jsonb_array_length(p_set->'items')<>100 then raise exception 'bad_set'; end if;
  insert into exam_sets(id,title,data) values (p_set->>'id', p_set->>'title', p_set)
    on conflict (id) do update set title=excluded.title, data=excluded.data, updated_at=now(); end $$;

-- ---------- exam room ----------
create or replace function rt_room_get(p_token uuid) returns jsonb language plpgsql security definer set search_path=public, extensions as $$
begin perform _any(p_token); return (select state from room where id=1); end $$;
create or replace function rt_room_set(p_token uuid, p_state jsonb, p_paper jsonb default null, p_clear_paper boolean default false) returns void language plpgsql security definer set search_path=public, extensions as $$
begin perform _tutor(p_token);
  if p_state is not null then update room set state=p_state, updated_at=now() where id=1; end if;
  if p_paper is not null then update room set paper=p_paper where id=1; end if;
  if p_clear_paper then update room set paper=null where id=1; end if; end $$;
create or replace function rt_room_paper(p_token uuid) returns jsonb language plpgsql security definer set search_path=public, extensions as $$
declare st jsonb; pp jsonb;
begin perform _any(p_token); select state, paper into st, pp from room where id=1;
  if pp is null or coalesce(st->>'status','') not in ('listening','reading') or pp->>'sid' is distinct from st->>'sid' then return null; end if;
  return pp; end $$;

do $$ declare f record; begin
  for f in select p.oid::regprocedure as sig from pg_proc p join pg_namespace n on n.oid=p.pronamespace where n.nspname='public' and p.proname like 'rt\_%' loop
    execute format('grant execute on function %s to anon, authenticated', f.sig); end loop;
  for f in select p.oid::regprocedure as sig from pg_proc p join pg_namespace n on n.oid=p.pronamespace where n.nspname='public' and p.proname like '\_%' loop
    execute format('revoke execute on function %s from public, anon, authenticated', f.sig); end loop;
end $$;
