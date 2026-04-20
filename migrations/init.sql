-- =============================================================================
-- MoreFixes Database Schema
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Users table (from prospector/ddl/20_users.sql)
-- ---------------------------------------------------------------------------
DROP TABLE IF EXISTS public.users;

CREATE TABLE public.users (
    id varchar(40) NOT NULL PRIMARY KEY,
    hashed_password varchar(40) NOT NULL,
    firstname varchar NOT NULL,
    lastname varchar NULL,
    photo varchar NULL,
    account_created varchar NULL,
    last_access varchar NULL
);

-- ---------------------------------------------------------------------------
-- Commits table (matches collect_projects.py INSERT and constants.py COMMIT_COLUMNS)
-- ---------------------------------------------------------------------------
DROP TABLE IF EXISTS public.commits;

CREATE TABLE public.commits (
    hash varchar(40) NOT NULL,
    repo_url varchar NOT NULL,
    author varchar NULL,
    author_date timestamptz NULL,
    author_timezone int NULL,
    committer varchar NULL,
    committer_date timestamptz NULL,
    committer_timezone int NULL,
    msg text NULL,
    merge boolean NULL,
    parents text[] NULL,
    num_lines_added int NULL,
    num_lines_deleted int NULL,
    dmm_unit_complexity float NULL,
    dmm_unit_interfacing float NULL,
    dmm_unit_size float NULL,
    CONSTRAINT commits_pkey PRIMARY KEY (hash, repo_url)
);

CREATE INDEX IF NOT EXISTS commit_hash_index ON public.commits USING btree (hash);
CREATE INDEX IF NOT EXISTS commit_repo_url_index ON public.commits USING btree (repo_url);

-- ---------------------------------------------------------------------------
-- Repository table (matches constants.py REPO_COLUMNS and DataDictionary)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.repository (
    repo_url varchar NOT NULL PRIMARY KEY,
    repo_name varchar NULL,
    description text NULL,
    date_created timestamptz NULL,
    date_last_push timestamptz NULL,
    homepage varchar NULL,
    repo_language varchar NULL,
    owner varchar NULL,
    forks_count int NULL,
    stars_count int NULL
);

-- ---------------------------------------------------------------------------
-- File change table (matches constants.py FILE_COLUMNS and collect_projects.py INSERT)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.file_change (
    file_change_id bigint NOT NULL PRIMARY KEY,
    hash varchar(40) NOT NULL,
    filename varchar NULL,
    old_path varchar NULL,
    new_path varchar NULL,
    change_type varchar NULL,
    diff text NULL,
    diff_parsed text NULL,
    num_lines_added int NULL,
    num_lines_deleted int NULL,
    code_after text NULL,
    code_before text NULL,
    nloc int NULL,
    complexity int NULL,
    token_count int NULL,
    programming_language varchar NULL
);

CREATE INDEX IF NOT EXISTS file_change_hash_index ON public.file_change USING btree (hash);

-- ---------------------------------------------------------------------------
-- Method change table (matches constants.py METHOD_COLUMNS and DataDictionary)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.method_change (
    method_change_id bigint NOT NULL PRIMARY KEY,
    file_change_id bigint NOT NULL,
    name varchar NULL,
    signature text NULL,
    parameters text NULL,
    start_line int NULL,
    end_line int NULL,
    code text NULL,
    nloc int NULL,
    complexity int NULL,
    token_count int NULL,
    top_nesting_level int NULL,
    before_change varchar NULL
);

CREATE INDEX IF NOT EXISTS method_change_file_id_index ON public.method_change USING btree (file_change_id);

-- ---------------------------------------------------------------------------
-- CVE-project mapping table (from Code/resources/cveprojectdatabase.py)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS cve_project (
    id SERIAL PRIMARY KEY,
    cve VARCHAR(30) NOT NULL,
    project_url VARCHAR(500) NOT NULL,
    rel_type VARCHAR(255),
    checked VARCHAR(255) DEFAULT 'False',
    UNIQUE (cve, project_url)
);

-- ---------------------------------------------------------------------------
-- CPE-project mapping table
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS cpe_project (
    cpe_name VARCHAR(255) NOT NULL,
    repo_url VARCHAR(512) NOT NULL,
    rel_type VARCHAR(255) NOT NULL,
    UNIQUE (cpe_name, repo_url)
);

-- ---------------------------------------------------------------------------
-- CVE-CPE mapper table
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS cve_cpe_mapper (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(30) NOT NULL,
    cpe_name text NOT NULL,
    UNIQUE (cve_id, cpe_name)
);

-- ---------------------------------------------------------------------------
-- Fixes table (from Code/collect_projects.py create_fixes_table)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fixes (
    cve_id text,
    hash text,
    repo_url text,
    rel_type text DEFAULT 'TBL_DIRECT_COMMIT',
    extraction_status text DEFAULT 'NOT_STARTED',
    score int DEFAULT 0,
    UNIQUE (cve_id, repo_url, hash)
);

CREATE INDEX IF NOT EXISTS cve_id_index ON fixes (cve_id);
