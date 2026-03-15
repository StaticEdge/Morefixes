-- Extracted from prospector/ddl/20_users.sql
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

-- Extracted from prospector/ddl/10_commit.sql
DROP TABLE IF EXISTS public.commits;

CREATE TABLE public.commits (
	commit_id varchar(40) NOT NULL,
	repository varchar NOT NULL,
	timestamp int,
	-- preprocessed data
	hunks int,
	message varchar NULL,
	diff varchar[] NULL,
	changed_files varchar[] NULL,
	message_reference_content varchar[] NULL,
	jira_refs jsonb NULL,
	ghissue_refs jsonb NULL,
	cve_refs varchar[] NULL,
	tags varchar[] NULL,
	minhash varchar NULL,
	CONSTRAINT commits_pkey PRIMARY KEY (commit_id, repository)
);

CREATE INDEX IF NOT EXISTS commit_index ON public.commits USING btree (commit_id);
CREATE UNIQUE INDEX IF NOT EXISTS commit_repository_index ON public.commits USING btree (commit_id, repository);
CREATE INDEX IF NOT EXISTS repository_index ON public.commits USING btree (repository);

-- Extracted from Code/resources/cveprojectdatabase.py
CREATE TABLE IF NOT EXISTS cve_project (
    id SERIAL PRIMARY KEY,
    cve VARCHAR(30) NOT NULL,
    project_url VARCHAR(500) NOT NULL,
    rel_type VARCHAR(255),
    checked VARCHAR(255) DEFAULT 'False',
    UNIQUE (cve, project_url)
);

CREATE TABLE IF NOT EXISTS cpe_project (
    cpe_name VARCHAR(255) NOT NULL,
    repo_url VARCHAR(512) NOT NULL,
    rel_type VARCHAR(255) NOT NULL,
    UNIQUE (cpe_name, repo_url)
);

CREATE TABLE IF NOT EXISTS cve_cpe_mapper (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(30) NOT NULL,
    cpe_name text NOT NULL,
    UNIQUE (cve_id, cpe_name)
);

-- Extracted from Code/collect_projects.py
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
