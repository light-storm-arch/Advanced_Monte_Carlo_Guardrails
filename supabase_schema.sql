-- =============================================================================
-- Supabase Schema for Team Logins & Client Persistence
-- Run this in your Supabase SQL Editor (Dashboard > SQL Editor > New Query)
-- =============================================================================

-- 1. Teams table
CREATE TABLE teams (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  name TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT now(),
  created_by UUID REFERENCES auth.users(id)
);

-- 2. Team members table (links auth users to teams)
CREATE TABLE team_members (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  team_id UUID REFERENCES teams(id) ON DELETE CASCADE NOT NULL,
  user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL,
  role TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('admin', 'member')),
  email TEXT NOT NULL,
  display_name TEXT,
  created_at TIMESTAMPTZ DEFAULT now(),
  UNIQUE(team_id, user_id)
);

-- 3. Invitations table (admin invites members by email)
CREATE TABLE invitations (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  team_id UUID REFERENCES teams(id) ON DELETE CASCADE NOT NULL,
  email TEXT NOT NULL,
  invited_by UUID REFERENCES auth.users(id) NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'accepted', 'expired')),
  created_at TIMESTAMPTZ DEFAULT now(),
  UNIQUE(team_id, email)
);

-- 4. Clients table (financial planning clients with all plan data as JSONB)
CREATE TABLE clients (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  team_id UUID REFERENCES teams(id) ON DELETE CASCADE NOT NULL,
  created_by UUID REFERENCES auth.users(id) NOT NULL,
  updated_by UUID REFERENCES auth.users(id),
  client_name TEXT NOT NULL,
  plan_data JSONB NOT NULL DEFAULT '{}',
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now()
);

-- =============================================================================
-- Auto-update trigger for updated_at on clients
-- =============================================================================
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER clients_updated_at
  BEFORE UPDATE ON clients
  FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- =============================================================================
-- Row Level Security (RLS)
-- =============================================================================

-- Enable RLS on all tables
ALTER TABLE teams ENABLE ROW LEVEL SECURITY;
ALTER TABLE team_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE clients ENABLE ROW LEVEL SECURITY;
ALTER TABLE invitations ENABLE ROW LEVEL SECURITY;

-- =============================================================================
-- Helper functions (SECURITY DEFINER bypasses RLS to avoid infinite recursion)
-- =============================================================================

-- Returns all team_ids the given user belongs to
CREATE OR REPLACE FUNCTION get_user_team_ids(uid UUID)
RETURNS SETOF UUID
LANGUAGE sql
SECURITY DEFINER
STABLE
SET search_path = public
AS $$
  SELECT team_id FROM team_members WHERE user_id = uid;
$$;

-- Returns true if the given user is an admin of the given team
CREATE OR REPLACE FUNCTION is_team_admin(uid UUID, tid UUID)
RETURNS BOOLEAN
LANGUAGE sql
SECURITY DEFINER
STABLE
SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1 FROM team_members WHERE user_id = uid AND team_id = tid AND role = 'admin'
  );
$$;

-- =============================================================================
-- Policies
-- =============================================================================

-- ---- Teams policies ----

CREATE POLICY "Users can view their teams" ON teams
  FOR SELECT USING (
    id IN (SELECT get_user_team_ids(auth.uid()))
    OR created_by = auth.uid()
  );

CREATE POLICY "Users can create teams" ON teams
  FOR INSERT WITH CHECK (auth.uid() = created_by);

-- ---- Team Members policies ----

CREATE POLICY "Users can view team members" ON team_members
  FOR SELECT USING (
    team_id IN (SELECT get_user_team_ids(auth.uid()))
    OR team_id IN (SELECT id FROM teams WHERE created_by = auth.uid())
  );

CREATE POLICY "Admins can add team members" ON team_members
  FOR INSERT WITH CHECK (
    -- Existing admins can add members
    is_team_admin(auth.uid(), team_id)
    OR
    -- Team creator can add themselves as the first member
    (user_id = auth.uid() AND team_id IN (
      SELECT id FROM teams WHERE created_by = auth.uid()
    ))
    OR
    -- Users can add themselves when accepting an invitation
    (user_id = auth.uid() AND team_id IN (
      SELECT team_id FROM invitations
      WHERE email = (auth.jwt() ->> 'email')
      AND status = 'pending'
    ))
  );

CREATE POLICY "Admins can remove team members" ON team_members
  FOR DELETE USING (
    is_team_admin(auth.uid(), team_id)
  );

-- ---- Clients policies ----

CREATE POLICY "Team members can view clients" ON clients
  FOR SELECT USING (
    team_id IN (SELECT get_user_team_ids(auth.uid()))
  );

CREATE POLICY "Team members can create clients" ON clients
  FOR INSERT WITH CHECK (
    team_id IN (SELECT get_user_team_ids(auth.uid()))
  );

CREATE POLICY "Team members can update clients" ON clients
  FOR UPDATE USING (
    team_id IN (SELECT get_user_team_ids(auth.uid()))
  );

CREATE POLICY "Team members can delete clients" ON clients
  FOR DELETE USING (
    team_id IN (SELECT get_user_team_ids(auth.uid()))
  );

-- ---- Invitations policies ----

CREATE POLICY "Admins can view invitations" ON invitations
  FOR SELECT USING (
    is_team_admin(auth.uid(), team_id)
    OR
    email = (auth.jwt() ->> 'email')
  );

CREATE POLICY "Admins can create invitations" ON invitations
  FOR INSERT WITH CHECK (
    is_team_admin(auth.uid(), team_id)
  );

CREATE POLICY "Admins can update invitations" ON invitations
  FOR UPDATE USING (
    is_team_admin(auth.uid(), team_id)
    OR
    (email = (auth.jwt() ->> 'email') AND status = 'pending')
  );

CREATE POLICY "Admins can delete invitations" ON invitations
  FOR DELETE USING (
    is_team_admin(auth.uid(), team_id)
  );
