-- =============================================================================
-- FIX: RLS Infinite Recursion on team_members
-- =============================================================================
-- Paste this ENTIRE script into your Supabase SQL Editor and click Run.
-- It drops the old policies and recreates them using helper functions
-- that avoid the infinite recursion problem.
-- =============================================================================

-- Step 1: Drop ALL existing policies (safe to run even if they don't exist)
DROP POLICY IF EXISTS "Users can view their teams" ON teams;
DROP POLICY IF EXISTS "Users can create teams" ON teams;
DROP POLICY IF EXISTS "Users can view team members" ON team_members;
DROP POLICY IF EXISTS "Admins can add team members" ON team_members;
DROP POLICY IF EXISTS "Admins can remove team members" ON team_members;
DROP POLICY IF EXISTS "Team members can view clients" ON clients;
DROP POLICY IF EXISTS "Team members can create clients" ON clients;
DROP POLICY IF EXISTS "Team members can update clients" ON clients;
DROP POLICY IF EXISTS "Team members can delete clients" ON clients;
DROP POLICY IF EXISTS "Admins can view invitations" ON invitations;
DROP POLICY IF EXISTS "Admins can create invitations" ON invitations;
DROP POLICY IF EXISTS "Admins can update invitations" ON invitations;
DROP POLICY IF EXISTS "Admins can delete invitations" ON invitations;

-- Step 2: Create helper functions with SECURITY DEFINER (bypasses RLS)

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

-- Step 3: Recreate all policies using the helper functions

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
