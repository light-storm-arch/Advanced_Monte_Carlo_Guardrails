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

-- ---- Teams policies ----

-- Users can see teams they belong to
CREATE POLICY "Users can view their teams" ON teams
  FOR SELECT USING (
    id IN (SELECT team_id FROM team_members WHERE user_id = auth.uid())
  );

-- Any authenticated user can create a team
CREATE POLICY "Users can create teams" ON teams
  FOR INSERT WITH CHECK (auth.uid() = created_by);

-- ---- Team Members policies ----

-- Users can see members of teams they belong to
CREATE POLICY "Users can view team members" ON team_members
  FOR SELECT USING (
    team_id IN (SELECT team_id FROM team_members AS tm WHERE tm.user_id = auth.uid())
  );

-- Admins can add members to their team
CREATE POLICY "Admins can add team members" ON team_members
  FOR INSERT WITH CHECK (
    team_id IN (
      SELECT team_id FROM team_members AS tm
      WHERE tm.user_id = auth.uid() AND tm.role = 'admin'
    )
    OR
    -- Allow users to add themselves when accepting an invitation
    (user_id = auth.uid() AND team_id IN (
      SELECT team_id FROM invitations
      WHERE email = (SELECT email FROM auth.users WHERE id = auth.uid())
      AND status = 'pending'
    ))
  );

-- Admins can remove members (but not themselves)
CREATE POLICY "Admins can remove team members" ON team_members
  FOR DELETE USING (
    team_id IN (
      SELECT team_id FROM team_members AS tm
      WHERE tm.user_id = auth.uid() AND tm.role = 'admin'
    )
  );

-- ---- Clients policies ----

-- All team members can view clients in their team
CREATE POLICY "Team members can view clients" ON clients
  FOR SELECT USING (
    team_id IN (SELECT team_id FROM team_members WHERE user_id = auth.uid())
  );

-- All team members can create clients in their team
CREATE POLICY "Team members can create clients" ON clients
  FOR INSERT WITH CHECK (
    team_id IN (SELECT team_id FROM team_members WHERE user_id = auth.uid())
  );

-- All team members can update clients in their team
CREATE POLICY "Team members can update clients" ON clients
  FOR UPDATE USING (
    team_id IN (SELECT team_id FROM team_members WHERE user_id = auth.uid())
  );

-- All team members can delete clients in their team
CREATE POLICY "Team members can delete clients" ON clients
  FOR DELETE USING (
    team_id IN (SELECT team_id FROM team_members WHERE user_id = auth.uid())
  );

-- ---- Invitations policies ----

-- Admins can view all invitations for their team
CREATE POLICY "Admins can view invitations" ON invitations
  FOR SELECT USING (
    team_id IN (
      SELECT team_id FROM team_members
      WHERE user_id = auth.uid() AND role = 'admin'
    )
    OR
    -- Users can see invitations addressed to their email
    email = (SELECT email FROM auth.users WHERE id = auth.uid())
  );

-- Admins can create invitations
CREATE POLICY "Admins can create invitations" ON invitations
  FOR INSERT WITH CHECK (
    team_id IN (
      SELECT team_id FROM team_members
      WHERE user_id = auth.uid() AND role = 'admin'
    )
  );

-- Admins can update invitations (e.g., mark as expired)
CREATE POLICY "Admins can update invitations" ON invitations
  FOR UPDATE USING (
    team_id IN (
      SELECT team_id FROM team_members
      WHERE user_id = auth.uid() AND role = 'admin'
    )
    OR
    -- Users can accept their own invitations
    (email = (SELECT email FROM auth.users WHERE id = auth.uid()) AND status = 'pending')
  );

-- Admins can delete invitations
CREATE POLICY "Admins can delete invitations" ON invitations
  FOR DELETE USING (
    team_id IN (
      SELECT team_id FROM team_members
      WHERE user_id = auth.uid() AND role = 'admin'
    )
  );
