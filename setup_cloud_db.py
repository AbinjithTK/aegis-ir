"""Run database migrations on Cloud SQL."""
import asyncio
import asyncpg

DB_URL = "postgresql://aegis:AegisIR2025!@35.192.22.130:5432/aegis_ir"

async def main():
    print("Connecting to Cloud SQL...")
    conn = await asyncpg.connect(DB_URL)
    print("Connected!")

    # Run migration 001: Initial schema
    import importlib.util
    import os

    migrations_dir = os.path.join("src", "sift_defender", "enterprise", "migrations", "versions")

    def load_migration(filename):
        spec = importlib.util.spec_from_file_location("migration", os.path.join(migrations_dir, filename))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    class ConnWrapper:
        def __init__(self):
            self.statements = []
        def execute(self, sql):
            self.statements.append(sql)

    # Run 001
    print("Running migration 001 (tenants, users, roles, user_roles)...")
    wrapper = ConnWrapper()
    m001 = load_migration("001_initial_schema.py")
    m001.upgrade(wrapper)
    for stmt in wrapper.statements:
        try:
            await conn.execute(stmt)
        except Exception as e:
            if "already exists" in str(e):
                pass
            else:
                print(f"  Warning: {str(e)[:80]}")
    print(f"  Executed {len(wrapper.statements)} statements")

    # Run 002: Seed default roles
    print("Running migration 002 (seed default roles)...")
    wrapper = ConnWrapper()
    m002 = load_migration("002_seed_default_roles.py")
    m002.upgrade(wrapper)
    for stmt in wrapper.statements:
        try:
            await conn.execute(stmt)
        except Exception as e:
            if "already exists" in str(e) or "duplicate" in str(e).lower():
                pass
            else:
                print(f"  Warning: {str(e)[:80]}")
    print(f"  Executed {len(wrapper.statements)} statements")

    # Run 004: Audit log
    print("Running migration 004 (audit log)...")
    wrapper = ConnWrapper()
    m004 = load_migration("004_audit_log.py")
    m004.upgrade(wrapper)
    for stmt in wrapper.statements:
        try:
            await conn.execute(stmt)
        except Exception as e:
            if "already exists" in str(e):
                pass
            else:
                print(f"  Warning: {str(e)[:80]}")
    print(f"  Executed {len(wrapper.statements)} statements")

    # Create a demo user for login
    print("Creating demo user...")
    import bcrypt
    password_hash = bcrypt.hashpw(b"demo123", bcrypt.gensalt()).decode()

    # Create tenant
    await conn.execute("""
        INSERT INTO tenants (id, name) VALUES ('00000000-0000-0000-0000-000000000001', 'Demo Organization')
        ON CONFLICT (id) DO NOTHING
    """)

    # Create user
    await conn.execute(f"""
        INSERT INTO users (id, tenant_id, email, password_hash, is_active)
        VALUES ('00000000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-000000000001', 'demo@aegis-ir.com', '{password_hash}', true)
        ON CONFLICT DO NOTHING
    """)

    # Assign ir_lead role
    role_id = await conn.fetchval("""
        SELECT id FROM roles WHERE tenant_id = '00000000-0000-0000-0000-000000000001' AND name = 'ir_lead' LIMIT 1
    """)
    if role_id:
        await conn.execute(f"""
            INSERT INTO user_roles (user_id, role_id, tenant_id)
            VALUES ('00000000-0000-0000-0000-000000000002', '{role_id}', '00000000-0000-0000-0000-000000000001')
            ON CONFLICT DO NOTHING
        """)
        print(f"  User demo@aegis-ir.com created with ir_lead role")
    else:
        print("  No ir_lead role found - seeding may not have worked")

    # Verify
    count = await conn.fetchval("SELECT COUNT(*) FROM tenants")
    print(f"\nDatabase ready! Tenants: {count}")
    users = await conn.fetchval("SELECT COUNT(*) FROM users")
    print(f"Users: {users}")
    roles = await conn.fetchval("SELECT COUNT(*) FROM roles")
    print(f"Roles: {roles}")

    await conn.close()
    print("\nDone! Cloud SQL is ready.")
    print("Demo login: demo@aegis-ir.com / demo123")

import sys
sys.path.insert(0, '.')
sys.path.insert(0, 'src')
asyncio.run(main())
