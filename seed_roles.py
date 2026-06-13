"""Seed default roles and assign to demo user."""
import asyncio
import asyncpg

DB_URL = "postgresql://aegis:AegisIR2025!@35.192.22.130:5432/aegis_ir"

async def main():
    conn = await asyncpg.connect(DB_URL)

    tenant_id = "00000000-0000-0000-0000-000000000001"

    # Seed roles
    roles = {
        "soc_analyst": "{investigation:start,investigation:view,finding:approve,finding:reject,case:create,playbook:view,evidence:access}",
        "ir_lead": "{investigation:start,investigation:view,finding:approve,finding:reject,case:create,case:manage,case:assign,playbook:view,playbook:edit,settings:view,settings:edit,audit:view,evidence:access,user:manage}",
        "ciso": "{investigation:view,audit:view,audit:export,report:executive}",
    }

    for name, perms in roles.items():
        await conn.execute(f"""
            INSERT INTO roles (id, tenant_id, name, permissions, is_default)
            VALUES (uuid_generate_v4(), '{tenant_id}'::uuid, '{name}', '{perms}', TRUE)
            ON CONFLICT (tenant_id, name) DO NOTHING
        """)
        print(f"  Seeded role: {name}")

    # Assign ir_lead to demo user
    role_id = await conn.fetchval(f"SELECT id FROM roles WHERE tenant_id = '{tenant_id}' AND name = 'ir_lead'")
    if role_id:
        await conn.execute(f"""
            INSERT INTO user_roles (user_id, role_id)
            VALUES ('00000000-0000-0000-0000-000000000002', '{role_id}')
            ON CONFLICT DO NOTHING
        """)
        print(f"  Assigned ir_lead to demo user")

    # Verify
    roles_count = await conn.fetchval("SELECT COUNT(*) FROM roles")
    print(f"\nRoles: {roles_count}")
    user_roles = await conn.fetchval("SELECT COUNT(*) FROM user_roles")
    print(f"User-Role assignments: {user_roles}")

    await conn.close()
    print("Done!")

asyncio.run(main())
