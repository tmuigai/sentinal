"""
Seed script to create initial security configurations in the database
"""
from app import app, db
from models import SecurityConfig

def create_security_configs():
    """Create standard security configurations for different user roles"""
    
    # Check if configs already exist
    existing_configs = SecurityConfig.query.all()
    if existing_configs:
        print(f"Security configurations already exist ({len(existing_configs)} found)")
        return
    
    # Create configs for each role
    configs = [
        # Standard user configuration - minimal permissions, strict limits
        {
            'name': 'Standard User',
            'role': 'user',
            'mem_limit': '256m',           # 256MB memory limit
            'cpu_quota': 25000,            # 25% CPU quota
            'pids_limit': 50,              # Max 50 processes
            'timeout': 300,                # 5 minute timeout
            'network_access': False,       # No network access
            'allow_file_write': False,     # Read-only filesystem
            'restrict_capabilities': True, # Drop all capabilities except minimal set
            'seccomp_profile': 'default',  # Default seccomp profile
            'additional_mounts': {},       # No additional mounts
        },
        
        # Admin configuration - more resources, some filesystem access
        {
            'name': 'Admin User',
            'role': 'admin',
            'mem_limit': '1g',             # 1GB memory limit
            'cpu_quota': 50000,            # 50% CPU quota
            'pids_limit': 100,             # Max 100 processes
            'timeout': 600,                # 10 minute timeout
            'network_access': False,       # Still no network access for safety
            'allow_file_write': True,      # Allow filesystem writes
            'restrict_capabilities': True, # Still drop capabilities for safety
            'seccomp_profile': 'default',  # Default seccomp profile
            'additional_mounts': {},       # No additional mounts
        },
        
        # Super admin configuration - maximum resources, full access
        {
            'name': 'Super Admin',
            'role': 'super_admin',
            'mem_limit': '2g',             # 2GB memory limit
            'cpu_quota': 75000,            # 75% CPU quota
            'pids_limit': 200,             # Max 200 processes
            'timeout': 1200,               # 20 minute timeout
            'network_access': True,        # Allow network access
            'allow_file_write': True,      # Allow filesystem writes
            'restrict_capabilities': False, # Don't restrict capabilities
            'seccomp_profile': 'none',     # No seccomp profile
            'additional_mounts': {         # Additional mounts
                '/data': {'target': '/mount/data', 'mode': 'rw'},
                '/cache': {'target': '/mount/cache', 'mode': 'rw'},
            },
        }
    ]
    
    # Add configs to database
    for config_data in configs:
        config = SecurityConfig(**config_data)
        db.session.add(config)
    
    db.session.commit()
    print(f"Created {len(configs)} security configurations")

if __name__ == '__main__':
    with app.app_context():
        create_security_configs()