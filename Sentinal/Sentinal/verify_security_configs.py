"""
Script to verify security configurations in the database.
"""
from app import app, db
from models import SecurityConfig

def verify_security_configs():
    """Verify that security configurations exist and print their details."""
    with app.app_context():
        configs = SecurityConfig.query.all()
        
        if not configs:
            print("No security configurations found in the database.")
            print("Run 'python seed_security_configs.py' to create default configurations.")
            return
        
        print(f"Found {len(configs)} security configuration(s):")
        print("-" * 50)
        
        for config in configs:
            print(f"Config: {config.name} (Role: {config.role})")
            print(f"  Memory limit: {config.mem_limit}")
            print(f"  CPU quota: {config.cpu_quota / 1000}%")
            print(f"  Process limit: {config.pids_limit}")
            print(f"  Timeout: {config.timeout}s")
            print(f"  Network access: {config.network_access}")
            print(f"  File write allowed: {config.allow_file_write}")
            print(f"  Capabilities restricted: {config.restrict_capabilities}")
            print(f"  Seccomp profile: {config.seccomp_profile}")
            
            # Check for additional mounts
            if config.additional_mounts:
                print("  Additional mounts:")
                for source, details in config.additional_mounts.items():
                    print(f"    {source} -> {details['target']} ({details.get('mode', 'ro')})")
            else:
                print("  No additional mounts")
            
            print("-" * 50)

if __name__ == "__main__":
    verify_security_configs()