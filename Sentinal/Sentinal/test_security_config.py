"""
Test script to verify the security configuration functionality.
Run this script to test the security configuration lookup in docker container creation.
"""
from app import app, db
from models import User, SecurityConfig, ExecutionHistory, Script
import datetime
import os
import time
import json

def test_security_config_lookup():
    print("Testing security configuration lookup for different user roles...")
    
    with app.app_context():
        # Create dummy users with different roles if they don't exist
        users = {
            'user': User.query.filter_by(email='test_user@example.com').first(),
            'admin': User.query.filter_by(email='test_admin@example.com').first(),
            'super_admin': User.query.filter_by(email='test_super@example.com').first()
        }
        
        if not users['user']:
            users['user'] = User(
                email='test_user@example.com',
                role='user'
            )
            users['user'].password_hash = 'dummy_hash'  # Not a real password
            db.session.add(users['user'])
        
        if not users['admin']:
            users['admin'] = User(
                email='test_admin@example.com',
                role='admin'
            )
            users['admin'].password_hash = 'dummy_hash'  # Not a real password
            db.session.add(users['admin'])
        
        if not users['super_admin']:
            users['super_admin'] = User(
                email='test_super@example.com',
                role='super_admin'
            )
            users['super_admin'].password_hash = 'dummy_hash'  # Not a real password
            db.session.add(users['super_admin'])
        
        # Create a test script if it doesn't exist
        script = Script.query.filter_by(name='Test Security Script').first()
        if not script:
            script = Script(
                name='Test Security Script',
                description='Script for testing security configurations',
                code='print("Hello from test script")\nprint("PROFIT: {\\"profit\\": 10.0}")',
                version='1.0',
                user_id=users['user'].id,
                public=True,
                price=0.0
            )
            db.session.add(script)
        
        # Commit to get IDs
        db.session.commit()
        
        # Test security config lookup for each user role
        for role, user in users.items():
            print(f"\nTesting security config for role: {role}")
            
            # Get the security config for this role
            security_config = SecurityConfig.query.filter_by(role=role).first()
            
            if security_config:
                print(f"Found security config: {security_config.name}")
                print(f"Memory limit: {security_config.mem_limit}")
                print(f"CPU quota: {security_config.cpu_quota / 1000}%")
                print(f"Process limit: {security_config.pids_limit}")
                print(f"Timeout: {security_config.timeout}s")
                print(f"Network access: {security_config.network_access}")
                print(f"File write allowed: {security_config.allow_file_write}")
                print(f"Capabilities restricted: {security_config.restrict_capabilities}")
                print(f"Seccomp profile: {security_config.seccomp_profile}")
                
                # Check for additional mounts
                if security_config.additional_mounts:
                    print("Additional mounts:")
                    for source, details in security_config.additional_mounts.items():
                        print(f"  {source} -> {details['target']} ({details.get('mode', 'ro')})")
                else:
                    print("No additional mounts")
            else:
                print(f"No security config found for role: {role}")
        
        print("\nTest completed.")

if __name__ == '__main__':
    test_security_config_lookup()