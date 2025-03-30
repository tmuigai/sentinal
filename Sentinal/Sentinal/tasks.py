import os
import time
import json
from datetime import datetime
from celery import shared_task
import docker
from app import app, db, socketio
from models import ExecutionHistory, Script, User, Profit, SecurityConfig
from utils import calculate_profit_share, distribute_admin_fees

# Mock Docker client for Replit environment
class MockContainer:
    def __init__(self, script_path, env_vars, config=None):
        self.id = f"mock-container-{int(time.time())}"
        self.script_path = script_path
        self.env_vars = env_vars
        self.config = config or {}
        self._result = {'StatusCode': 0}
        self._logs = ""
        self._killed = False
        self._started_at = None
        self._process = None
    
    def wait(self):
        """Wait for the script to finish and return the result"""
        import subprocess
        import sys
        import resource
        import signal
        import threading
        import time
        
        # Set environment variables
        exec_env = os.environ.copy()
        exec_env.update(self.env_vars)
        
        # Get resource limits from config
        mem_limit = self.config.get('mem_limit', '256m')
        cpu_quota = self.config.get('cpu_quota', 25000)
        pids_limit = self.config.get('pids_limit', 50)
        timeout = self.config.get('timeout', 300)
        
        # Convert memory limit to bytes for resource limiting
        if isinstance(mem_limit, str):
            if mem_limit.endswith('m'):
                mem_bytes = int(mem_limit[:-1]) * 1024 * 1024
            elif mem_limit.endswith('g'):
                mem_bytes = int(mem_limit[:-1]) * 1024 * 1024 * 1024
            else:
                mem_bytes = int(mem_limit)
        else:
            mem_bytes = 256 * 1024 * 1024  # Default to 256MB
        
        try:
            # Set resource limits similar to Docker constraints
            def preexec_fn():
                """Set resource limits before executing the script"""
                # Set memory limit
                resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
                
                # Set CPU time limit (approximate based on quota)
                cpu_seconds = max(30, int(timeout * cpu_quota / 100000))
                resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds))
                
                # Set process limit
                resource.setrlimit(resource.RLIMIT_NPROC, (pids_limit, pids_limit))
                
                # Set open files limit
                resource.setrlimit(resource.RLIMIT_NOFILE, (1024, 1024))
                
                # Apply additional security measures
                restrict_capabilities = self.config.get('restrict_capabilities', True)
                
                # Create a new process group for easier killing
                os.setpgrp()
            
            # Apply network restrictions if configured
            network_access = self.config.get('network_access', False)
            
            # Start the process with proper environment and restrictions
            self._started_at = time.time()
            self._process = subprocess.Popen(
                [sys.executable, self.script_path], 
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=exec_env,
                preexec_fn=preexec_fn,
                text=True
            )
            
            # Log the security settings for debugging
            security_settings = {
                "mem_limit": self.config.get('mem_limit', '256m'),
                "cpu_quota": self.config.get('cpu_quota', 25000),
                "pids_limit": self.config.get('pids_limit', 50),
                "timeout": self.config.get('timeout', 300),
                "network_access": network_access,
                "read_only": self.config.get('read_only', True),
                "restrict_capabilities": self.config.get('restrict_capabilities', True),
            }
            app.logger.debug(f"Container started with security settings: {security_settings}")
            
            # Set up timeout
            timer = None
            if timeout:
                def on_timeout():
                    """Kill the process when timeout is reached"""
                    self._killed = True
                    try:
                        if self._process and self._process.poll() is None:
                            # Kill the entire process group
                            os.killpg(os.getpgid(self._process.pid), signal.SIGKILL)
                    except Exception as e:
                        app.logger.error(f"Error killing process after timeout: {str(e)}")
                
                timer = threading.Timer(timeout, on_timeout)
                timer.daemon = True
                timer.start()
            
            # Wait for process to complete
            stdout, stderr = self._process.communicate()
            self._logs = stdout
            if stderr:
                self._logs += "\n" + stderr
            
            # Cancel timer if process completed before timeout
            if timer and timer.is_alive():
                timer.cancel()
            
            if self._killed:
                self._logs += f"\n\n*** EXECUTION TIMED OUT AFTER {timeout} SECONDS ***\n"
                self._result = {'StatusCode': 137, 'Error': 'Timeout'}  # SIGKILL exit code
            else:
                self._result = {'StatusCode': self._process.returncode}
                
            # Add information about resource usage
            execution_time = time.time() - self._started_at
            self._logs += f"\n\n=== Execution Summary ===\n"
            self._logs += f"Execution time: {execution_time:.2f} seconds\n"
            self._logs += f"Exit code: {self._result['StatusCode']}\n"
            
        except Exception as e:
            self._logs = f"Error executing script: {str(e)}"
            self._result = {'StatusCode': 1, 'Error': str(e)}
        
        return self._result
    
    def logs(self):
        """Return container logs as bytes"""
        return self._logs.encode('utf-8')
    
    def kill(self):
        """Kill the running process"""
        if self._process and self._process.poll() is None:
            try:
                import signal
                # Kill the entire process group
                os.killpg(os.getpgid(self._process.pid), signal.SIGKILL)
                self._killed = True
            except Exception as e:
                app.logger.error(f"Error killing process: {str(e)}")
    
    def remove(self):
        """Clean up resources (similar to Docker container removal)"""
        # Nothing to do in the mock implementation
        pass

class MockDockerClient:
    def __init__(self):
        self.containers = MockContainerClient()

class MockContainerClient:
    def run(self, image, command, volumes, environment, detach, mem_limit, cpu_period, cpu_quota, 
            network_mode, pids_limit=None, read_only=None, tmpfs=None, 
            cap_drop=None, cap_add=None, security_opt=None, ulimits=None):
        # Extract script path from volumes
        script_dir = list(volumes.keys())[0]
        script_filename = command.split('/')[-1]
        script_path = os.path.join(script_dir, script_filename)
        
        # Create config dictionary for resource limits
        config = {
            'mem_limit': mem_limit,
            'cpu_period': cpu_period,
            'cpu_quota': cpu_quota,
            'network_mode': network_mode,
            'pids_limit': pids_limit,
            'read_only': read_only,
            'tmpfs': tmpfs,
            'cap_drop': cap_drop,
            'cap_add': cap_add,
            'security_opt': security_opt,
            'ulimits': ulimits
        }
        
        return MockContainer(script_path, environment, config)

# Initialize Docker client or mock
docker_client = None
try:
    docker_client = docker.from_env()
    app.logger.info("Docker client initialized successfully")
except:
    app.logger.warning("Docker not available. Using mock Docker client for Replit environment")
    docker_client = MockDockerClient()

@shared_task
def execute_script_task(execution_id):
    """
    Celery task to execute a script in a Docker container.
    
    Args:
        execution_id: ID of the ExecutionHistory record
    """
    with app.app_context():
        execution = ExecutionHistory.query.get(execution_id)
        if not execution:
            app.logger.error(f"Execution {execution_id} not found")
            return
        
        script = Script.query.get(execution.script_id)
        user = User.query.get(execution.user_id)
        
        try:
            # Update execution status
            execution.status = 'running'
            db.session.commit()
            
            # Emit WebSocket event for status update
            socketio.emit('execution_update', {
                'execution_id': execution.id,
                'status': 'running',
                'message': 'Execution started'
            }, room=str(execution.id))
            
            # Create a temporary script file
            script_dir = os.path.join(app.instance_path, 'scripts')
            os.makedirs(script_dir, exist_ok=True)
            
            script_filename = f"{script.id}_{int(time.time())}.py"
            script_path = os.path.join(script_dir, script_filename)
            
            with open(script_path, 'w') as f:
                f.write(script.code)
            
            # Prepare parameters as environment variables
            env_vars = {}
            if execution.parameters_used:
                for key, value in execution.parameters_used.items():
                    env_vars[key] = str(value)
            
            # Run script in Docker container
            if docker_client:
                # Get security configuration for the user's role
                security_config = SecurityConfig.query.filter_by(role=user.role).first()
                
                # If no config exists for this role, use the default 'user' config
                if not security_config:
                    security_config = SecurityConfig.query.filter_by(role='user').first()
                    
                # If still no config exists, use hardcoded defaults
                if security_config:
                    # Use the security config from the database
                    mem_limit = security_config.mem_limit
                    cpu_quota = security_config.cpu_quota
                    pids_limit = security_config.pids_limit
                    timeout = security_config.timeout
                    network_access = security_config.network_access
                    allow_file_write = security_config.allow_file_write
                    restrict_capabilities = security_config.restrict_capabilities
                    seccomp_profile = security_config.seccomp_profile
                    additional_mounts = security_config.additional_mounts or {}
                else:
                    # Fallback to default values
                    mem_limit = '256m'  # Default memory limit
                    cpu_quota = 25000   # Default CPU quota (25% of CPU)
                    pids_limit = 50     # Default process limit
                    timeout = 300       # Default timeout (5 minutes)
                    network_access = False
                    allow_file_write = False
                    restrict_capabilities = True
                    seccomp_profile = 'default'
                    additional_mounts = {}
                
                # Prepare volumes with additional mounts from security config
                volumes = {
                    script_dir: {'bind': '/scripts', 'mode': 'ro'}  # Read-only script volume
                }
                
                # Add additional mounts from security config
                if additional_mounts:
                    for source, details in additional_mounts.items():
                        volumes[source] = {'bind': details['target'], 'mode': details.get('mode', 'ro')}
                
                # Prepare security options
                security_opts = ['no-new-privileges=true']
                if seccomp_profile != 'none':
                    security_opts.append(f'seccomp={seccomp_profile}')
                
                # Prepare capabilities
                cap_drop = ['ALL'] if restrict_capabilities else []
                cap_add = ['CHOWN', 'SETGID', 'SETUID'] if restrict_capabilities else []
                
                # Create the secured container with configuration from security config
                container = docker_client.containers.run(
                    image='python:3.9-slim',  # Base Python image
                    command=f'python /scripts/{script_filename}',
                    volumes=volumes,
                    environment=env_vars,
                    detach=True,
                    # Resource limits
                    mem_limit=mem_limit,
                    cpu_period=100000,        # CPU period for quota calculation
                    cpu_quota=cpu_quota,      # CPU quota based on user role
                    pids_limit=pids_limit,    # Limit number of processes
                    # Security measures
                    network_mode=None if network_access else 'none',
                    read_only=not allow_file_write,  # Read-only filesystem unless allowed
                    tmpfs={                   # Temporary filesystem for /tmp
                        '/tmp': 'size=64m,exec,nodev,nosuid'
                    },
                    cap_drop=cap_drop,
                    cap_add=cap_add,
                    security_opt=security_opts,
                    # Ulimits
                    ulimits=[
                        {'name': 'nofile', 'soft': 1024, 'hard': 1024},  # File descriptor limits
                        {'name': 'nproc', 'soft': pids_limit, 'hard': pids_limit}  # Process limits
                    ]
                )
                
                execution.container_id = container.id
                db.session.commit()
                
                # Setup timeout handling for the container
                import threading
                timeout_event = threading.Event()
                timeout_reached = False
                
                def check_timeout():
                    """Monitor the container and kill it if timeout is reached"""
                    nonlocal timeout_reached
                    if not timeout_event.wait(timeout):
                        try:
                            # Timeout reached, kill the container
                            app.logger.warning(f"Script execution timed out after {timeout} seconds")
                            container.kill()
                            timeout_reached = True
                        except Exception as e:
                            app.logger.error(f"Error killing container after timeout: {str(e)}")
                
                # Start timeout thread
                timeout_thread = threading.Thread(target=check_timeout)
                timeout_thread.daemon = True
                timeout_thread.start()
                
                # Wait for container to finish
                result = container.wait()
                
                # Stop timeout thread
                timeout_event.set()
                timeout_thread.join(1.0)  # Join with 1s timeout
                
                # Get container logs
                logs = container.logs().decode('utf-8')
                
                # Add timeout message to logs if applicable
                if timeout_reached:
                    logs += "\n\n*** EXECUTION TIMED OUT AFTER " + str(timeout) + " SECONDS ***\n"
                    result = {'StatusCode': 1, 'Error': 'Timeout'}
                
                # Update execution record
                execution.logs = logs
                execution.completed_at = datetime.utcnow()
                
                if result['StatusCode'] == 0:
                    execution.status = 'success'
                    
                    # Extract profit information from logs
                    # Assuming script outputs JSON with profit info: {"profit": 100.0}
                    try:
                        for line in logs.strip().split('\n'):
                            if line.startswith('PROFIT:'):
                                profit_data = json.loads(line[7:].strip())
                                profit_amount = float(profit_data.get('profit', 0.0))
                                
                                if profit_amount > 0:
                                    # Calculate shares (70% to user, 30% to platform)
                                    user_share, platform_share = calculate_profit_share(profit_amount)
                                    
                                    # Update user balance
                                    user.balance += user_share
                                    
                                    # Record profit for the user
                                    profit = Profit(
                                        user_id=user.id,
                                        script_id=script.id,
                                        execution_id=execution.id,
                                        amount=user_share,
                                        profit_type='realized'
                                    )
                                    db.session.add(profit)
                                    
                                    # Distribute platform fees to admins (30%)
                                    distribute_admin_fees(
                                        platform_share=platform_share,
                                        script_id=script.id,
                                        execution_id=execution.id
                                    )
                                    
                                    break
                    except Exception as e:
                        app.logger.error(f"Error processing profit data: {str(e)}")
                else:
                    execution.status = 'failed'
                
                # Clean up container
                container.remove()
            else:
                # Fallback if Docker is not available (for development only)
                execution.logs = "Docker not available. Cannot execute script."
                execution.status = 'failed'
                execution.completed_at = datetime.utcnow()
            
            # Clean up temporary script file
            try:
                os.remove(script_path)
            except:
                pass
            
            db.session.commit()
            
            # Emit WebSocket event with final status
            socketio.emit('execution_update', {
                'execution_id': execution.id,
                'status': execution.status,
                'logs': execution.logs,
                'completed_at': execution.completed_at.isoformat() if execution.completed_at else None
            }, room=str(execution.id))
            
        except Exception as e:
            app.logger.error(f"Error executing script {script.id}: {str(e)}")
            
            # Update execution record
            execution.status = 'failed'
            execution.logs = str(e)
            execution.completed_at = datetime.utcnow()
            db.session.commit()
            
            # Emit WebSocket event with error
            socketio.emit('execution_update', {
                'execution_id': execution.id,
                'status': 'failed',
                'error': str(e),
                'logs': str(e),
                'completed_at': execution.completed_at.isoformat()
            }, room=str(execution.id))
