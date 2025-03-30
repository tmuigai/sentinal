from datetime import datetime
from app import db
from werkzeug.security import generate_password_hash, check_password_hash

# Association tables
script_dependencies = db.Table(
    'script_dependencies',
    db.Column('script_id', db.Integer, db.ForeignKey('script.id'), primary_key=True),
    db.Column('dependency_id', db.Integer, db.ForeignKey('script.id'), primary_key=True)
)

script_tags = db.Table(
    'script_tags',
    db.Column('script_id', db.Integer, db.ForeignKey('script.id'), primary_key=True),
    db.Column('tag_id', db.Integer, db.ForeignKey('tag.id'), primary_key=True)
)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    username = db.Column(db.String(50), unique=True)  # Optional display name for leaderboard
    role = db.Column(db.String(20), default='user')  # 'user', 'admin', 'super_admin'
    balance = db.Column(db.Float, default=0.0)
    blocked = db.Column(db.Boolean, default=False)
    two_factor_enabled = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    payment_method = db.Column(db.String(50))  # Method to receive admin fees: 'bank', 'crypto', 'paypal', etc.
    payment_details = db.Column(db.JSON)  # JSON with payment details based on the selected method
    
    # Gamification elements
    experience_points = db.Column(db.Integer, default=0)  # XP for leveling up
    level = db.Column(db.Integer, default=1)  # User level based on XP
    streak_days = db.Column(db.Integer, default=0)  # Consecutive days active
    last_active = db.Column(db.DateTime, default=datetime.utcnow)  # Last user activity
    community_rank = db.Column(db.Integer)  # Dynamic rank in the community
    
    # Relationships
    scripts = db.relationship('Script', backref='author', lazy='dynamic')
    executions = db.relationship('ExecutionHistory', backref='user', lazy='dynamic')
    profits = db.relationship('Profit', backref='user', lazy='dynamic')
    admin_logs = db.relationship('AdminLog', backref='admin', lazy='dynamic')
    achievements = db.relationship('UserAchievement', backref='user', lazy='dynamic')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self):
        return f'<User {self.email}>'

class Script(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    description = db.Column(db.Text)
    code = db.Column(db.Text, nullable=False)
    version = db.Column(db.String(20), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    parameters = db.Column(db.JSON)  # Input parameters
    public = db.Column(db.Boolean, default=False)
    price = db.Column(db.Float, default=0.0)  # Price to use this script
    
    # Relationships through association tables
    dependencies = db.relationship(
        'Script', 
        secondary=script_dependencies,
        primaryjoin=(script_dependencies.c.script_id == id),
        secondaryjoin=(script_dependencies.c.dependency_id == id),
        backref=db.backref('dependents', lazy='dynamic'),
        lazy='dynamic'
    )
    
    tags = db.relationship(
        'Tag',
        secondary=script_tags,
        backref=db.backref('scripts', lazy='dynamic'),
        lazy='dynamic'
    )
    
    executions = db.relationship('ExecutionHistory', backref='script', lazy='dynamic')
    profits = db.relationship('Profit', backref='script', lazy='dynamic')
    
    def __repr__(self):
        return f'<Script {self.name} v{self.version}>'

class ExecutionHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    script_id = db.Column(db.Integer, db.ForeignKey('script.id'), nullable=False)
    status = db.Column(db.String(20), nullable=False)  # success/failed/running/queued
    logs = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)
    container_id = db.Column(db.String(80))
    parameters_used = db.Column(db.JSON)
    
    def __repr__(self):
        return f'<Execution {self.id} - {self.status}>'

class Profit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    script_id = db.Column(db.Integer, db.ForeignKey('script.id'), nullable=False)
    execution_id = db.Column(db.Integer, db.ForeignKey('execution_history.id'))
    amount = db.Column(db.Float, nullable=False)
    profit_type = db.Column(db.String(20), nullable=False)  # realized/unrealized
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    execution = db.relationship('ExecutionHistory', backref='profit')
    
    def __repr__(self):
        return f'<Profit {self.id} - {self.amount}>'

class AdminLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(80), nullable=False)  # e.g., "blocked user 123"
    details = db.Column(db.Text)
    ip_address = db.Column(db.String(40))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<AdminLog {self.id} - {self.action}>'

class Tag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False, unique=True)
    description = db.Column(db.Text)
    parent_id = db.Column(db.Integer, db.ForeignKey('tag.id'))
    
    # Relationship for hierarchy
    children = db.relationship('Tag', backref=db.backref('parent', remote_side=[id]))
    
    def __repr__(self):
        return f'<Tag {self.name}>'

class DerivAPIToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(100), nullable=False)
    expiry = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User', backref='deriv_tokens')
    
    def __repr__(self):
        return f'<DerivAPIToken {self.id}>'
        
class Achievement(db.Model):
    """
    Achievements that users can earn
    """
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    badge_image = db.Column(db.String(255))  # Path to badge image
    points = db.Column(db.Integer, default=10)  # XP points awarded
    difficulty = db.Column(db.String(20), default='easy')  # easy, medium, hard
    category = db.Column(db.String(50))  # scripting, trading, community
    
    # Relationship to users who earned this achievement
    users = db.relationship('UserAchievement', backref='achievement', lazy='dynamic')
    
    def __repr__(self):
        return f'<Achievement {self.name}>'

class UserAchievement(db.Model):
    """
    Association between users and their earned achievements
    """
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    achievement_id = db.Column(db.Integer, db.ForeignKey('achievement.id'), nullable=False)
    date_earned = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Create a unique constraint to prevent duplicate achievements
    __table_args__ = (db.UniqueConstraint('user_id', 'achievement_id'),)
    
    def __repr__(self):
        return f'<UserAchievement user_id={self.user_id} achievement_id={self.achievement_id}>'


class SecurityConfig(db.Model):
    """
    Security configuration for different user roles or subscription tiers
    Controls resource limits and permissions for script execution containers
    """
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    role = db.Column(db.String(20), unique=True, nullable=False)  # 'user', 'admin', 'super_admin'
    
    # Resource limits
    mem_limit = db.Column(db.String(20), default='256m')           # Memory limit (e.g., '256m', '1g')
    cpu_quota = db.Column(db.Integer, default=25000)               # CPU quota (25% = 25000)
    pids_limit = db.Column(db.Integer, default=50)                 # Max number of processes
    timeout = db.Column(db.Integer, default=300)                   # Timeout in seconds
    
    # Security options
    network_access = db.Column(db.Boolean, default=False)          # Allow network access
    allow_file_write = db.Column(db.Boolean, default=False)        # Allow filesystem writes
    restrict_capabilities = db.Column(db.Boolean, default=True)    # Restrict Linux capabilities
    seccomp_profile = db.Column(db.String(50), default='default')  # Seccomp security profile
    
    # Default additional paths to mount (JSON)
    additional_mounts = db.Column(db.JSON)                        
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f'<SecurityConfig {self.role} - {self.name}>'
