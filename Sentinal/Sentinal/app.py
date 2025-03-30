import os
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_socketio import SocketIO
from flask_mail import Mail
from flask_caching import Cache
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
from celery import Celery

# Initialize Flask app
app = Flask(__name__)

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
    "connect_args": {
        "sslmode": "require", 
        "connect_timeout": 10,
        "keepalives": 1,
        "keepalives_idle": 30,
        "keepalives_interval": 10,
        "keepalives_count": 5
    },
    "pool_size": 10,
    "max_overflow": 20
}
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'super-secret-key')
app.secret_key = os.environ.get("SESSION_SECRET", 'another-secret-key')

# JWT Configuration for cookie-based tokens
app.config['JWT_TOKEN_LOCATION'] = ['cookies', 'headers']
app.config['JWT_COOKIE_SECURE'] = True
app.config['JWT_COOKIE_CSRF_PROTECT'] = False  # For simplicity in development 
app.config['JWT_ACCESS_COOKIE_PATH'] = '/'
app.config['JWT_COOKIE_SAMESITE'] = 'Lax'

# Deriv OAuth Configuration
app.config['DERIV_CLIENT_ID'] = os.environ.get('DERIV_CLIENT_ID', '70547')
app.config['DERIV_CLIENT_SECRET'] = os.environ.get('DERIV_CLIENT_SECRET', 'vNlclahPL1JmSzO')

# Updated URLs based on Deriv's documentation
app.config['DERIV_OAUTH_AUTH_URL'] = 'https://oauth.deriv.com/oauth2/authorize'
app.config['DERIV_OAUTH_TOKEN_URL'] = 'https://oauth.deriv.com/oauth2/token'
app.config['DERIV_API_URL'] = 'https://oauth.deriv.com'

# Ensure we have OAuth URL for backwards compatibility
app.config['DERIV_OAUTH_URL'] = app.config['DERIV_OAUTH_AUTH_URL']

# According to Deriv OAuth2 implementation, they use a non-standard scope format
# Try the format used in their official examples without resource prefix
app.config['DERIV_SCOPE'] = 'read admin payments trading trading_information'

# Log Deriv configuration
app.logger.info(f"Deriv client ID configured: {app.config['DERIV_CLIENT_ID']}")
app.logger.info(f"Deriv OAuth URL: {app.config['DERIV_OAUTH_URL']}")
app.logger.info(f"Deriv API URL: {app.config['DERIV_API_URL']}")

# Mail configuration
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.example.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')

# Cache configuration
app.config['CACHE_TYPE'] = 'SimpleCache'
app.config['CACHE_DEFAULT_TIMEOUT'] = 300

# CORS configuration
app.config['CORS_HEADERS'] = 'Content-Type'

# Initialize extensions
db = SQLAlchemy(app)
jwt = JWTManager(app)
socketio = SocketIO(app, cors_allowed_origins="*")
mail = Mail(app)
cache = Cache(app)
limiter = Limiter(key_func=get_remote_address)
limiter.init_app(app)
CORS(app, resources={r"/*": {"origins": "*"}})

# Celery configuration
app.config['CELERY_BROKER_URL'] = os.environ.get('CELERY_BROKER_URL', 'redis://localhost:6379/0')
app.config['CELERY_RESULT_BACKEND'] = os.environ.get('CELERY_RESULT_BACKEND', 'redis://localhost:6379/0')

celery = Celery(
    app.name,
    broker=app.config['CELERY_BROKER_URL'],
    backend=app.config['CELERY_RESULT_BACKEND']
)
celery.conf.update(app.config)

# Setup logging
if not os.path.exists('logs'):
    os.makedirs('logs')

file_handler = RotatingFileHandler('logs/app.log', maxBytes=10240, backupCount=10)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
file_handler.setLevel(logging.INFO)
app.logger.addHandler(file_handler)

app.logger.setLevel(logging.INFO)
app.logger.info('Trading Script Platform startup')

# Import models and routes after initializing extensions
from models import *
from routes import *

# Create database tables and ensure they exist
with app.app_context():
    db.create_all()
    # Ensure tables are created by testing a simple query
    try:
        db.session.execute(text("SELECT 1"))
        db.session.commit()
        app.logger.info("Database tables verified")
    except Exception as e:
        app.logger.error(f"Database initialization error: {str(e)}")
        db.session.rollback()
