import os
import json
import csv
from io import StringIO
from datetime import datetime, timedelta
import docker
from flask import render_template, redirect, url_for, flash, request, jsonify, send_file, make_response, session
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, set_access_cookies
from app import app, db, jwt, socketio, limiter, cache, mail

@app.route('/switch-account-type', methods=['POST'])
@jwt_required()
def switch_account_type():
    """Switch between demo and real accounts"""
    new_type = request.json.get('type')
    if new_type in ['demo', 'real']:
        session['account_type'] = new_type
        return jsonify({'status': 'success', 'type': new_type})
    return jsonify({'status': 'error', 'message': 'Invalid account type'}), 400
import requests
from sqlalchemy import text, func
from app import app, db, jwt, socketio, limiter, cache, mail
from models import User, Script, ExecutionHistory, Profit, AdminLog, Tag, DerivAPIToken, Achievement, UserAchievement, SecurityConfig
from tasks import execute_script_task
from utils import (
    log_admin_action, get_client_ip, create_or_get_tag, 
    is_admin, is_super_admin, promote_to_admin, update_payment_method,
    calculate_profit_share, distribute_admin_fees,
    update_user_activity, award_xp, update_community_ranks, 
    maybe_award_achievement, get_leaderboard, get_user_achievements
)
from flask_mail import Message

# Import the mock Docker client from tasks
from tasks import docker_client, MockDockerClient

# Main routes
@app.route('/')
def index():
    try:
        # Test database connection before proceeding
        db.session.execute(text("SELECT 1")).scalar()
        return render_template('index.html')
    except Exception as e:
        app.logger.error(f"Database connection error on index page: {str(e)}")
        error_message = "Database connection error. Please try again later."
        return render_template('error.html', error=error_message)

@app.route('/dashboard')
@jwt_required()
def dashboard():
    try:
        # Test database connection before proceeding
        db.session.execute(text("SELECT 1")).scalar()

        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        if not user:
            return redirect(url_for('login'))

        # Get Deriv token
        deriv_token = DerivAPIToken.query.filter_by(user_id=current_user_id).first()
        
        # Initialize balance values
        real_balance = 0
        demo_balance = 0

        if deriv_token:
            try:
                # Make API request to get balances
                headers = {
                    'Authorization': f'Bearer {deriv_token.token}',
                }

                try:
                    # Check if token is expired
                    validate_response = requests.get(f'{app.config["DERIV_API_URL"]}/oauth2/validate', headers=headers)
                    if validate_response.status_code == 401:  # Token expired
                        flash('Your Deriv token has expired. Please reconnect your account.', 'warning')
                        db.session.delete(deriv_token)
                        db.session.commit()
                        return redirect(url_for('deriv_login'))

                    # Get account status
                    status_response = requests.get(
                        f'{app.config["DERIV_API_URL"]}/accounts',
                        headers=headers
                    )
                    
                    current_balance = 0
                    account_name = ""
                    account_type = session.get('account_type', 'real')
                    
                    if status_response.ok:
                        accounts_data = status_response.json()
                        accounts = accounts_data.get('accounts', [])
                        
                        # Get account type from session
                        account_type = session.get('account_type', 'real')
                        
                        # Find matching account
                        for account in accounts:
                            is_virtual = account.get('is_virtual', False)
                            if (is_virtual and account_type == 'demo') or (not is_virtual and account_type == 'real'):
                                current_balance = float(account.get('balance', 0))
                                account_name = account.get('display_name', account.get('loginid', ''))
                                app.logger.info(f"Found matching {account_type} account {account_name} with balance: {current_balance}")
                                break
                        else:
                            current_balance = 0
                            account_name = "No account found"
                            app.logger.warning(f"No matching {account_type} account found")
                    
                    app.logger.info(f"Using account type: {account_type}, balance: {current_balance}")
                    
                except Exception as e:
                    app.logger.error(f"Error fetching Deriv balances: {str(e)}")
                    flash('Error fetching account balances', 'warning')
                    flash('Error fetching account balances. Please try reconnecting your account.', 'warning')
            except Exception as e:
                app.logger.error(f"Error fetching Deriv balance: {str(e)}")

        # Update user's activity streak and XP
        update_user_activity(current_user_id)

        # Get recent executions and profit data
        executions = ExecutionHistory.query.filter_by(user_id=current_user_id).order_by(ExecutionHistory.created_at.desc()).limit(10).all()
        profits = Profit.query.filter_by(user_id=current_user_id).order_by(Profit.created_at.desc()).limit(10).all()

        # Get recent achievements
        recent_achievements = UserAchievement.query.filter_by(user_id=current_user_id).order_by(UserAchievement.date_earned.desc()).limit(3).all()

        return render_template(
            'dashboard.html', 
            user=user, 
            executions=executions, 
            profits=profits,
            recent_achievements=recent_achievements,
            db=db,
            Profit=Profit,
            current_balance=current_balance,
            account_name=account_name,
            is_deriv_connected=bool(deriv_token)
        )
    except Exception as e:
        app.logger.error(f"Database connection error on dashboard page: {str(e)}")
        error_message = "Database connection error. Please try again later."
        flash('Unable to connect to the database. Please try again later.', 'danger')
        return render_template('error.html', error=error_message)

# Authentication routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        # Test database connection before querying
        try:
            # Use a simple query to test the connection
            db.session.execute(text("SELECT 1")).scalar()

            # If query succeeds, proceed with login
            user = User.query.filter_by(email=email).first()
        except Exception as e:
            app.logger.error(f"Database connection error during login: {str(e)}")
            flash('Unable to connect to the database. Please try again later.', 'danger')
            return redirect(url_for('login'))
        if user and user.check_password(password):
            if user.blocked:
                flash('Your account has been blocked. Please contact the administrator.', 'danger')
                return redirect(url_for('login'))

            # Convert user.id to string to prevent "Subject must be a string" error
            access_token = create_access_token(identity=str(user.id))
            
            # Create response with proper redirect
            response = make_response(redirect(url_for('dashboard')))
            
            # Set the JWT token in cookies
            set_access_cookies(response, access_token)
            
            return response

        flash('Invalid email or password', 'danger')

    return render_template('login.html')

@app.route('/api/login', methods=['POST'])
def api_login():
    email = request.json.get('email')
    password = request.json.get('password')

    # Test database connection before querying
    try:
        # Use a simple query to test the connection
        db.session.execute(text("SELECT 1")).scalar()

        # If query succeeds, proceed with login
        user = User.query.filter_by(email=email).first()
    except Exception as e:
        app.logger.error(f"Database connection error during API login: {str(e)}")
        return jsonify(message='Database connection error. Please try again later.'), 500
    if user and user.check_password(password):
        if user.blocked:
            return jsonify(message='Your account has been blocked.'), 403

        # Convert user.id to string to prevent "Subject must be a string" error
        access_token = create_access_token(identity=str(user.id))
        return jsonify(access_token=access_token, user_id=user.id, role=user.role)

    return jsonify(message='Invalid credentials'), 401

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # Validation
        if not email or not password or not confirm_password:
            flash('All fields are required', 'danger')
            return redirect(url_for('register'))

        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('register'))

        # Test database connection before querying
        try:
            # Use a simple query to test the connection
            db.session.execute(text("SELECT 1")).scalar()

            # If query succeeds, proceed with registration
            existing_user = User.query.filter_by(email=email).first()
        except Exception as e:
            app.logger.error(f"Database connection error during registration: {str(e)}")
            flash('Unable to connect to the database. Please try again later.', 'danger')
            return redirect(url_for('register'))
        if existing_user:
            flash('Email already exists', 'danger')
            return redirect(url_for('register'))

        # Create user
        user = User(email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/api/register', methods=['POST'])
def api_register():
    email = request.json.get('email')
    password = request.json.get('password')

    # Validation
    if not email or not password:
        return jsonify(message='Email and password are required'), 400

    # Test database connection before querying
    try:
        # Use a simple query to test the connection
        db.session.execute(text("SELECT 1")).scalar()

        # If query succeeds, proceed with registration
        existing_user = User.query.filter_by(email=email).first()
    except Exception as e:
        app.logger.error(f"Database connection error during API registration: {str(e)}")
        return jsonify(message='Database connection error. Please try again later.'), 500
    if existing_user:
        return jsonify(message='Email already exists'), 400

    # Create user
    user = User(email=email)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    return jsonify(message='Registration successful', user_id=user.id), 201

# Deriv OAuth routes
@app.route('/login/deriv')
def deriv_login():
    client_id = app.config.get('DERIV_CLIENT_ID', None)
    if not client_id:
        flash("Deriv login is not configured. Please contact the administrator.", "danger")
        return redirect(url_for('login'))

    # Get the full URL for the callback, ensuring it uses HTTPS
    # Use Flask's url_for with _external=True to generate an absolute URL
    redirect_uri = url_for('deriv_callback', _external=True)
    if redirect_uri.startswith('http://'):
        redirect_uri = redirect_uri.replace('http://', 'https://')

    app.logger.info(f"DERIV LOGIN - Callback URL: {redirect_uri}")

    # Make sure to include app_id parameter and appropriate scopes to request permissions
    # Using the format that Deriv expects according to their API docs
    # Format should be space-separated with resource:action syntax for specific permissions
    scope_str = app.config['DERIV_SCOPE']

    # Properly URL encode the scope parameter to ensure spaces are transmitted correctly
    import urllib.parse
    encoded_scope = urllib.parse.quote(scope_str)

    # Log what we're trying
    app.logger.info(f"Using Deriv's expected scope format: {scope_str}")
    app.logger.info(f"URL encoded scope: {encoded_scope}")
    app.logger.info(f"Redirect URI: {redirect_uri}")

    # Deriv requires app_id parameter instead of client_id
    auth_url = (f'{app.config["DERIV_OAUTH_URL"]}'
                f'?response_type=code'
                f'&app_id={client_id}'
                f'&redirect_uri={redirect_uri}'
                f'&scope={encoded_scope}')

    app.logger.info(f"Redirecting to authorization URL: {auth_url}")
    return redirect(auth_url)

@app.route('/login/deriv/callback')
def deriv_callback():
    # Log all request parameters for debugging
    app.logger.info(f"Received callback with args: {request.args}")
    app.logger.info(f"Request URL: {request.url}")
    app.logger.info(f"Request method: {request.method}")
    app.logger.info(f"Request headers: {dict(request.headers)}")

    error = request.args.get('error')
    if error:
        app.logger.error(f"OAuth error: {error}")
        flash(f'Authorization error: {error}', 'danger')
        return redirect(url_for('login'))

    # Standard OAuth would provide a 'code' parameter, but Deriv appears to be sending tokens directly
    code = request.args.get('code')
    token1 = request.args.get('token1')
    token2 = request.args.get('token2')

    app.logger.info(f"Checking for authentication tokens: code={code}, token1={token1}, token2={token2}")

    # If we have token1 or token2, we can use those directly instead of exchanging a code
    # This is non-standard OAuth but appears to be how Deriv API works
    if token1 or token2:
        app.logger.info("Using direct token approach with Deriv API")

        # Use the first available token
        token = token1 or token2

        # Get account information
        acct1 = request.args.get('acct1')
        acct2 = request.args.get('acct2')
        account = acct1 or acct2

        app.logger.info(f"Using token: {token} for account: {account}")

        try:
            # Use the token directly instead of going through OAuth token exchange
            app.logger.info(f"Using Deriv token directly: {token}")

            # Generate unique email based on account
            email = f"{account}@deriv-user.com"
            
            try:
                # Test database connection before querying
                db.session.execute(text("SELECT 1")).scalar()

                # Check if a token already exists for this account
                existing_token = DerivAPIToken.query.filter_by(token=token).first()
                if existing_token:
                    user = User.query.get(existing_token.user_id)
                else:
                    # Look up or create user
                    user = User.query.filter_by(email=email).first()
                    if not user:
                        is_first_user = User.query.count() == 0
                        user = User(
                            email=email,
                            username=f"Trader_{account[:8]}", # Add username for display
                            role='admin' if is_first_user else 'user'
                        )
                        user.set_password(os.urandom(12).hex())
                        db.session.add(user)
                        db.session.commit()

                # Store the Deriv token
                deriv_token = DerivAPIToken(
                    user_id=user.id,
                    token=token
                )

                db.session.add(deriv_token)
                db.session.commit()

                # Create JWT token and redirect to dashboard
                # Convert user.id to string to prevent "Subject must be a string" error
                access_token = create_access_token(identity=str(user.id))

                # Set the JWT token using Flask-JWT-Extended's set_access_cookies
                response = make_response(redirect(url_for('dashboard')))
                set_access_cookies(response, access_token)

                flash('Successfully logged in with Deriv', 'success')
                return response

            except Exception as e:
                app.logger.error(f"Database error with direct token approach: {str(e)}")
                flash('Database error while processing login. Please try again.', 'danger')
                return redirect(url_for('login'))

        except Exception as e:
            app.logger.error(f"Error using direct token: {str(e)}")
            flash(f'Error with Deriv login using direct token: {str(e)}', 'danger')
            return redirect(url_for('login'))

    # Fall back to standard OAuth flow if no tokens were provided
    if not code:
        app.logger.error("No authorization code or tokens in request args")
        # Try to get it from the entire URL as query parameter
        from urllib.parse import urlparse, parse_qs
        parsed_url = urlparse(request.url)
        query_params = parse_qs(parsed_url.query)
        app.logger.info(f"Parsed query parameters: {query_params}")

        if 'code' in query_params:
            code = query_params['code'][0]
            app.logger.info(f"Found code in parsed URL: {code}")
        else:
            app.logger.error("No code or tokens found for authentication")
            flash('No authorization code or tokens received from Deriv', 'danger')
            return redirect(url_for('login'))

    client_id = app.config.get('DERIV_CLIENT_ID')
    client_secret = app.config.get('DERIV_CLIENT_SECRET')

    # Get the full URL for the callback, ensuring it uses HTTPS
    # Use the same URL format as in the initial auth request for consistency
    redirect_uri = url_for('deriv_callback', _external=True)
    if redirect_uri.startswith('http://'):
        redirect_uri = redirect_uri.replace('http://', 'https://')

    app.logger.info(f"CALLBACK - Using redirect URI: {redirect_uri}")

    # Exchange authorization code for token
    try:
        # Log all relevant information for debugging
        app.logger.info(f"Sending token request with code: {code}")
        app.logger.info(f"Redirect URI: {redirect_uri}")
        app.logger.info(f"Client ID: {client_id}")
        # Deriv OAuth token request format uses app_id instead of client_id
        token_data = {
            'app_id': client_id,
            'client_secret': client_secret,
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': redirect_uri,
        }

        # Set proper Authorization header with app_id
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': f'Bearer {client_id}',
            'app_id': client_id
        }
        app.logger.info(f"Token request data: {token_data}")

        # Send the request with proper headers and ensure we get a valid response
        response = requests.post(
            app.config['DERIV_OAUTH_TOKEN_URL'],
            data=token_data,
            headers=headers
        )

        # Check for HTTP errors
        response.raise_for_status()

        # Parse the JSON response
        token_response = response.json()
        app.logger.info(f"Token response received (access_token {'present' if 'access_token' in token_response else 'missing'})")

        if 'error' in token_response:
            flash(f"OAuth error: {token_response['error']}", 'danger')
            return redirect(url_for('login'))

        # Get user info from Deriv
        app.logger.info(f"Getting user info with access token")

        # Make the request to get user info with standard headers
        user_info_headers = {
            'Accept': 'application/json',
            'Authorization': f'Bearer {token_response["access_token"]}',
            'app_id': client_id
        }
        user_info_response = requests.get(
            f'{app.config["DERIV_API_URL"]}/oauth2/userinfo',
            headers=user_info_headers
        )

        # Check for HTTP errors
        user_info_response.raise_for_status()

        # Parse the JSON response
        user_info = user_info_response.json()
        app.logger.info(f"User info received (email {'present' if 'email' in user_info else 'missing'})")

        if 'error' in user_info:
            flash(f"Error fetching user info: {user_info['error']}", 'danger')
            return redirect(url_for('login'))

        # Check if user exists, create if not
        try:
            # Test database connection before querying
            db.session.execute(text("SELECT 1")).scalar()

            # If query succeeds, proceed with user lookup/creation
            user = User.query.filter_by(email=user_info['email']).first()
            if not user:
                # Make first user admin
                is_first_user = User.query.count() == 0
                user = User(
                    email=user_info['email'],
                    role='admin' if is_first_user else 'user'
                )
                user.set_password(os.urandom(12).hex())  # Generate random password
                db.session.add(user)
                db.session.commit()
        except Exception as e:
            app.logger.error(f"Database connection error during Deriv OAuth callback: {str(e)}")
            flash('Unable to connect to the database. Please try again later.', 'danger')
            return redirect(url_for('login'))

        # Store the Deriv token
        deriv_token = DerivAPIToken(
            user_id=user.id,
            token=token_response['access_token']
        )
        if 'expires_in' in token_response:
            deriv_token.expiry = datetime.utcnow() + timedelta(seconds=token_response['expires_in'])

        db.session.add(deriv_token)
        db.session.commit()

        # Create JWT token and redirect to dashboard
        # Convert user.id to string to prevent "Subject must be a string" error
        access_token = create_access_token(identity=str(user.id))

        # Set the JWT token using Flask-JWT-Extended's set_access_cookies
        response = make_response(redirect(url_for('dashboard')))
        set_access_cookies(response, access_token)

        flash('Successfully logged in with Deriv', 'success')
        return response

    except Exception as e:
        # Provide more detailed error information
        error_msg = str(e)
        app.logger.error(f"Deriv OAuth error: {error_msg}")

        # Log the full response if available
        if hasattr(e, 'response') and e.response:
            try:
                app.logger.error(f"Error response content: {e.response.content}")
                app.logger.error(f"Error response status: {e.response.status_code}")
                app.logger.error(f"Error response headers: {e.response.headers}")
            except:
                app.logger.error("Error while logging response details")

        # Try showing a special debugging page for troubleshooting
        if app.debug:
            # Safe access to token_data which might not be defined in all code paths
            token_data_str = "Not available"
            try:
                if 'token_data' in locals():
                    token_data_str = str(token_data)
            except:
                pass

            # Also handle potential missing redirect_uri
            redirect_uri_str = "Not available"
            try:
                if 'redirect_uri' in locals():
                    redirect_uri_str = str(redirect_uri)
            except:
                pass

            return f"""
            <html>
                <head><title>OAuth Debug</title></head>
                <body>
                    <h1>OAuth Debug Information</h1>
                    <p>This page is only shown in debug mode.</p>
                    <h2>Error Information</h2>
                    <p>Error: {error_msg}</p>
                    <h2>Request Parameters</h2>
                    <pre>{token_data_str}</pre>
                    <h2>Redirect URI</h2>
                    <p>{redirect_uri_str}</p>
                    <h2>Request Args</h2>
                    <pre>{dict(request.args)}</pre>
                    <p><a href="{url_for('login')}">Back to Login</a></p>
                </body>
            </html>
            """

        # Check for common OAuth errors
        if "invalid_grant" in error_msg.lower():
            flash('Authorization code expired or invalid. Please try again.', 'danger')
        elif "redirect_uri_mismatch" in error_msg.lower():
            flash('OAuth redirect URI mismatch. Please contact the administrator.', 'danger')
        elif "invalid_client" in error_msg.lower():
            flash('OAuth client authentication failed. Please contact the administrator.', 'danger')
        else:
            flash(f'An error occurred during Deriv OAuth login: {error_msg}', 'danger')

        return redirect(url_for('login'))

# Script routes
@app.route('/scripts')
@jwt_required()
def scripts():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    # Get user's scripts
    user_scripts = Script.query.filter_by(user_id=current_user_id).all()

    # Get public scripts from other users
    public_scripts = Script.query.filter(
        Script.user_id != current_user_id,
        Script.public == True
    ).all()

    return render_template('scripts.html', user=user, user_scripts=user_scripts, public_scripts=public_scripts)

@app.route('/scripts/<int:script_id>')
@jwt_required()
def script_detail(script_id):
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    script = Script.query.get_or_404(script_id)

    # Check if user has permission to view this script
    if script.user_id != current_user_id and not script.public:
        flash('You do not have permission to view this script', 'danger')
        return redirect(url_for('scripts'))

    # Get execution history for this script
    executions = ExecutionHistory.query.filter_by(
        script_id=script_id,
        user_id=current_user_id
    ).order_by(ExecutionHistory.created_at.desc()).all()

    return render_template('script_detail.html', user=user, script=script, executions=executions)

@app.route('/scripts/create', methods=['GET', 'POST'])
@jwt_required()
def create_script():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if request.method == 'POST':
        # Handle file upload
        if 'script_file' in request.files:
            uploaded_file = request.files['script_file']
            if uploaded_file.filename:
                code = uploaded_file.read().decode('utf-8')
                request.form = request.form.copy()
                request.form['code'] = code

    # Check if request includes the owner_id field (admin upload)
    if request.form.get('owner_id') and user.role in ['admin', 'super_admin']:
        owner_id = int(request.form.get('owner_id'))
        selected_user = User.query.get(owner_id)
        if not selected_user:
            flash('Invalid user selected', 'danger')
            return redirect(url_for('create_script'))
        current_user_id = owner_id

    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        code = request.form.get('code')
        version = request.form.get('version', '1.0.0')
        public = request.form.get('public') == 'on'
        price = float(request.form.get('price', 0.0))

        # Validation
        if not name or not code:
            flash('Name and code are required', 'danger')
            return redirect(url_for('create_script'))

        # Create script
        script = Script(
            name=name,
            description=description,
            code=code,
            version=version,
            user_id=current_user_id,
            public=public,
            price=price
        )

        # Handle parameters
        parameters = {}
        param_keys = request.form.getlist('param_key')
        param_types = request.form.getlist('param_type')
        param_defaults = request.form.getlist('param_default')

        for i in range(len(param_keys)):
            if param_keys[i]:
                parameters[param_keys[i]] = {
                    'type': param_types[i] if i < len(param_types) else 'string',
                    'default': param_defaults[i] if i < len(param_defaults) else ''
                }

        script.parameters = parameters

        # Handle tags
        tag_names = request.form.getlist('tags')
        for tag_name in tag_names:
            if tag_name:
                tag = create_or_get_tag(tag_name)
                script.tags.append(tag)

        db.session.add(script)
        db.session.commit()

        flash('Script created successfully', 'success')
        return redirect(url_for('script_detail', script_id=script.id))

    # Get all available tags
    tags = Tag.query.all()

    return render_template('create_script.html', user=user, tags=tags, User=User)

@app.route('/scripts/<int:script_id>/edit', methods=['GET', 'POST'])
@jwt_required()
def edit_script(script_id):
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    script = Script.query.get_or_404(script_id)

    # Check if user has permission to edit this script
    if script.user_id != current_user_id:
        flash('You do not have permission to edit this script', 'danger')
        return redirect(url_for('scripts'))

    if request.method == 'POST':
        script.name = request.form.get('name')
        script.description = request.form.get('description')
        script.code = request.form.get('code')
        script.version = request.form.get('version', '1.0.0')
        script.public = request.form.get('public') == 'on'
        script.price = float(request.form.get('price', 0.0))

        # Handle parameters
        parameters = {}
        param_keys = request.form.getlist('param_key')
        param_types = request.form.getlist('param_type')
        param_defaults = request.form.getlist('param_default')

        for i in range(len(param_keys)):
            if param_keys[i]:
                parameters[param_keys[i]] = {
                    'type': param_types[i] if i < len(param_types) else 'string',
                    'default': param_defaults[i] if i < len(param_defaults) else ''
                }

        script.parameters = parameters

        # Handle tags
        tag_names = request.form.getlist('tags')

        # Clear existing tags
        script.tags = []

        # Add new tags
        for tag_name in tag_names:
            if tag_name:
                tag = create_or_get_tag(tag_name)
                script.tags.append(tag)

        db.session.commit()

        flash('Script updated successfully', 'success')
        return redirect(url_for('script_detail', script_id=script.id))

    # Get all available tags
    tags = Tag.query.all()

    return render_template('edit_script.html', user=user, script=script, tags=tags)

@app.route('/scripts/<int:script_id>/delete', methods=['POST'])
@jwt_required()
def delete_script(script_id):
    current_user_id = get_jwt_identity()

    script = Script.query.get_or_404(script_id)

    # Check if user has permission to delete this script
    if script.user_id != current_user_id:
        flash('You do not have permission to delete this script', 'danger')
        return redirect(url_for('scripts'))

    # Delete associated executions and profits
    ExecutionHistory.query.filter_by(script_id=script_id).delete()
    Profit.query.filter_by(script_id=script_id).delete()

    # Delete script
    db.session.delete(script)
    db.session.commit()

    flash('Script deleted successfully', 'success')
    return redirect(url_for('scripts'))

# Script execution routes
@app.route('/execute-script/<int:script_id>', methods=['GET', 'POST'])
@jwt_required()
def execute_script(script_id):
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    script = Script.query.get_or_404(script_id)

    # Check if user has permission to execute this script
    if script.user_id != current_user_id and not script.public:
        flash('You do not have permission to execute this script', 'danger')
        return redirect(url_for('scripts'))

    # If it's someone else's script, check if user has enough balance
    if script.user_id != current_user_id and script.price > 0:
        if user.balance < script.price:
            flash(f'Insufficient balance. This script costs {script.price}', 'danger')
            return redirect(url_for('script_detail', script_id=script_id))

    if request.method == 'POST':
        # Get parameters from form
        parameters = {}
        if script.parameters:
            for param_key, param_info in script.parameters.items():
                param_value = request.form.get(param_key, param_info.get('default', ''))

                # Convert parameter to the right type
                param_type = param_info.get('type', 'string')
                if param_type == 'number':
                    try:
                        param_value = float(param_value)
                    except ValueError:
                        param_value = 0.0
                elif param_type == 'boolean':
                    param_value = param_value.lower() in ('true', 'yes', 'on', '1')

                parameters[param_key] = param_value

        # Create execution record
        execution = ExecutionHistory(
            user_id=current_user_id,
            script_id=script_id,
            status='queued',
            parameters_used=parameters
        )
        db.session.add(execution)
        db.session.commit()

        # Charge user if using someone else's script
        if script.user_id != current_user_id and script.price > 0:
            user.balance -= script.price
            db.session.commit()

        # Execute script (in background in production, but directly in our mock)
        execute_script_task(execution.id)

        flash('Script execution started', 'success')
        return redirect(url_for('execution_detail', execution_id=execution.id))

    return render_template('execute_script.html', user=user, script=script)

@app.route('/executions/<int:execution_id>')
@jwt_required()
def execution_detail(execution_id):
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    execution = ExecutionHistory.query.get_or_404(execution_id)

    # Check if user has permission to view this execution
    if execution.user_id != current_user_id:
        flash('You do not have permission to view this execution', 'danger')
        return redirect(url_for('dashboard'))

    # Get related profits for this execution
    profits = Profit.query.filter_by(execution_id=execution_id).all()

    return render_template('execution_detail.html', user=user, execution=execution, profits=profits)

# API endpoints
@app.route('/api/execute-script/<int:script_id>', methods=['POST'])
@jwt_required()
def api_execute_script(script_id):
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    script = Script.query.get_or_404(script_id)

    # Check permissions and balance
    if script.user_id != current_user_id and not script.public:
        return jsonify(message='Permission denied'), 403

    if script.user_id != current_user_id and script.price > 0:
        if user.balance < script.price:
            return jsonify(message=f'Insufficient balance. This script costs {script.price}'), 402

    # Get parameters from request
    parameters = request.json.get('parameters', {})

    # Create execution record
    execution = ExecutionHistory(
        user_id=current_user_id,
        script_id=script_id,
        status='queued',
        parameters_used=parameters
    )
    db.session.add(execution)
    db.session.commit()

    # Charge user if using someone else's script
    if script.user_id != current_user_id and script.price > 0:
        user.balance -= script.price
        db.session.commit()

    # Execute script (in background in production, but directly in our mock)
    execute_script_task(execution.id)

    return jsonify(
        message='Script execution started',
        execution_id=execution.id
    )

@app.route('/api/executions/<int:execution_id>')
@jwt_required()
def api_execution_detail(execution_id):
    current_user_id = get_jwt_identity()

    execution = ExecutionHistory.query.get_or_404(execution_id)

    # Check if user has permission to view this execution
    if execution.user_id != current_user_id:
        return jsonify(message='Permission denied'), 403

    # Get related profits for this execution
    profits = Profit.query.filter_by(execution_id=execution_id).all()

    return jsonify(
        execution={
            'id': execution.id,
            'status': execution.status,
            'created_at': execution.created_at.isoformat(),
            'completed_at': execution.completed_at.isoformat() if execution.completed_at else None,
            'logs': execution.logs,
            'parameters_used': execution.parameters_used
        },
        profits=[{
            'id': profit.id,
            'amount': profit.amount,
            'profit_type': profit.profit_type,
            'created_at': profit.created_at.isoformat()
        } for profit in profits]
    )

# Admin routes
@app.route('/admin')
@jwt_required()
def admin_dashboard():
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)

        # Check if the user is a regular admin or super admin
        if user.role not in ['admin', 'super_admin']:
            flash('Access denied. Admin privileges required.', 'danger')
            return redirect(url_for('dashboard'))
            
        # Get users
        users = User.query.all()
        
        # Get recent admin logs
        admin_logs = AdminLog.query.order_by(AdminLog.created_at.desc()).limit(20).all()
        
        return render_template(
            'admin.html',
            user=user,
            users=users,
            admin_logs=admin_logs,
            total_executions=ExecutionHistory.query.count(),
            successful_executions=ExecutionHistory.query.filter_by(status='success').count(),
            failed_executions=ExecutionHistory.query.filter_by(status='failed').count(),
            total_profits=db.session.query(db.func.sum(Profit.amount)).scalar() or 0,
            platform_fees=db.session.query(db.func.sum(Profit.amount)).filter_by(profit_type='platform_fee').scalar() or 0,
            admin_users=User.query.filter(User.role.in_(['admin', 'super_admin'])).all(),
            security_configs=SecurityConfig.query.all(),
            is_super_admin=(user.role == 'super_admin')
        )
    except Exception as e:
        app.logger.error(f"Error in admin dashboard: {str(e)}")
        flash('Error loading admin dashboard', 'danger')
        return redirect(url_for('dashboard'))

    # Get users
    users = User.query.all()

    # Get recent admin logs
    admin_logs = AdminLog.query.order_by(AdminLog.created_at.desc()).limit(20).all()

    # Get execution statistics
    total_executions = ExecutionHistory.query.count()
    successful_executions = ExecutionHistory.query.filter_by(status='success').count()
    failed_executions = ExecutionHistory.query.filter_by(status='failed').count()

    # Get profit statistics
    total_profits = db.session.query(db.func.sum(Profit.amount)).scalar() or 0
    platform_fees = db.session.query(db.func.sum(Profit.amount)).filter_by(profit_type='platform_fee').scalar() or 0

    # Get all admin users for the super admin to manage
    admin_users = User.query.filter(User.role.in_(['admin', 'super_admin'])).all()

    # Get security configurations for container isolation
    security_configs = SecurityConfig.query.all()

    return render_template(
        'admin.html',
        user=user,
        users=users,
        admin_logs=admin_logs,
        total_executions=total_executions,
        successful_executions=successful_executions,
        failed_executions=failed_executions,
        total_profits=total_profits,
        platform_fees=platform_fees,
        admin_users=admin_users,
        security_configs=security_configs,
        is_super_admin=(user.role == 'super_admin')
    )

@app.route('/admin/block-user/<int:user_id>', methods=['POST'])
@jwt_required()
def block_user(user_id):
    admin_id = get_jwt_identity()
    admin = User.query.get(admin_id)

    if admin.role not in ['admin', 'super_admin']:
        return jsonify(message='Unauthorized'), 403

    user = User.query.get_or_404(user_id)

    # Only super admin can block/unblock other admins
    if user.role in ['admin', 'super_admin'] and admin.role != 'super_admin':
        flash('Only super admins can block or unblock other administrators.', 'danger')
        return redirect(url_for('admin_dashboard'))

    # Super admins cannot be blocked
    if user.role == 'super_admin':
        flash('Super admins cannot be blocked.', 'danger')
        return redirect(url_for('admin_dashboard'))

    # Toggle blocked status
    user.blocked = not user.blocked
    db.session.commit()

    # Log admin action
    action = f'{"Blocked" if user.blocked else "Unblocked"} user {user.id} ({user.email})'
    log_admin_action(admin_id, action, get_client_ip())

    flash(f'User {user.email} {"blocked" if user.blocked else "unblocked"} successfully', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/make-admin/<int:user_id>', methods=['POST'])
@jwt_required()
def make_admin(user_id):
    admin_id = get_jwt_identity()
    admin = User.query.get(admin_id)

    # Only admins and super admins can access this route
    if admin.role not in ['admin', 'super_admin']:
        return jsonify(message='Unauthorized'), 403

    user = User.query.get_or_404(user_id)

    # Only super admin can manage other admin roles
    if admin.role == 'admin' and user.role in ['admin', 'super_admin']:
        flash('Only super admins can change the role of other administrators.', 'danger')
        return redirect(url_for('admin_dashboard'))

    # Get the requested role from the form (if provided)
    new_role = request.form.get('role', 'admin')

    # Regular admins can only create other regular admins
    if admin.role == 'admin' and new_role == 'super_admin':
        flash('Only super admins can create super admins.', 'danger')
        return redirect(url_for('admin_dashboard'))

    # Toggle orset admin status based on current role
    if user.role in ['admin', 'super_admin']:
        # Demote to user
        user.role = 'user'
        action_message = f'Removed {user.email} from being an administrator'
    else:
        # Promote to admin or super_admin (only super_admin can create super_admin)
        if new_role == 'super_admin' and admin.role == 'super_admin':
            user.role = 'super_admin'
            action_message = f'Promoted {user.email} to super administrator'
        else:
            user.role = 'admin'
            action_message = f'Promoted {user.email} to administrator'

    db.session.commit()

    # Log admin action
    log_admin_action(admin_id, action_message, get_client_ip())

    flash(action_message, 'success')
    return redirect(url_for('admin_dashboard'))

# Export routes
@app.route('/export/csv')
@jwt_required()
def export_csv():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    # Generate CSV
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'Script Name', 'Status', 'Logs', 'Created At', 'Completed At'])

    executions = ExecutionHistory.query.filter_by(user_id=current_user_id).all()
    for execution in executions:
        writer.writerow([
            execution.id,
            execution.script.name,
            execution.status,
            execution.logs,
            execution.created_at,
            execution.completed_at
        ])

    output.seek(0)
    return send_file(
        output,
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'execution_history_{datetime.utcnow().strftime("%Y%m%d%H%M%S")}.csv'
    )

# Admin payment methods
@app.route('/admin/payment-methods', methods=['GET', 'POST'])
@jwt_required()
def admin_payment_methods():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    # Only admins and super admins can access this page
    if user.role not in ['admin', 'super_admin']:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        payment_method = request.form.get('payment_method')
        payment_details = {}

        # Gather payment details based on selected method
        if payment_method == 'bank':
            payment_details = {
                'bank_name': request.form.get('bank_name'),
                'account_number': request.form.get('account_number'),
                'routing_number': request.form.get('routing_number'),
                'account_holder': request.form.get('account_holder')
            }
        elif payment_method == 'crypto':
            payment_details = {
                'crypto_currency': request.form.get('crypto_currency'),
                'wallet_address': request.form.get('wallet_address')
            }
        elif payment_method == 'paypal':
            payment_details = {
                'paypal_email': request.form.get('paypal_email')
            }

        # Update the current admin's payment method
        user.payment_method = payment_method
        user.payment_details = payment_details
        db.session.commit()

        flash('Payment method updated successfully.', 'success')
        return redirect(url_for('admin_payment_methods'))

    return render_template('admin_payment.html', user=user)

# Super admin route to manage all admin payment methods
@app.route('/admin/manage-payment-methods', methods=['GET'])
@jwt_required()
def manage_admin_payment_methods():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    # Only super admins can access this page
    if user.role != 'super_admin':
        flash('Access denied. Super admin privileges required.', 'danger')
        return redirect(url_for('admin_dashboard'))

    # Get all admins and super admins
    admins = User.query.filter(User.role.in_(['admin', 'super_admin'])).all()

    return render_template('manage_admin_payments.html', user=user, admins=admins)

# Container security configuration routes
@app.route('/admin/security-configs', methods=['GET'])
@jwt_required()
def security_configs():
    """View and manage security configurations for containers"""
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    # Only super admins can access this route
    if user.role != 'super_admin':
        flash('Access denied. Super admin privileges required.', 'danger')
        return redirect(url_for('admin_dashboard'))

    # Get all security configurations
    configs = SecurityConfig.query.all()

    return render_template('security_configs.html', user=user, configs=configs)

@app.route('/admin/security-configs/create', methods=['GET', 'POST'])
@jwt_required()
def create_security_config():
    """Create a new security configuration"""
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    # Only super admins can access this route
    if user.role != 'super_admin':
        flash('Access denied. Super admin privileges required.', 'danger')
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        # Parse form data
        name = request.form.get('name')
        role = request.form.get('role')
        mem_limit = request.form.get('mem_limit')
        cpu_quota = int(request.form.get('cpu_quota', 25000))
        pids_limit = int(request.form.get('pids_limit', 50))
        timeout = int(request.form.get('timeout', 300))
        network_access = request.form.get('network_access') == 'on'
        allow_file_write = request.form.get('allow_file_write') == 'on'
        restrict_capabilities = request.form.get('restrict_capabilities') == 'on'
        seccomp_profile = request.form.get('seccomp_profile')

        # Parse additional mounts
        additional_mounts = {}
        mount_sources = request.form.getlist('mount_source')
        mount_targets = request.form.getlist('mount_target')
        mount_modes = request.form.getlist('mount_mode')

        for i in range(len(mount_sources)):
            if mount_sources[i] and mount_targets[i]:
                additional_mounts[mount_sources[i]] = {
                    'target': mount_targets[i],
                    'mode': mount_modes[i] if i < len(mount_modes) else 'ro'
                }

        # Create new security config
        config = SecurityConfig(
            name=name,
            role=role,
            mem_limit=mem_limit,
            cpu_quota=cpu_quota,
            pids_limit=pids_limit,
            timeout=timeout,
            network_access=network_access,
            allow_file_write=allow_file_write,
            restrict_capabilities=restrict_capabilities,
            seccomp_profile=seccomp_profile,
            additional_mounts=additional_mounts
        )

        db.session.add(config)

        try:
            db.session.commit()
            # Log admin action
            log_admin_action(current_user_id, f'Created security configuration: {name}', get_client_ip())
            flash(f'Security configuration "{name}" created successfully', 'success')
            return redirect(url_for('security_configs'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating security configuration: {str(e)}', 'danger')

    return render_template('create_security_config.html', user=user)

@app.route('/admin/security-configs/<int:config_id>/edit', methods=['GET', 'POST'])
@jwt_required()
def edit_security_config(config_id):
    """Edit an existing security configuration"""
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    # Only super admins can access this route
    if user.role != 'super_admin':
        flash('Access denied. Super admin privileges required.', 'danger')
        return redirect(url_for('admin_dashboard'))

    # Get the security config
    config = SecurityConfig.query.get_or_404(config_id)

    if request.method == 'POST':
        # Update config fields
        config.name = request.form.get('name')
        config.mem_limit = request.form.get('mem_limit')
        config.cpu_quota = int(request.form.get('cpu_quota', 25000))
        config.pids_limit = int(request.form.get('pids_limit', 50))
        config.timeout = int(request.form.get('timeout', 300))
        config.network_access = request.form.get('network_access') == 'on'
        config.allow_file_write = request.form.get('allow_file_write') == 'on'
        config.restrict_capabilities = request.form.get('restrict_capabilities') == 'on'
        config.seccomp_profile = request.form.get('seccomp_profile')

        # Parse additional mounts
        additional_mounts = {}
        mount_sources = request.form.getlist('mount_source')
        mount_targets = request.form.getlist('mount_target')
        mount_modes = request.form.getlist('mount_mode')

        for i in range(len(mount_sources)):
            if mount_sources[i] and mount_targets[i]:
                additional_mounts[mount_sources[i]] = {
                    'target': mount_targets[i],
                    'mode': mount_modes[i] if i < len(mount_modes) else 'ro'
                }

        config.additional_mounts = additional_mounts

        try:
            db.session.commit()
            # Log admin action
            log_admin_action(current_user_id, f'Updated security configuration: {config.name}', get_client_ip())
            flash(f'Security configuration "{config.name}" updated successfully', 'success')
            return redirect(url_for('security_configs'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating security configuration: {str(e)}', 'danger')

    return render_template('edit_security_config.html', user=user, config=config)

@app.route('/admin/seed-security-configs', methods=['GET'])
@jwt_required()
def seed_security_configs():
    """Seed default security configurations"""
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    # Only super admins can access this route
    if user.role != 'super_admin':
        flash('Access denied. Super admin privileges required.', 'danger')
        return redirect(url_for('admin_dashboard'))

    # Import and run the seed script function
    from seed_security_configs import create_security_configs

    try:
        create_security_configs()
        flash('Default security configurations created successfully.', 'success')

        # Log the action
        log_admin_action(
            admin_id=current_user_id,
            action="Seeded default security configurations",
            ip_address=get_client_ip()
        )
    except Exception as e:
        flash(f'Error creating security configurations: {str(e)}', 'danger')

    return redirect(url_for('security_configs'))

@app.route('/admin/security-configs/<int:config_id>/delete', methods=['POST'])
@jwt_required()
def delete_security_config(config_id):
    """Delete a security configuration"""
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    # Only super admins can access this route
    if user.role != 'super_admin':
        flash('Access denied. Super admin privileges required.', 'danger')
        return redirect(url_for('admin_dashboard'))

    # Get the security config
    config = SecurityConfig.query.get_or_404(config_id)

    # Don't allow deleting the default security configs for main roles
    if config.role in ['user', 'admin', 'super_admin']:
        flash(f'Cannot delete built-in security configuration for role: {config.role}', 'danger')
        return redirect(url_for('security_configs'))

    try:
        # Delete the security config
        config_name = config.name
        db.session.delete(config)
        db.session.commit()

        # Log admin action
        log_admin_action(current_user_id, f'Deleted security configuration: {config_name}', get_client_ip())
        flash(f'Security configuration "{config_name}" deleted successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting security configuration: {str(e)}', 'danger')

    return redirect(url_for('security_configs'))

# Route for super admin to update another admin's payment method
@app.route('/admin/update-admin-payment/<int:admin_id>', methods=['POST'])
@jwt_required()
def update_admin_payment(admin_id):
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    # Only super admins can access this route
    if user.role != 'super_admin':
        flash('Access denied. Super admin privileges required.', 'danger')
        return redirect(url_for('admin_dashboard'))

    # Get the admin to update
    admin_to_update = User.query.filter_by(id=admin_id).first()

    if not admin_to_update or admin_to_update.role not in ['admin', 'super_admin']:
        flash('Invalid admin selected.', 'danger')
        return redirect(url_for('manage_admin_payment_methods'))

    payment_method = request.form.get('payment_method')
    payment_details = {}

    # Gather payment details based on selected method
    if payment_method == 'bank':
        payment_details = {
            'bank_name': request.form.get('bank_name'),
            'account_number': request.form.get('account_number'),
            'routing_number': request.form.get('routing_number'),
            'account_holder': request.form.get('account_holder')
        }
    elif payment_method == 'crypto':
        payment_details = {
            'crypto_currency': request.form.get('crypto_currency'),
            'wallet_address': request.form.get('wallet_address')
        }
    elif payment_method == 'paypal':
        payment_details = {
            'paypal_email': request.form.get('paypal_email')
        }

    # Update the admin's payment method and log the action
    success = update_payment_method(admin_to_update.id, payment_method, payment_details, current_user_id)

    if success:
        flash(f'Payment method for {admin_to_update.email} updated successfully.', 'success')
    else:
        flash('Failed to update payment method.', 'danger')

    return redirect(url_for('manage_admin_payment_methods'))

# PWA routes
@app.route('/offline')
def offline():
    """
    Offline page for PWA when network is unavailable
    """
    return render_template('offline.html')

# Leaderboard and Achievement routes
@app.route('/leaderboard')
def leaderboard():
    """
    Community leaderboard showing top users
    """
    # Optional time period filter
    time_period = request.args.get('period', 'all')
    if time_period not in ['all', 'week', 'month']:
        time_period = 'all'

    # Get top users for leaderboard
    top_users = get_leaderboard(limit=20, time_period=time_period)

    # Update user ranks if they've changed
    update_community_ranks()

    # Get current user if logged in
    current_user = None
    current_user_rank = None

    if 'jwt_token' in request.cookies:
        try:
            token = request.cookies.get('jwt_token')
            user_id = get_jwt_identity()
            if user_id:
                current_user = User.query.get(user_id)
                # Update user activity for leaderboard participation
                update_user_activity(user_id)

                # Get user's rank, even if not in top 20
                if current_user and current_user.community_rank:
                    current_user_rank = current_user.community_rank
        except:
            pass

    return render_template(
        'leaderboard.html', 
        users=top_users, 
        time_period=time_period,
        user=current_user,
        user_rank=current_user_rank
    )

@app.route('/achievements')
@jwt_required()
def achievements():
    """
    View all available achievements and user progress
    """
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    # Get all achievements
    all_achievements = Achievement.query.all()

    # Get user's earned achievements
    user_achievements = UserAchievement.query.filter_by(user_id=current_user_id).all()
    earned_ids = [ua.achievement_id for ua in user_achievements]

    # Update user activity
    update_user_activity(current_user_id)

    return render_template(
        'achievements.html',
        user=user,
        achievements=all_achievements,
        earned_ids=earned_ids
    )

@app.route('/profile/achievements')
@jwt_required()
def user_achievements():
    """
    View current user's earned achievements
    """
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    # Get user's earned achievements
    user_achievements = get_user_achievements(current_user_id)

    # Update user activity
    update_user_activity(current_user_id)

    return render_template(
        'user_achievements.html',
        user=user,
        achievements=user_achievements
    )

# WebSocket routes
@socketio.on('connect')
def handle_connect():
    app.logger.info('Client connected to WebSocket')

@socketio.on('disconnect')
def handle_disconnect():
    app.logger.info('Client disconnected from WebSocket')

@socketio.on('join_execution')
def handle_join_execution(data):
    execution_id = data.get('execution_id')
    if execution_id:
        app.logger.info(f'Client joined execution room {execution_id}')
        socketio.emit('execution_update', {'message': 'Joined execution room', 'execution_id': execution_id})