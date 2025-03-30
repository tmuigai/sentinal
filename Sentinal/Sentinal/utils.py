import datetime
from flask import request
from app import db, app
from models import AdminLog, Tag, User, Profit, Achievement, UserAchievement
from sqlalchemy import func, desc

def log_admin_action(admin_id, action, ip_address=None, details=None):
    """
    Log an admin action in the database.
    
    Args:
        admin_id: ID of the admin performing the action
        action: Description of the action
        ip_address: IP address of the admin (optional)
        details: Additional details about the action (optional)
    """
    log = AdminLog(
        admin_id=admin_id,
        action=action,
        ip_address=ip_address,
        details=details
    )
    db.session.add(log)
    db.session.commit()
    return log

def get_client_ip():
    """Get the client's IP address from the request."""
    if request.headers.getlist("X-Forwarded-For"):
        return request.headers.getlist("X-Forwarded-For")[0]
    return request.remote_addr

def create_or_get_tag(tag_name):
    """
    Find an existing tag by name or create a new one.
    
    Args:
        tag_name: Name of the tag
    
    Returns:
        Tag object
    """
    tag = Tag.query.filter_by(name=tag_name).first()
    if not tag:
        tag = Tag(name=tag_name)
        db.session.add(tag)
        db.session.commit()
    return tag

def format_datetime(dt):
    """Format datetime for display."""
    if not dt:
        return ''
    return dt.strftime('%Y-%m-%d %H:%M:%S')

def calculate_profit_share(profit_amount):
    """
    Calculate the profit share between user and platform.
    Platform takes 30%, user gets 70%.
    
    Args:
        profit_amount: The total profit amount
    
    Returns:
        Tuple of (user_share, platform_share)
    """
    if not profit_amount or profit_amount <= 0:
        return 0, 0
    
    user_share = profit_amount * 0.7
    platform_share = profit_amount * 0.3
    
    return user_share, platform_share

def distribute_admin_fees(platform_share, script_id=None, execution_id=None):
    """
    Distribute platform fees (30%) equally among all admins.
    
    Args:
        platform_share: The amount to distribute (30% of the total profit)
        script_id: ID of the script that generated the profit (optional)
        execution_id: ID of the execution that generated the profit (optional)
    
    Returns:
        bool: True if distribution was successful, False otherwise
    """
    if not platform_share or platform_share <= 0:
        app.logger.warning("No platform share to distribute")
        return False
    
    # Get all admin users (including super_admin)
    admins = User.query.filter(User.role.in_(['admin', 'super_admin'])).all()
    if not admins:
        app.logger.warning("No admin users found to distribute fees")
        return False
    
    # Calculate equal share for each admin
    admin_count = len(admins)
    share_per_admin = platform_share / admin_count
    
    app.logger.info(f"Distributing {platform_share} to {admin_count} admins ({share_per_admin} each)")
    
    # Create profit records and update balances for each admin
    try:
        for admin in admins:
            # Update admin balance
            admin.balance += share_per_admin
            
            # Create profit record
            profit = Profit(
                user_id=admin.id,
                script_id=script_id,
                execution_id=execution_id,
                amount=share_per_admin,
                profit_type='platform_fee'
            )
            db.session.add(profit)
        
        db.session.commit()
        return True
    except Exception as e:
        app.logger.error(f"Error distributing admin fees: {str(e)}")
        db.session.rollback()
        return False

def is_super_admin(user):
    """
    Check if a user is a super admin.
    
    Args:
        user: User object to check
        
    Returns:
        bool: True if user is a super admin, False otherwise
    """
    return user and user.role == 'super_admin'

def is_admin(user):
    """
    Check if a user is an admin or super admin.
    
    Args:
        user: User object to check
        
    Returns:
        bool: True if user is an admin or super admin, False otherwise
    """
    return user and user.role in ['admin', 'super_admin']

def promote_to_admin(user_id, new_role='admin', admin_id=None):
    """
    Promote a user to admin or super admin.
    Only super admins can create other admins.
    
    Args:
        user_id: ID of the user to promote
        new_role: New role ('admin' or 'super_admin')
        admin_id: ID of the admin performing the action (for logging)
        
    Returns:
        bool: True if promotion was successful, False otherwise
    """
    if new_role not in ['admin', 'super_admin']:
        app.logger.error(f"Invalid role: {new_role}")
        return False
        
    user = User.query.get(user_id)
    if not user:
        app.logger.error(f"User {user_id} not found")
        return False
        
    try:
        user.role = new_role
        db.session.commit()
        
        if admin_id:
            action = f"promoted user {user_id} to {new_role}"
            log_admin_action(admin_id, action, get_client_ip())
            
        return True
    except Exception as e:
        app.logger.error(f"Error promoting user: {str(e)}")
        db.session.rollback()
        return False

def update_payment_method(user_id, payment_method, payment_details, admin_id=None):
    """
    Update an admin's payment method and details.
    
    Args:
        user_id: ID of the admin to update
        payment_method: Payment method (e.g., 'bank', 'crypto', 'paypal')
        payment_details: JSON with payment details
        admin_id: ID of the admin performing the action (for logging)
        
    Returns:
        bool: True if update was successful, False otherwise
    """
    user = User.query.get(user_id)
    if not user or not is_admin(user):
        app.logger.error(f"User {user_id} not found or not an admin")
        return False
        
    try:
        user.payment_method = payment_method
        user.payment_details = payment_details
        db.session.commit()
        
        if admin_id:
            action = f"updated payment method for user {user_id}"
            log_admin_action(admin_id, action, get_client_ip())
            
        return True
    except Exception as e:
        app.logger.error(f"Error updating payment method: {str(e)}")
        db.session.rollback()
        return False

# Gamification utility functions
def update_user_activity(user_id):
    """
    Update user's activity streak and award daily login XP.
    
    Args:
        user_id: ID of the user to update
        
    Returns:
        Tuple of (streak_updated, xp_awarded)
    """
    user = User.query.get(user_id)
    if not user:
        return False, 0
    
    today = datetime.datetime.utcnow().date()
    last_active_date = user.last_active.date() if user.last_active else None
    
    # Daily XP for login - only award once per day
    xp_awarded = 0
    streak_updated = False
    
    try:
        # Only update if last active is not today
        if last_active_date != today:
            # Check if we're maintaining a streak (consecutive days)
            if last_active_date and (today - last_active_date).days == 1:
                user.streak_days += 1
                streak_updated = True
                
                # Bonus XP for longer streaks
                if user.streak_days % 7 == 0:  # Weekly milestone
                    xp_awarded += 50
                    maybe_award_achievement(user_id, 'streak_weekly')
                elif user.streak_days % 30 == 0:  # Monthly milestone
                    xp_awarded += 200
                    maybe_award_achievement(user_id, 'streak_monthly')
            elif last_active_date and (today - last_active_date).days > 1:
                # Streak broken
                user.streak_days = 1
            else:
                # First activity
                user.streak_days = 1
            
            # Base daily login XP
            daily_xp = 10
            xp_awarded += daily_xp
            
            # Update last active time
            user.last_active = datetime.datetime.utcnow()
            
            # Add XP
            award_xp(user_id, xp_awarded)
            
            db.session.commit()
    except Exception as e:
        app.logger.error(f"Error updating user activity: {str(e)}")
        db.session.rollback()
        return False, 0
    
    return streak_updated, xp_awarded

def award_xp(user_id, xp_amount):
    """
    Award XP to a user and handle level ups
    
    Args:
        user_id: ID of the user to award XP to
        xp_amount: Amount of XP to award
        
    Returns:
        Tuple of (new_xp, level_up)
    """
    if xp_amount <= 0:
        return 0, False
    
    user = User.query.get(user_id)
    if not user:
        return 0, False
    
    try:
        # Calculate current level before XP award
        old_level = user.level
        
        # Add XP
        user.experience_points += xp_amount
        
        # Calculate new level - each level requires more XP
        new_level = calculate_level(user.experience_points)
        user.level = new_level
        
        level_up = new_level > old_level
        
        # Award achievements for level milestones
        if level_up:
            if new_level >= 5:
                maybe_award_achievement(user_id, 'level_5')
            if new_level >= 10:
                maybe_award_achievement(user_id, 'level_10')
            if new_level >= 25:
                maybe_award_achievement(user_id, 'level_25')
            if new_level >= 50:
                maybe_award_achievement(user_id, 'level_50')
        
        db.session.commit()
        return user.experience_points, level_up
    except Exception as e:
        app.logger.error(f"Error awarding XP: {str(e)}")
        db.session.rollback()
        return 0, False

def calculate_level(xp):
    """
    Calculate level based on XP.
    Formula: Level = 1 + sqrt(XP / 100)
    This creates a curve where each level requires more XP.
    
    Args:
        xp: Experience points
        
    Returns:
        int: User level
    """
    import math
    if xp <= 0:
        return 1
    
    level = 1 + int(math.sqrt(xp / 100))
    return level

def update_community_ranks():
    """
    Update user community ranks based on XP.
    This should be called periodically.
    
    Returns:
        bool: True if update was successful
    """
    try:
        # Get users ordered by XP
        users = User.query.order_by(User.experience_points.desc()).all()
        
        # Assign ranks
        for i, user in enumerate(users):
            user.community_rank = i + 1
        
        db.session.commit()
        return True
    except Exception as e:
        app.logger.error(f"Error updating community ranks: {str(e)}")
        db.session.rollback()
        return False

def maybe_award_achievement(user_id, achievement_code):
    """
    Check if a user should receive an achievement and award it if so.
    
    Args:
        user_id: ID of the user
        achievement_code: Code identifying the achievement
        
    Returns:
        bool: True if achievement was awarded
    """
    user = User.query.get(user_id)
    if not user:
        return False
    
    # Check if user already has this achievement
    achievement = Achievement.query.filter_by(name=achievement_code).first()
    if not achievement:
        app.logger.error(f"Achievement {achievement_code} not found")
        return False
    
    # Check if user already has this achievement
    existing = UserAchievement.query.filter_by(
        user_id=user_id, achievement_id=achievement.id
    ).first()
    
    if existing:
        return False  # Already awarded
    
    try:
        # Award achievement
        user_achievement = UserAchievement(
            user_id=user_id,
            achievement_id=achievement.id
        )
        db.session.add(user_achievement)
        
        # Award XP for achievement
        award_xp(user_id, achievement.points)
        
        db.session.commit()
        return True
    except Exception as e:
        app.logger.error(f"Error awarding achievement: {str(e)}")
        db.session.rollback()
        return False

def get_leaderboard(limit=10, time_period=None):
    """
    Get top users for the leaderboard
    
    Args:
        limit: Number of users to return
        time_period: Optional time period filter (all, week, month)
        
    Returns:
        List of user objects with rank, username, level, and XP
    """
    query = User.query
    
    # Apply time filter if specified
    if time_period == 'week':
        week_ago = datetime.datetime.utcnow() - datetime.timedelta(days=7)
        query = query.filter(User.last_active >= week_ago)
    elif time_period == 'month':
        month_ago = datetime.datetime.utcnow() - datetime.timedelta(days=30)
        query = query.filter(User.last_active >= month_ago)
    
    # Get users sorted by XP
    top_users = query.order_by(User.experience_points.desc()).limit(limit).all()
    
    return top_users

def get_user_achievements(user_id):
    """
    Get all achievements for a user
    
    Args:
        user_id: ID of the user
        
    Returns:
        List of achievement objects with name, description, and date earned
    """
    return UserAchievement.query.filter_by(user_id=user_id)\
        .join(Achievement)\
        .order_by(UserAchievement.date_earned.desc())\
        .all()
