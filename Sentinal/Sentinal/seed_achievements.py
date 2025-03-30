"""
Seed script to create initial achievements in the database
"""
from app import app, db
from models import Achievement

def create_achievements():
    """Create standard achievement records"""
    
    # Remove any existing achievements first
    Achievement.query.delete()
    
    # Define our achievements
    achievements = [
        # Level-based achievements
        {
            'name': 'level_5',
            'description': 'Reached Level 5',
            'badge_image': '/static/img/badge-level5.svg',
            'points': 100,
            'difficulty': 'easy',
            'category': 'experience'
        },
        {
            'name': 'level_10',
            'description': 'Reached Level 10',
            'badge_image': '/static/img/badge-level10.svg',
            'points': 200,
            'difficulty': 'medium',
            'category': 'experience'
        },
        {
            'name': 'level_25',
            'description': 'Reached Level 25',
            'badge_image': '/static/img/badge-level25.svg',
            'points': 500,
            'difficulty': 'hard',
            'category': 'experience'
        },
        {
            'name': 'level_50',
            'description': 'Reached Level 50',
            'badge_image': '/static/img/badge-level50.svg',
            'points': 1000,
            'difficulty': 'elite',
            'category': 'experience'
        },
        
        # Streak-based achievements
        {
            'name': 'streak_weekly',
            'description': 'Active for 7 days in a row',
            'badge_image': '/static/img/badge-streak7.svg',
            'points': 50,
            'difficulty': 'easy',
            'category': 'engagement'
        },
        {
            'name': 'streak_monthly',
            'description': 'Active for 30 days in a row',
            'badge_image': '/static/img/badge-streak30.svg',
            'points': 200,
            'difficulty': 'medium',
            'category': 'engagement'
        },
        
        # Script creation achievements
        {
            'name': 'first_script',
            'description': 'Created your first trading script',
            'badge_image': '/static/img/badge-script1.svg',
            'points': 50,
            'difficulty': 'easy',
            'category': 'scripting'
        },
        {
            'name': 'five_scripts',
            'description': 'Created 5 trading scripts',
            'badge_image': '/static/img/badge-script5.svg',
            'points': 100,
            'difficulty': 'medium',
            'category': 'scripting'
        },
        {
            'name': 'popular_script',
            'description': 'Created a script used by 5+ traders',
            'badge_image': '/static/img/badge-popular.svg',
            'points': 200,
            'difficulty': 'hard',
            'category': 'scripting'
        },
        
        # Trading achievements
        {
            'name': 'first_profit',
            'description': 'Made your first profit',
            'badge_image': '/static/img/badge-profit1.svg',
            'points': 50,
            'difficulty': 'easy',
            'category': 'trading'
        },
        {
            'name': 'hundred_profit',
            'description': 'Accumulated $100 in profits',
            'badge_image': '/static/img/badge-profit100.svg',
            'points': 100,
            'difficulty': 'medium',
            'category': 'trading'
        },
        {
            'name': 'thousand_profit',
            'description': 'Accumulated $1000 in profits',
            'badge_image': '/static/img/badge-profit1000.svg',
            'points': 500,
            'difficulty': 'hard',
            'category': 'trading'
        },
        
        # Community achievements
        {
            'name': 'top_10',
            'description': 'Reached top 10 on the leaderboard',
            'badge_image': '/static/img/badge-top10.svg',
            'points': 200,
            'difficulty': 'hard',
            'category': 'community'
        },
        {
            'name': 'top_3',
            'description': 'Reached top 3 on the leaderboard',
            'badge_image': '/static/img/badge-top3.svg',
            'points': 500,
            'difficulty': 'elite',
            'category': 'community'
        },
        {
            'name': 'number_1',
            'description': 'Reached #1 on the leaderboard',
            'badge_image': '/static/img/badge-number1.svg',
            'points': 1000,
            'difficulty': 'elite',
            'category': 'community'
        }
    ]
    
    # Add all achievements to the database
    for achievement_data in achievements:
        achievement = Achievement(**achievement_data)
        db.session.add(achievement)
    
    # Commit the changes
    db.session.commit()
    print(f"Created {len(achievements)} achievements")
    
if __name__ == '__main__':
    with app.app_context():
        create_achievements()