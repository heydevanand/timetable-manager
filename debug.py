#!/usr/bin/env python3
"""
Debug helper script for Flask Timetable app
"""
import os
import sys
import shutil
import tempfile
import logging
from app import app, db, User

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def reset_session_files():
    """Remove Flask session files to clear cache issues"""
    try:
        session_dir = os.path.join(tempfile.gettempdir(), 'flask_session')
        if os.path.exists(session_dir):
            shutil.rmtree(session_dir)
            os.makedirs(session_dir, exist_ok=True)
            logger.info(f"Cleared session files in {session_dir}")
        else:
            os.makedirs(session_dir, exist_ok=True)
            logger.info(f"Created session directory {session_dir}")
    except Exception as e:
        logger.error(f"Error resetting session files: {e}")

def reset_database():
    """Reset the database and recreate tables"""
    try:
        with app.app_context():
            db.drop_all()
            db.create_all()
            logger.info("Database reset successfully")
    except Exception as e:
        logger.error(f"Error resetting database: {e}")

def show_users():
    """Display all users in the database"""
    try:
        with app.app_context():
            users = User.query.all()
            logger.info(f"Found {len(users)} users:")
            for user in users:
                logger.info(f"  - {user.username} (Admin: {user.is_admin})")
    except Exception as e:
        logger.error(f"Error showing users: {e}")

def main():
    """Main function to run debug operations"""
    if len(sys.argv) < 2:
        print("Usage: python debug.py [reset_session|reset_db|show_users|all]")
        return
    
    action = sys.argv[1].lower()
    
    if action == 'reset_session':
        reset_session_files()
    elif action == 'reset_db':
        reset_database()
    elif action == 'show_users':
        show_users()
    elif action == 'all':
        reset_session_files()
        reset_database()
        show_users()
    else:
        print(f"Unknown action: {action}")

if __name__ == "__main__":
    main()
