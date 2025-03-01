#!/usr/bin/env python3
import os
import sys
import sqlite3
import stat

# Database file path
DB_FILE = 'timetable.db'
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), DB_FILE)

def check_db_permissions():
    """Check database file permissions and report issues"""
    print(f"Checking database at: {DB_PATH}")
    
    # Check if file exists
    if not os.path.exists(DB_PATH):
        print(f"ERROR: Database file does not exist at {DB_PATH}")
        print("Creating an empty database file...")
        try:
            conn = sqlite3.connect(DB_PATH)
            conn.close()
            print("Empty database file created successfully")
        except Exception as e:
            print(f"Failed to create database file: {e}")
            return False
    
    # Check permissions
    try:
        file_stat = os.stat(DB_PATH)
        permissions = stat.filemode(file_stat.st_mode)
        print(f"File permissions: {permissions}")
        
        # Check if file is readable and writable
        if not os.access(DB_PATH, os.R_OK):
            print("ERROR: Database file is not readable")
            return False
        if not os.access(DB_PATH, os.W_OK):
            print("ERROR: Database file is not writable")
            return False
            
        print("File permissions look good")
        
        # Check if we can open the database
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = cursor.fetchall()
            print(f"Database contains {len(tables)} tables:")
            for table in tables:
                print(f" - {table[0]}")
            conn.close()
            print("Database connection successful")
            return True
        except sqlite3.Error as e:
            print(f"ERROR: Could not query database: {e}")
            return False
            
    except Exception as e:
        print(f"ERROR checking file permissions: {e}")
        return False

def fix_permissions():
    """Try to fix database permissions"""
    print("Attempting to fix database permissions...")
    try:
        # Make the file readable and writable by all (be careful with this in production)
        os.chmod(DB_PATH, 0o666)
        print(f"Permissions updated to allow read/write for all users")
        return True
    except Exception as e:
        print(f"ERROR fixing permissions: {e}")
        return False

if __name__ == "__main__":
    print("Database Diagnostics Tool")
    print("------------------------")
    
    if check_db_permissions():
        print("\nDatabase looks healthy!")
        sys.exit(0)
    else:
        print("\nDatabase issues detected!")
        if input("Would you like to attempt to fix permissions? (y/n): ").lower() == 'y':
            if fix_permissions() and check_db_permissions():
                print("\nPermissions fixed successfully!")
                sys.exit(0)
            else:
                print("\nCould not fix permissions automatically.")
        
        print("\nSuggested manual fixes:")
        print(" 1. Delete the database file and let the app recreate it:")
        print(f"    rm {DB_PATH}")
        print(" 2. Create an empty database with proper permissions:")
        print(f"    touch {DB_PATH} && chmod 666 {DB_PATH}")
        print(" 3. Check the app's user permissions on your server/hosting")
        sys.exit(1)
