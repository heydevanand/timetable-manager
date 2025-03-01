import os
import sys

# Add the current directory to the path so we can import our app modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    # Import directly from app.py where models are defined
    from app import app, db, User  # Import User directly from app
    
    def reset_database():
        with app.app_context():
            print("Starting database reset...")
            try:
                # Drop all tables
                db.drop_all()
                print("Tables dropped successfully")
                
                # Recreate all tables
                db.create_all()
                print("Tables created successfully")
                
                # Create admin user
                admin = User(
                    username='admin',
                    email='admin@example.com',
                    is_admin=True,
                    full_name='Administrator',
                    department='IT'
                )
                
                # Set password
                admin.set_password('admin123')  # Using stronger default password
                
                # Add to database
                db.session.add(admin)
                db.session.commit()
                
                print("Database has been reset. Admin user created.")
                print("Username: admin")
                print("Password: admin123")
                
            except Exception as e:
                print(f"Error during database reset: {str(e)}")
                db.session.rollback()
                raise
    
    if __name__ == "__main__":
        reset_database()

except ImportError as e:
    print(f"Import error: {str(e)}")
    print("Make sure you're running this script from the correct directory.")
    sys.exit(1)
except Exception as e:
    print(f"Unexpected error: {str(e)}")
    sys.exit(1)
