from app import app, db, User
from datetime import datetime

with app.app_context():
    # Add new columns to user table
    try:
        with db.engine.connect() as conn:
            conn.execute('ALTER TABLE user ADD COLUMN created_at DATETIME')
            conn.execute('ALTER TABLE user ADD COLUMN full_name VARCHAR(100)')
            conn.execute('ALTER TABLE user ADD COLUMN department VARCHAR(100)')
            conn.execute('UPDATE user SET created_at = ? WHERE created_at IS NULL', (datetime.utcnow(),))
            print("Database updated successfully")
    except Exception as e:
        print(f"Error updating database: {e}")
        # If error, recreate tables (warning: this will delete existing data)
        # Uncomment below lines only if you're okay with data loss
        # db.drop_all()
        # db.create_all()
