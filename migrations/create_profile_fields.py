from app import db
from flask import Flask
from flask_migrate import Migrate
from models import User

def upgrade():
    # Use SQLAlchemy to add columns if you're not using Flask-Migrate
    # This is a simple example - in a real app, use proper migration tools
    with app.app_context():
        # Add full_name column if it doesn't exist
        db.engine.execute('ALTER TABLE user ADD COLUMN IF NOT EXISTS full_name VARCHAR(150)')
        # Add department column if it doesn't exist
        db.engine.execute('ALTER TABLE user ADD COLUMN IF NOT EXISTS department VARCHAR(100)')
        # Add created_at column with default timestamp if it doesn't exist
        db.engine.execute('ALTER TABLE user ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP')
        
        db.session.commit()

if __name__ == '__main__':
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'  # Update with your actual DB URI
    db.init_app(app)
    upgrade()
