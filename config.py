import os
import tempfile

class Config:
    """Base configuration."""
    SECRET_KEY = os.environ.get('SECRET_KEY', 'default-key-for-dev')
    SESSION_TYPE = 'filesystem'
    SESSION_FILE_DIR = os.path.join(tempfile.gettempdir(), 'flask_session')
    SESSION_PERMANENT = True
    SESSION_USE_SIGNER = True
    PERMANENT_SESSION_LIFETIME = 3600  # 1 hour
    WTF_CSRF_ENABLED = True
    WTF_CSRF_SSL_STRICT = False  # Don't require HTTPS for dev
    SQLALCHEMY_TRACK_MODIFICATIONS = False

class DevelopmentConfig(Config):
    """Development configuration."""
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///timetable.db'
    

class ProductionConfig(Config):
    """Production configuration."""
    DEBUG = False
    WTF_CSRF_SSL_STRICT = True  # Require HTTPS for production
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///timetable.db')
    SECRET_KEY = os.environ.get('SECRET_KEY')  # Must be set in production
    
    # Make sure secret key is set
    @classmethod
    def init_app(cls, app):
        Config.init_app(app)
        
        # Log to stderr
        import logging
        from logging import StreamHandler
        file_handler = StreamHandler()
        file_handler.setLevel(logging.WARNING)
        app.logger.addHandler(file_handler)

# Default to development config
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
