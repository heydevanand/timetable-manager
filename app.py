# app.py - Main Flask Application
import os
import logging
import sys
import tempfile
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect, generate_csrf
from flask_session import Session

# Determine the environment
env = os.environ.get('FLASK_ENV', 'development')
debug_mode = env == 'development'

# Configure logging
logging.basicConfig(
    stream=sys.stdout,
    level=logging.DEBUG if debug_mode else logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Create Flask application
app = Flask(__name__)

# Import configuration
if debug_mode:
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///timetable.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # Generate/load secret key for development
    SECRET_KEY_FILE = os.path.join(app.root_path, 'secret_key')
    if os.path.exists(SECRET_KEY_FILE):
        with open(SECRET_KEY_FILE, 'rb') as f:
            app.config['SECRET_KEY'] = f.read()
    else:
        app.config['SECRET_KEY'] = os.urandom(24)
        with open(SECRET_KEY_FILE, 'wb') as f:
            f.write(app.config['SECRET_KEY'])
else:
    # Production settings
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///timetable.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
    
    if not app.config['SECRET_KEY']:
        app.logger.error("No SECRET_KEY set for production environment!")
        
    app.config['WTF_CSRF_SSL_STRICT'] = True

# Configure session to use filesystem
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_FILE_DIR'] = os.path.join(tempfile.gettempdir(), 'flask_session')
app.config['SESSION_PERMANENT'] = True
app.config['SESSION_USE_SIGNER'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1 hour

# Create session directory if it doesn't exist
os.makedirs(app.config['SESSION_FILE_DIR'], exist_ok=True)

# Initialize session
Session(app)

# Initialize SQLAlchemy and CSRF protection
db = SQLAlchemy(app)
csrf = CSRFProtect(app)

# Configure CSRF protection
app.config['WTF_CSRF_TIME_LIMIT'] = None if debug_mode else 3600
app.config['WTF_CSRF_ENABLED'] = True

# Set up Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    full_name = db.Column(db.String(100), nullable=True)
    department = db.Column(db.String(100), nullable=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
        
    def __repr__(self):
        return f"User('{self.username}', '{self.email}')"

class Teacher(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    schedules = db.relationship('Schedule', backref='teacher', lazy=True, cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"Teacher('{self.name}')"

class Schedule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    day = db.Column(db.String(20), nullable=False)
    time_slot = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(10), nullable=False, default='Free')  # 'Free' or 'Engaged'
    room_number = db.Column(db.String(10), nullable=True)
    teacher_id = db.Column(db.Integer, db.ForeignKey('teacher.id'), nullable=False)
    
    def __repr__(self):
        return f"Schedule('{self.day}', '{self.time_slot}', '{self.status}', '{self.room_number}')"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Initialize the data from CSV
def init_data():
    # Check if data already exists
    if Teacher.query.first():
        return
    
    # Create teachers
    teachers = [
        "Ashish Mishra", "Himanshu", "Dev Anand", "Harish Ojha", 
        "Yogesh Vajpayee", "Shubham", "Mukesh Jangid", "Kapil Manchandani"
    ]
    
    days = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
    time_slots = [
        "08:00 - 09:00", "09:00 - 10:00", "10:00 - 11:00", "11:00 - 12:00",
        "12:00 - 01:00", "01:00 - 02:00", "02:00 - 03:00", "03:00 - 04:00",
        "04:00 - 05:00", "05:00 - 06:00"
    ]
    
    # Sample data (you can add more from the CSV)
    timetable_data = [
        # Format: (teacher_name, day, time_slot, status, room_number)
        ("Ashish Mishra", "Monday", "08:00 - 09:00", "Engaged", "201"),
        ("Himanshu", "Monday", "08:00 - 09:00", "Engaged", "107"),
        ("Ashish Mishra", "Monday", "09:00 - 10:00", "Free", None),
        # Add more entries here...
    ]
    
    # Create teacher objects
    teacher_objects = {}
    for teacher_name in teachers:
        teacher = Teacher(name=teacher_name)
        db.session.add(teacher)
        db.session.commit()
        teacher_objects[teacher_name] = teacher
    
    # Create initial schedules for all teachers and time slots
    for teacher_name in teachers:
        teacher = teacher_objects[teacher_name]
        for day in days:
            for time_slot in time_slots:
                # Default everything to Free
                schedule = Schedule(
                    day=day,
                    time_slot=time_slot,
                    status="Free",
                    room_number=None,
                    teacher=teacher
                )
                db.session.add(schedule)
    
    # Update with the sample data
    for data in timetable_data:
        teacher_name, day, time_slot, status, room_number = data
        teacher = teacher_objects[teacher_name]
        
        # Find the existing schedule
        schedule = Schedule.query.filter_by(
            teacher_id=teacher.id,
            day=day,
            time_slot=time_slot
        ).first()
        
        if schedule:
            schedule.status = status
            schedule.room_number = room_number
    
    db.session.commit()
    
    # Create admin user with clear credentials
    create_admin_user()

# Add a dedicated function to create/reset admin user
def create_admin_user():
    admin = User.query.filter_by(username='admin').first()
    if admin:
        # Update existing admin's password
        admin.set_password('admin123')
        # Ensure created_at exists
        if not hasattr(admin, 'created_at') or admin.created_at is None:
            admin.created_at = datetime.utcnow()
    else:
        # Create new admin user
        admin = User(
            username='admin', 
            email='admin@example.com', 
            is_admin=True,
            created_at=datetime.utcnow()
        )
        admin.set_password('admin123')
        db.session.add(admin)
    
    db.session.commit()
    print("Admin user created/updated successfully with username 'admin' and password 'admin123'")

# Authentication Routes
@app.route('/login', methods=['GET', 'POST'])
@csrf.exempt
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if not user:
            flash('Login failed. User does not exist.', 'danger')
        elif not user.check_password(password):
            flash('Login failed. Incorrect password.', 'danger')
        else:
            # Make session permanent to extend beyond browser close
            session.permanent = True
            login_user(user, remember=('remember' in request.form))
            next_page = request.args.get('next')
            flash('Login successful!', 'success')
            return redirect(next_page or url_for('index'))
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
@csrf.exempt
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        # Check if username or email already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'danger')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'danger')
            return redirect(url_for('register'))
            
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('register'))
            
        # Create new user (all new registrations are regular users)
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))
        
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/users')
@login_required
def manage_users():
    # Only admin can manage users
    if not current_user.is_admin:
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('index'))
    
    users = User.query.all()
    return render_template('users.html', users=users)

@app.route('/users/toggle_admin/<int:id>')
@login_required
def toggle_admin(id):
    # Only admin can change roles
    if not current_user.is_admin:
        flash('You do not have permission to perform this action.', 'danger')
        return redirect(url_for('index'))
    
    user = User.query.get_or_404(id)
    # Prevent removing admin rights from the last admin
    if user.is_admin and User.query.filter_by(is_admin=True).count() <= 1:
        flash('Cannot remove the last admin.', 'danger')
    else:
        user.is_admin = not user.is_admin
        db.session.commit()
        flash(f"User {user.username}'s admin status updated.", 'success')
    
    return redirect(url_for('manage_users'))

@app.route('/users/delete/<int:id>')
@login_required
def delete_user(id):
    # Only admin can delete users
    if not current_user.is_admin:
        flash('You do not have permission to perform this action.', 'danger')
        return redirect(url_for('index'))
    
    user = User.query.get_or_404(id)
    
    # Prevent deleting yourself or the last admin
    if user == current_user:
        flash('You cannot delete your own account.', 'danger')
    elif user.is_admin and User.query.filter_by(is_admin=True).count() <= 1:
        flash('Cannot delete the last admin.', 'danger')
    else:
        db.session.delete(user)
        db.session.commit()
        flash(f"User {user.username} has been deleted.", 'success')
    
    return redirect(url_for('manage_users'))

# Routes
@app.route('/')
def index():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    teachers = Teacher.query.all()
    return render_template('index.html', teachers=teachers)

@app.route('/timetable')
@login_required
def timetable():
    days = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
    time_slots = [
        "08:00 - 09:00", "09:00 - 10:00", "10:00 - 11:00", "11:00 - 12:00",
        "12:00 - 01:00", "01:00 - 02:00", "02:00 - 03:00", "03:00 - 04:00",
        "04:00 - 05:00", "05:00 - 06:00"
    ]
    teachers = Teacher.query.all()
    
    return render_template('timetable.html', days=days, time_slots=time_slots, teachers=teachers)

@app.route('/free_teachers')
@login_required
def free_teachers():
    days = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
    time_slots = [
        "08:00 - 09:00", "09:00 - 10:00", "10:00 - 11:00", "11:00 - 12:00",
        "12:00 - 01:00", "01:00 - 02:00", "02:00 - 03:00", "03:00 - 04:00",
        "04:00 - 05:00", "05:00 - 06:00"
    ]
    
    selected_day = request.args.get('day', days[0])
    selected_time = request.args.get('time_slot', time_slots[0])
    
    free_teachers_list = Teacher.query.join(Schedule).filter(
        Schedule.day == selected_day,
        Schedule.time_slot == selected_time,
        Schedule.status == 'Free'
    ).all()
    
    return render_template('free_teachers.html', 
                          free_teachers=free_teachers_list,
                          days=days,
                          time_slots=time_slots,
                          selected_day=selected_day,
                          selected_time=selected_time)

# Teacher CRUD
@app.route('/teacher/add', methods=['GET', 'POST'])
@login_required
@csrf.exempt  # This exempts the route from CSRF protection (not recommended)
def add_teacher():
    # Only admin can add teachers
    if not current_user.is_admin:
        flash('You do not have permission to add teachers.', 'danger')
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        name = request.form['name']
        
        # Check if teacher already exists
        if Teacher.query.filter_by(name=name).first():
            flash('Teacher already exists!', 'danger')
            return redirect(url_for('add_teacher'))
        
        teacher = Teacher(name=name)
        db.session.add(teacher)
        
        # Create default schedule entries for the new teacher
        days = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
        time_slots = [
            "08:00 - 09:00", "09:00 - 10:00", "10:00 - 11:00", "11:00 - 12:00",
            "12:00 - 01:00", "01:00 - 02:00", "02:00 - 03:00", "03:00 - 04:00",
            "04:00 - 05:00", "05:00 - 06:00"
        ]
        
        for day in days:
            for time_slot in time_slots:
                schedule = Schedule(
                    day=day,
                    time_slot=time_slot,
                    status="Free",
                    room_number=None,
                    teacher=teacher
                )
                db.session.add(schedule)
        
        db.session.commit()
        flash('Teacher added successfully!', 'success')
        return redirect(url_for('index'))
    
    return render_template('add_teacher.html')

@app.route('/teacher/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_teacher(id):
    # Only admin can edit teachers
    if not current_user.is_admin:
        flash('You do not have permission to edit teachers.', 'danger')
        return redirect(url_for('index'))
        
    teacher = Teacher.query.get_or_404(id)
    
    if request.method == 'POST':
        name = request.form['name']
        
        # Check if new name already exists for another teacher
        existing = Teacher.query.filter_by(name=name).first()
        if existing and existing.id != id:
            flash('Teacher name already exists!', 'danger')
            return redirect(url_for('edit_teacher', id=id))
        
        teacher.name = name
        db.session.commit()
        flash('Teacher updated successfully!', 'success')
        return redirect(url_for('index'))
    
    return render_template('edit_teacher.html', teacher=teacher)

@app.route('/teacher/delete/<int:id>')
@login_required
def delete_teacher(id):
    # Only admin can delete teachers
    if not current_user.is_admin:
        flash('You do not have permission to delete teachers.', 'danger')
        return redirect(url_for('index'))
        
    teacher = Teacher.query.get_or_404(id)
    db.session.delete(teacher)
    db.session.commit()
    flash('Teacher deleted successfully!', 'success')
    return redirect(url_for('index'))

# Schedule CRUD
@app.route('/schedule/edit', methods=['GET', 'POST'])
@login_required
def edit_schedule():
    # Only admin can edit schedule
    if not current_user.is_admin:
        flash('You do not have permission to edit schedules.', 'danger')
        return redirect(url_for('timetable'))
        
    if request.method == 'POST':
        teacher_id = request.form['teacher_id']
        day = request.form['day']
        time_slot = request.form['time_slot']
        status = request.form['status']
        room_number = request.form['room_number'] if request.form['room_number'] else None
        
        schedule = Schedule.query.filter_by(
            teacher_id=teacher_id,
            day=day,
            time_slot=time_slot
        ).first()
        
        if schedule:
            schedule.status = status
            schedule.room_number = room_number
            db.session.commit()
            flash('Schedule updated successfully!', 'success')
        else:
            flash('Schedule not found!', 'danger')
            
        return redirect(url_for('timetable'))
    
    teacher_id = request.args.get('teacher_id')
    day = request.args.get('day')
    time_slot = request.args.get('time_slot')
    
    schedule = Schedule.query.filter_by(
        teacher_id=teacher_id,
        day=day,
        time_slot=time_slot
    ).first_or_404()
    
    return render_template('edit_schedule.html', schedule=schedule)

@csrf.exempt
@app.route('/api/schedule/<int:teacher_id>/<string:day>/<string:time_slot>')
@login_required
def get_schedule(teacher_id, day, time_slot):
    schedule = Schedule.query.filter_by(
        teacher_id=teacher_id,
        day=day,
        time_slot=time_slot
    ).first()
    
    if schedule:
        return jsonify({
            'status': schedule.status,
            'room_number': schedule.room_number
        })
    else:
        return jsonify({
            'status': 'Free',
            'room_number': None
        })

# Add a dedicated route to initialize/reset admin (requires app to be running)
@app.route('/initialize-admin', methods=['GET'])
@csrf.exempt
def initialize_admin():
    # Only allow this in development
    if not app.debug:
        return "Not allowed in production", 403
        
    create_admin_user()
    flash('Admin user created or reset with username: admin and password: admin123', 'success')
    return redirect(url_for('login'))

# Profile route - displays user profile information
@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')

# Edit profile route - handles both display and processing of profile edits
@app.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def edit_profile():
    if request.method == 'POST':
        # Get form data
        email = request.form.get('email')
        full_name = request.form.get('full_name')
        department = request.form.get('department')
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        # Verify current password - FIX: use check_password method
        if not current_user.check_password(current_password):
            flash('Current password is incorrect', 'danger')
            return redirect(url_for('edit_profile'))
        
        # Check if the new email is already in use by another user
        if email != current_user.email:
            user = User.query.filter_by(email=email).first()
            if user and user.id != current_user.id:
                flash('Email is already in use', 'danger')
                return redirect(url_for('edit_profile'))
        
        # Update user information
        current_user.email = email
        current_user.full_name = full_name
        current_user.department = department
        
        # Update password if provided - FIX: use set_password method
        if new_password:
            if new_password != confirm_password:
                flash('New passwords do not match', 'danger')
                return redirect(url_for('edit_profile'))
            current_user.set_password(new_password)
        
        # Save changes to database
        db.session.commit()
        flash('Profile updated successfully', 'success')
        return redirect(url_for('profile'))
    
    # For GET requests, just display the edit form
    return render_template('edit_profile.html')

# Add a route to check and reset CSRF token if needed
@app.route('/check-csrf')
def check_csrf():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    
    # Force regenerate CSRF token
    csrf_token = generate_csrf()  # Use the imported function
    
    if app.debug:
        return render_template('check_csrf.html', 
                             csrf_token=csrf_token,
                             session_data=dict(session))
    else:
        return redirect(url_for('index'))

# Ensure all CSRF exempt routes are explicitly marked
csrf.exempt(app.route('/initialize-admin')(initialize_admin))
csrf.exempt(app.route('/api/schedule/<int:teacher_id>/<string:day>/<string:time_slot>')(get_schedule))

# Create a direct access route with CSRF disabled for debugging
@app.route('/direct-access')
@csrf.exempt
def direct_access():
    # Only in debug mode for security
    if not app.debug:
        return "Not allowed in production", 403
        
    # Log in as admin automatically (ONLY FOR DEVELOPMENT)
    admin = User.query.filter_by(username='admin').first()
    if admin:
        login_user(admin)
        flash('Auto-login as admin for debugging', 'info')
        return redirect(url_for('index'))
    else:
        flash('Admin user not found. Initializing database...', 'warning')
        try:
            with app.app_context():
                db.create_all()
                create_admin_user()
                admin = User.query.filter_by(username='admin').first()
                if admin:
                    login_user(admin)
                    return redirect(url_for('index'))
        except Exception as e:
            return f"Error: {str(e)}", 500

# Add a dedicated route to reset database (this should be removed in production)
@app.route('/reset-database', methods=['GET'])
@csrf.exempt
def reset_db_route():
    # Only allow this in development
    if not app.debug:
        return "Not allowed in production", 403
        
    try:
        with app.app_context():
            # Drop all tables
            db.drop_all()
            
            # Recreate all tables
            db.create_all()
            
            # Create admin user
            admin = User(
                username='admin',
                email='admin@example.com',
                is_admin=True,
                full_name='Administrator',
                department='IT'
            )
            
            # Set password
            admin.set_password('admin123')
            
            # Add to database
            db.session.add(admin)
            db.session.commit()
            
            flash('Database has been reset. Admin user created with username: admin and password: admin123', 'success')
            return redirect(url_for('login'))
    except Exception as e:
        return f"Error resetting database: {str(e)}", 500

# Ensure CSRF exempt is properly registered for this route
csrf.exempt(app.route('/reset-database')(reset_db_route))

# Make sure all forms have CSRF tokens by adding this context processor
@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf())  # Use the imported function

# Add a public database reset endpoint with all protections disabled
@app.route('/public-reset', methods=['GET'])
@csrf.exempt
def public_reset():
    try:
        # Get the database filepath
        db_path = app.config['SQLALCHEMY_DATABASE_URI'].replace('sqlite:///', '')
        if not db_path.startswith('/'):
            # It's a relative path, make it absolute
            db_path = os.path.join(app.root_path, db_path)
            
        print(f"Database path: {db_path}")
        
        # Check if we can access the database directory
        db_dir = os.path.dirname(db_path)
        if not os.access(db_dir, os.W_OK):
            return f"Cannot write to database directory: {db_dir}", 500
            
        # Try to reconnect to the database
        try:
            db.session.execute('SELECT 1')
        except:
            db.session.rollback()
            
        # Drop and recreate all tables
        db.drop_all()
        db.create_all()
        
        # Create admin user
        admin = User(
            username='admin',
            email='admin@example.com',
            is_admin=True,
            full_name='Administrator',
            department='IT'
        )
        admin.set_password('admin123')
        
        # Add to database
        db.session.add(admin)
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            return f"Database commit failed: {str(e)}", 500
            
        return f"""
        <html>
        <body>
            <h1>Database Reset Successful</h1>
            <p>Admin user created with:</p>
            <ul>
                <li>Username: admin</li>
                <li>Password: admin123</li>
            </ul>
            <p><a href="/login">Go to login</a></p>
        </body>
        </html>
        """
    except Exception as e:
        print(f"Error in public_reset: {str(e)}")
        return f"Error: {str(e)}", 500

# Add a database debugging endpoint
@app.route('/debug-db', methods=['GET'])
@csrf.exempt
def debug_db():
    if not app.debug:
        return "Not available in production", 403
        
    try:
        # Basic diagnostics
        result = "<h2>Database Diagnostics</h2>"
        
        # Get database file path
        db_path = app.config['SQLALCHEMY_DATABASE_URI'].replace('sqlite:///', '')
        if not db_path.startswith('/'):
            # It's a relative path, make it absolute
            db_path = os.path.join(app.root_path, db_path)
        
        result += f"<p>Database path: {db_path}</p>"
        
        # Check if file exists
        if os.path.exists(db_path):
            result += f"<p>✅ Database file exists</p>"
            
            # Check permissions
            try:
                file_stat = os.stat(db_path)
                result += f"<p>File permissions: {oct(file_stat.st_mode)}</p>"
                
                if os.access(db_path, os.R_OK):
                    result += "<p>✅ File is readable</p>"
                else:
                    result += "<p>❌ File is not readable</p>"
                    
                if os.access(db_path, os.W_OK):
                    result += "<p>✅ File is writable</p>"
                else:
                    result += "<p>❌ File is not writable</p>"
            except Exception as e:
                result += f"<p>❌ Error checking permissions: {str(e)}</p>"
        else:
            result += f"<p>❌ Database file does not exist!</p>"
            
        # Check connection
        try:
            db.session.execute('SELECT 1')
            result += "<p>✅ Database connection successful</p>"
            
            # Count tables
            try:
                engine = db.engine
                inspector = db.inspect(engine)
                tables = inspector.get_table_names()
                result += f"<p>Tables in database: {len(tables)}</p>"
                result += "<ul>"
                for table in tables:
                    count = db.session.execute(f"SELECT COUNT(*) FROM {table}").scalar()
                    result += f"<li>{table}: {count} rows</li>"
                result += "</ul>"
            except Exception as e:
                result += f"<p>❌ Error inspecting tables: {str(e)}</p>"
                
        except Exception as e:
            result += f"<p>❌ Database connection failed: {str(e)}</p>"
            
        # Add action buttons
        result += """
        <hr>
        <h3>Actions:</h3>
        <ul>
            <li><a href="/public-reset" onclick="return confirm('Are you sure? This will ERASE ALL DATA!')">Reset Database (create new admin)</a></li>
            <li><a href="/login">Go to Login</a></li>
        </ul>
        """
            
        return f"""
        <html>
        <head><title>Database Diagnostics</title></head>
        <body>{result}</body>
        </html>
        """
    except Exception as e:
        return f"Error in diagnostics: {str(e)}", 500

# Make sure to exempt these routes from CSRF protection
csrf.exempt(app.route('/public-reset')(public_reset))
csrf.exempt(app.route('/debug-db')(debug_db))

# Run the app
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        init_data()
    app.run(debug=True, use_reloader=True)
else:
    # This ensures init_data runs even when imported by a WSGI server
    with app.app_context():
        db.create_all()
        init_data()
        try:
            init_data()
        except Exception as e:
            print(f"Error initializing data: {e}")