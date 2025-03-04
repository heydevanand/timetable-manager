from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_required, current_user
from models import db, User, Teacher, Schedule
from utils import create_admin_user
from flask_wtf.csrf import csrf_exempt

# Create a blueprint for admin routes
admin = Blueprint('admin', __name__)

# Admin route protection decorator
def admin_required(func):
    @login_required
    def decorated_view(*args, **kwargs):
        if not current_user.is_admin:
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('main.index'))
        return func(*args, **kwargs)
    decorated_view.__name__ = func.__name__
    return decorated_view

@admin.route('/users')
@admin_required
def manage_users():
    users = User.query.all()
    return render_template('users.html', users=users)

@admin.route('/users/toggle_admin/<int:id>')
@admin_required
def toggle_admin(id):
    user = User.query.get_or_404(id)
    # Prevent removing admin rights from the last admin
    if user.is_admin and User.query.filter_by(is_admin=True).count() <= 1:
        flash('Cannot remove the last admin.', 'danger')
    else:
        user.is_admin = not user.is_admin
        db.session.commit()
        flash(f"User {user.username}'s admin status updated.", 'success')
    
    return redirect(url_for('admin.manage_users'))

@admin.route('/users/delete/<int:id>')
@admin_required
def delete_user(id):
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
    
    return redirect(url_for('admin.manage_users'))

@admin.route('/teacher/add', methods=['GET', 'POST'])
@admin_required
def add_teacher():
    if request.method == 'POST':
        name = request.form['name']
        
        # Check if teacher already exists
        if Teacher.query.filter_by(name=name).first():
            flash('Teacher already exists!', 'danger')
            return redirect(url_for('admin.add_teacher'))
        
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
        return redirect(url_for('main.index'))
    
    return render_template('add_teacher.html')

@admin.route('/teacher/edit/<int:id>', methods=['GET', 'POST'])
@admin_required
def edit_teacher(id):
    teacher = Teacher.query.get_or_404(id)
    
    if request.method == 'POST':
        name = request.form['name']
        
        # Check if new name already exists for another teacher
        existing = Teacher.query.filter_by(name=name).first()
        if existing and existing.id != id:
            flash('Teacher name already exists!', 'danger')
            return redirect(url_for('admin.edit_teacher', id=id))
        
        teacher.name = name
        db.session.commit()
        flash('Teacher updated successfully!', 'success')
        return redirect(url_for('main.index'))
    
    return render_template('edit_teacher.html', teacher=teacher)

@admin.route('/teacher/delete/<int:id>')
@admin_required
def delete_teacher(id):
    teacher = Teacher.query.get_or_404(id)
    db.session.delete(teacher)
    db.session.commit()
    flash('Teacher deleted successfully!', 'success')
    return redirect(url_for('main.index'))

@admin.route('/schedule/edit', methods=['GET', 'POST'])
@admin_required
def edit_schedule():
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
            
        return redirect(url_for('main.timetable'))
    
    teacher_id = request.args.get('teacher_id')
    day = request.args.get('day')
    time_slot = request.args.get('time_slot')
    
    schedule = Schedule.query.filter_by(
        teacher_id=teacher_id,
        day=day,
        time_slot=time_slot
    ).first_or_404()
    
    return render_template('edit_schedule.html', schedule=schedule)

@admin.route('/api/schedule/<int:teacher_id>/<string:day>/<string:time_slot>')
@csrf_exempt
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

# Administration and debugging routes
@admin.route('/initialize-admin', methods=['GET'])
@csrf_exempt
def initialize_admin():
    create_admin_user()
    flash('Admin user created or reset with username: admin and password: admin123', 'success')
    return redirect(url_for('auth.login'))

@admin.route('/reset-database', methods=['GET'])
@csrf_exempt
def reset_db_route():
    try:
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
        admin.set_password('admin123')
        
        # Add to database
        db.session.add(admin)
        db.session.commit()
        
        flash('Database has been reset. Admin user created with username: admin and password: admin123', 'success')
        return redirect(url_for('auth.login'))
    except Exception as e:
        return f"Error resetting database: {str(e)}", 500
