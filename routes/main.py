from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from models import db, Teacher, Schedule
from flask_wtf.csrf import csrf_exempt, generate_csrf

# Create a blueprint for main routes
main = Blueprint('main', __name__)

@main.route('/')
def index():
    if not current_user.is_authenticated:
        return redirect(url_for('auth.login'))
    teachers = Teacher.query.all()
    return render_template('index.html', teachers=teachers)

@main.route('/timetable')
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

@main.route('/free_teachers')
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
