# app.py - Main Flask Application
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///timetable.db'
app.config['SQLALCHEMY_TRACK_CHANGES'] = False
app.config['SECRET_KEY'] = 'your-secret-key'
db = SQLAlchemy(app)

# Models
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

# Routes
@app.route('/')
def index():
    teachers = Teacher.query.all()
    return render_template('index.html', teachers=teachers)

@app.route('/timetable')
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
def add_teacher():
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
def edit_teacher(id):
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
def delete_teacher(id):
    teacher = Teacher.query.get_or_404(id)
    db.session.delete(teacher)
    db.session.commit()
    flash('Teacher deleted successfully!', 'success')
    return redirect(url_for('index'))

# Schedule CRUD
@app.route('/schedule/edit', methods=['GET', 'POST'])
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

@app.route('/api/schedule/<int:teacher_id>/<string:day>/<string:time_slot>')
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

# Run the app
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        init_data()
    app.run(debug=True)