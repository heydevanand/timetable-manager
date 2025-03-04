# Fix import statements by using absolute imports with dot notation
from .models import db, User, Teacher, Schedule
from datetime import datetime

def create_admin_user():
    """Create or reset the admin user."""
    admin = User.query.filter_by(username='admin').first()
    if admin:
        # Update existing admin's password
        admin.set_password('admin123')
    else:
        # Create new admin user
        admin = User(
            username='admin', 
            email='admin@example.com', 
            is_admin=True,
            full_name='Administrator',
            department='IT'
        )
        admin.set_password('admin123')
        db.session.add(admin)
    
    db.session.commit()
    print("Admin user created/updated successfully with username 'admin' and password 'admin123'")
    return admin

def init_data():
    """Initialize database with sample data if empty."""
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
    
    # Sample data
    timetable_data = [
        # Format: (teacher_name, day, time_slot, status, room_number)
        ("Ashish Mishra", "Monday", "08:00 - 09:00", "Engaged", "201"),
        ("Himanshu", "Monday", "08:00 - 09:00", "Engaged", "107"),
        ("Ashish Mishra", "Monday", "09:00 - 10:00", "Free", None),
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
    
    # Create admin user
    create_admin_user()
