import os
import sys
import pytest
import tempfile

# Ensure the project root is in the Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from app import app, db, User, Teacher, Schedule, DAYS, TIME_SLOTS, init_data


@pytest.fixture
def client():
    """Create a test client with a fresh database for each test."""
    db_fd, db_path = tempfile.mkstemp(suffix='.db')
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    app.config['SESSION_TYPE'] = 'filesystem'
    app.config['SESSION_FILE_DIR'] = tempfile.mkdtemp()
    app.config['LOGIN_DISABLED'] = False

    with app.app_context():
        db.drop_all()
        db.create_all()
        init_data()
        db.session.commit()

    with app.test_client() as client:
        yield client

    os.close(db_fd)
    os.unlink(db_path)


def login(client, username='admin', password='admin123'):
    """Helper to log in as admin."""
    return client.post('/login', data={
        'username': username,
        'password': password,
    }, follow_redirects=True)


# ─── Model Tests ─────────────────────────────────────────────────────────────

class TestModels:
    def test_user_password_hashing(self, client):
        with app.app_context():
            user = User.query.filter_by(username='admin').first()
            assert user is not None
            assert user.check_password('admin123')
            assert not user.check_password('wrongpassword')

    def test_teacher_model_fields(self, client):
        with app.app_context():
            teacher = Teacher.query.first()
            assert teacher is not None
            assert teacher.name is not None
            assert teacher.department is not None
            assert hasattr(teacher, 'email')
            assert hasattr(teacher, 'phone')

    def test_schedule_model_fields(self, client):
        with app.app_context():
            schedule = Schedule.query.filter_by(status='Engaged').first()
            assert schedule is not None
            assert schedule.day in DAYS
            assert schedule.time_slot in TIME_SLOTS
            assert schedule.subject is not None
            assert schedule.room_number is not None

    def test_teacher_schedule_relationship(self, client):
        with app.app_context():
            teacher = Teacher.query.first()
            assert len(teacher.schedules) == len(DAYS) * len(TIME_SLOTS)

    def test_init_data_creates_teachers(self, client):
        with app.app_context():
            assert Teacher.query.count() == 8

    def test_init_data_creates_schedules(self, client):
        with app.app_context():
            assert Schedule.query.count() == 8 * len(DAYS) * len(TIME_SLOTS)


# ─── Auth Tests ──────────────────────────────────────────────────────────────

class TestAuth:
    def test_login_page_loads(self, client):
        resp = client.get('/login')
        assert resp.status_code == 200
        assert b'Login' in resp.data

    def test_register_page_loads(self, client):
        resp = client.get('/register')
        assert resp.status_code == 200
        assert b'Register' in resp.data

    def test_login_success(self, client):
        resp = login(client)
        assert resp.status_code == 200
        assert b'Login successful' in resp.data

    def test_login_wrong_password(self, client):
        resp = client.post('/login', data={
            'username': 'admin',
            'password': 'wrong',
        }, follow_redirects=True)
        assert b'Incorrect password' in resp.data

    def test_login_nonexistent_user(self, client):
        resp = client.post('/login', data={
            'username': 'nonexistent',
            'password': 'admin123',
        }, follow_redirects=True)
        assert b'does not exist' in resp.data

    def test_register_new_user(self, client):
        resp = client.post('/register', data={
            'username': 'testuser',
            'email': 'test@example.com',
            'password': 'test123',
            'confirm_password': 'test123',
        }, follow_redirects=True)
        assert b'Registration successful' in resp.data

    def test_register_password_mismatch(self, client):
        resp = client.post('/register', data={
            'username': 'testuser',
            'email': 'test@example.com',
            'password': 'test123',
            'confirm_password': 'different',
        }, follow_redirects=True)
        assert b'Passwords do not match' in resp.data

    def test_register_short_password(self, client):
        resp = client.post('/register', data={
            'username': 'testuser',
            'email': 'test@example.com',
            'password': 'ab',
            'confirm_password': 'ab',
        }, follow_redirects=True)
        assert b'at least 6 characters' in resp.data

    def test_logout(self, client):
        login(client)
        resp = client.get('/logout', follow_redirects=True)
        assert b'logged out' in resp.data

    def test_unauthenticated_redirect(self, client):
        resp = client.get('/dashboard')
        assert resp.status_code == 302


# ─── Main Route Tests ────────────────────────────────────────────────────────

class TestMainRoutes:
    def test_index_page(self, client):
        login(client)
        resp = client.get('/')
        assert resp.status_code == 200
        assert b'Teachers' in resp.data

    def test_dashboard(self, client):
        login(client)
        resp = client.get('/dashboard')
        assert resp.status_code == 200
        assert b'Dashboard' in resp.data
        assert b'Overall Utilization' in resp.data

    def test_timetable(self, client):
        login(client)
        resp = client.get('/timetable')
        assert resp.status_code == 200
        assert b'Weekly Timetable' in resp.data

    def test_free_teachers(self, client):
        login(client)
        resp = client.get('/free_teachers?day=Monday&time_slot=08:00+-+09:00')
        assert resp.status_code == 200
        assert b'Available Teachers' in resp.data

    def test_teacher_timetable(self, client):
        login(client)
        with app.app_context():
            teacher = Teacher.query.first()
            tid = teacher.id
        resp = client.get(f'/teacher/{tid}')
        assert resp.status_code == 200
        assert b'Weekly Schedule' in resp.data

    def test_teacher_timetable_404(self, client):
        login(client)
        resp = client.get('/teacher/99999')
        assert resp.status_code == 404


# ─── Admin Route Tests ───────────────────────────────────────────────────────

class TestAdminRoutes:
    def test_add_teacher(self, client):
        login(client)
        resp = client.post('/teacher/add', data={
            'name': 'New Teacher',
            'department': 'Mathematics',
            'email': 'new@example.com',
        }, follow_redirects=True)
        assert b'Teacher added successfully' in resp.data

        with app.app_context():
            teacher = Teacher.query.filter_by(name='New Teacher').first()
            assert teacher is not None
            assert teacher.department == 'Mathematics'
            assert len(teacher.schedules) == len(DAYS) * len(TIME_SLOTS)

    def test_add_duplicate_teacher(self, client):
        login(client)
        with app.app_context():
            existing = Teacher.query.first()
            name = existing.name
        resp = client.post('/teacher/add', data={
            'name': name,
        }, follow_redirects=True)
        assert b'already exists' in resp.data

    def test_edit_teacher(self, client):
        login(client)
        with app.app_context():
            teacher = Teacher.query.first()
            tid = teacher.id
        resp = client.post(f'/teacher/edit/{tid}', data={
            'name': 'Updated Name',
            'department': 'New Dept',
            'email': 'updated@example.com',
        }, follow_redirects=True)
        assert b'Teacher updated successfully' in resp.data

        with app.app_context():
            teacher = db.session.get(Teacher, tid)
            assert teacher.name == 'Updated Name'
            assert teacher.department == 'New Dept'

    def test_delete_teacher(self, client):
        login(client)
        with app.app_context():
            teacher = Teacher.query.first()
            tid = teacher.id
            initial_count = Teacher.query.count()

        resp = client.get(f'/teacher/delete/{tid}', follow_redirects=True)
        assert b'Teacher deleted successfully' in resp.data

        with app.app_context():
            assert Teacher.query.count() == initial_count - 1

    def test_edit_schedule(self, client):
        login(client)
        with app.app_context():
            teacher = Teacher.query.first()
            tid = teacher.id

        resp = client.post('/schedule/edit', data={
            'teacher_id': tid,
            'day': 'Wednesday',
            'time_slot': '02:00 - 03:00',
            'status': 'Engaged',
            'room_number': '301',
            'subject': 'Test Subject',
        }, follow_redirects=True)
        assert b'Schedule updated successfully' in resp.data

        with app.app_context():
            schedule = Schedule.query.filter_by(
                teacher_id=tid,
                day='Wednesday',
                time_slot='02:00 - 03:00'
            ).first()
            assert schedule.status == 'Engaged'
            assert schedule.room_number == '301'
            assert schedule.subject == 'Test Subject'

    def test_edit_schedule_free_clears_fields(self, client):
        login(client)
        with app.app_context():
            teacher = Teacher.query.first()
            tid = teacher.id

        # Set to Engaged first
        client.post('/schedule/edit', data={
            'teacher_id': tid,
            'day': 'Wednesday',
            'time_slot': '03:00 - 04:00',
            'status': 'Engaged',
            'room_number': '301',
            'subject': 'Test',
        })
        # Set back to Free
        client.post('/schedule/edit', data={
            'teacher_id': tid,
            'day': 'Wednesday',
            'time_slot': '03:00 - 04:00',
            'status': 'Free',
        }, follow_redirects=True)

        with app.app_context():
            schedule = Schedule.query.filter_by(
                teacher_id=tid,
                day='Wednesday',
                time_slot='03:00 - 04:00'
            ).first()
            assert schedule.status == 'Free'
            assert schedule.room_number is None
            assert schedule.subject is None

    def test_manage_users(self, client):
        login(client)
        resp = client.get('/users')
        assert resp.status_code == 200
        assert b'Manage Users' in resp.data


# ─── Export Tests ─────────────────────────────────────────────────────────────

class TestExport:
    def test_export_timetable(self, client):
        login(client)
        resp = client.get('/export/timetable')
        assert resp.status_code == 200
        assert 'spreadsheetml' in resp.content_type

    def test_export_teacher_timetable(self, client):
        login(client)
        with app.app_context():
            teacher = Teacher.query.first()
            tid = teacher.id
        resp = client.get(f'/export/teacher/{tid}')
        assert resp.status_code == 200
        assert 'spreadsheetml' in resp.content_type


# ─── API Tests ────────────────────────────────────────────────────────────────

class TestAPI:
    def test_get_schedule_api(self, client):
        login(client)
        with app.app_context():
            teacher = Teacher.query.filter_by(name='Ashish Mishra').first()
            tid = teacher.id

        resp = client.get(f'/api/schedule/{tid}/Monday/08:00 - 09:00')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['status'] == 'Engaged'
        assert data['room_number'] == '201'
        assert data['subject'] == 'Data Structures'

    def test_room_conflict_api(self, client):
        login(client)
        resp = client.get('/api/room_conflict/201/Monday/08:00 - 09:00')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['has_conflict'] is True
        assert len(data['booked_by']) > 0

    def test_no_room_conflict_api(self, client):
        login(client)
        resp = client.get('/api/room_conflict/999/Monday/08:00 - 09:00')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['has_conflict'] is False


# ─── Profile Tests ────────────────────────────────────────────────────────────

class TestProfile:
    def test_profile_page(self, client):
        login(client)
        resp = client.get('/profile')
        assert resp.status_code == 200
        assert b'Profile' in resp.data

    def test_edit_profile_page(self, client):
        login(client)
        resp = client.get('/profile/edit')
        assert resp.status_code == 200
        assert b'Edit Profile' in resp.data
