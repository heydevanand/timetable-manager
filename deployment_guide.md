# Deployment Guide for Flask Timetable Application

This guide provides instructions for deploying the Flask Timetable application to various hosting environments.

## Prerequisites

- Python 3.9+ installed on your production server
- pip for installing dependencies
- Git for version control (optional)

## Deployment Options

### 1. Deploying to Heroku

1. Create a Heroku account and install the Heroku CLI
2. Login to Heroku and create a new app:
   ```
   heroku login
   heroku create your-timetable-app
   ```
3. Set environment variables:
   ```
   heroku config:set FLASK_ENV=production
   heroku config:set SECRET_KEY=$(python -c "import os; print(os.urandom(24).hex())")
   ```
4. Deploy your application:
   ```
   git add .
   git commit -m "Prepare for deployment"
   git push heroku main
   ```
5. Initialize the database:
   ```
   heroku run python
   ```
   Then in the Python console:
   ```python
   from app import app, db
   with app.app_context():
       db.create_all()
   ```
6. Open your application:
   ```
   heroku open
   ```

### 2. Deploying to PythonAnywhere

1. Sign up for a PythonAnywhere account
2. Upload your code or clone from GitHub
3. Set up a virtual environment and install requirements:
   ```
   mkvirtualenv --python=/usr/bin/python3.9 timetable-env
   pip install -r requirements.txt
   ```
4. Set up a Web app with Flask
5. Set the WSGI configuration file to point to wsgi.py
6. Set environment variables in the WSGI configuration file
7. Initialize the database using the PythonAnywhere console

### 3. Deploying to a VPS/Dedicated Server with Nginx and Gunicorn

1. Set up your server and install required packages:
   ```
   sudo apt update
   sudo apt install python3-pip python3-dev nginx
   ```

2. Create a virtual environment:
   ```
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   pip install gunicorn
   ```

3. Set environment variables:
   ```
   export FLASK_ENV=production
   export SECRET_KEY=your_secure_secret_key
   ```

4. Test Gunicorn:
   ```
   gunicorn --bind 0.0.0.0:5000 wsgi:app
   ```

5. Create a systemd service file:
   ```
   sudo nano /etc/systemd/system/timetable.service
   ```
   
   Add the following content:
   ```
   [Unit]
   Description=Gunicorn instance to serve timetable application
   After=network.target

   [Service]
   User=your_username
   Group=www-data
   WorkingDirectory=/path/to/flask-timetable
   Environment="PATH=/path/to/flask-timetable/venv/bin"
   Environment="FLASK_ENV=production"
   Environment="SECRET_KEY=your_secure_secret_key"
   ExecStart=/path/to/flask-timetable/venv/bin/gunicorn --workers 3 --bind unix:timetable.sock -m 007 wsgi:app

   [Install]
   WantedBy=multi-user.target
   ```

6. Start and enable the service:
   ```
   sudo systemctl start timetable
   sudo systemctl enable timetable
   ```

7. Configure Nginx:
   ```
   sudo nano /etc/nginx/sites-available/timetable
   ```
   
   Add the following content:
   ```
   server {
       listen 80;
       server_name your_domain.com www.your_domain.com;

       location / {
           include proxy_params;
           proxy_pass http://unix:/path/to/flask-timetable/timetable.sock;
       }
   }
   ```

8. Enable the site and restart Nginx:
   ```
   sudo ln -s /etc/nginx/sites-available/timetable /etc/nginx/sites-enabled
   sudo systemctl restart nginx
   ```

9. Set up SSL with Let's Encrypt (optional but recommended):
   ```
   sudo apt install certbot python3-certbot-nginx
   sudo certbot --nginx -d your_domain.com -d www.your_domain.com
   ```

## Production Security Considerations

1. Always use a strong SECRET_KEY
2. Keep DEBUG=False in production
3. Use HTTPS in production
4. Regularly update dependencies to patch vulnerabilities
5. Use a production-ready database like PostgreSQL instead of SQLite
6. Set up proper logging
7. Configure firewalls and keep server updated
8. Set up regular backups of your database
