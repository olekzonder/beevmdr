from flask import Flask, render_template, request
from flask_sqlalchemy import SQLAlchemy
import random
from datetime import datetime
#import request

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///testdb.db'  # или ваша строка подключения
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

    #id = db.Column(db.Integer, primary_key=True)
    #username = db.Column(db.String(80), unique=True, nullable=False)
    #email = db.Column(db.String(120), unique=True, nullable=False)


class EndpointsHostinfo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    computer_name = db.Column(db.String(50), nullable=False)
    os_name = db.Column(db.String(50), nullable=False)
    last_user = db.Column(db.String(50), nullable=False)
    ip_address = db.Column(db.String(20), nullable=False)
    mac_address = db.Column(db.String(20), nullable=False)
    last_update = db.Column(db.DateTime, nullable=False)
    protection_status = db.Column(db.String(10), nullable=False)
    vulnerable_software_percent = db.Column(db.Integer, nullable=False)

    def __repr__(self):
        return f'<Endpoint {self.computer_name}>'

def generate_mac():
    return ":".join([f"{random.randint(0x00, 0xff):02x}" for _ in range(6)])

def create_sample_data():
    with app.app_context():
        db.create_all()
        
        # Очищаем таблицу если она уже существует
        db.session.query(EndpointsHostinfo).delete()
        
        # Создаем 15 записей
        for i in range(1, 16):
            record = EndpointsHostinfo(
                computer_name=f"ARM-F-{i:04d}",
                os_name="Linux",
                last_user=f"user{i:03d}",
                ip_address=f"10.10.10.{i}",
                mac_address=generate_mac(),
                last_update=datetime.now(),
                protection_status="On",
                vulnerable_software_percent=random.randint(0, 30)
            )
            db.session.add(record)
        
        db.session.commit()
        print("Добавлено 15 записей в таблицу endpoints_hostinfo")

@app.route('/dashboard')
def show_dashboard():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    endpoints = EndpointsHostinfo.query.order_by(EndpointsHostinfo.id).paginate(page=page, per_page=per_page, error_out=False)
    return render_template('dashboard.html', endpoints=endpoints)

@app.route('/endpoints')
def show_endpoints():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    endpoints = EndpointsHostinfo.query.order_by(EndpointsHostinfo.id).paginate(page=page, per_page=per_page, error_out=False)
    return render_template('endpoints.html', endpoints=endpoints)

@app.route('/')
def index():
    try:
        page = request.args.get('page', 1, type=int)
        if page < 1:
            page = 1
    except ValueError:
        page = 1
    
    per_page = 10
    endpoints = EndpointsHostinfo.query.paginate(page=page, per_page=per_page)
    return render_template('endpoints.html', endpoints=endpoints)


if __name__ == '__main__':
    create_sample_data()
    #print('DB created successfully!')
    app.run(debug=True)