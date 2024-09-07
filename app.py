from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
from sqlalchemy.exc import IntegrityError
from models import db, User, Place, SavedPlace

app = Flask(__name__)
app.config.from_object('config.Config')

db.init_app(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/restaurants')
def restaurants():
    restaurants = [
        {
            "name": "Ресторан Helga",
            "reviews": "430 отзывов",
            "status": "Открыто",
            "cuisine": "Европейская, Гриль",
            "price_range": "$$ - $$$",
            "description": "Рекомендуем. Всё было очень вкусно. Красивая и быстрая подача. Лучшее место для гурманов в Пскове.",
            "image": "https://dynamic-media-cdn.tripadvisor.com/media/photo-o/16/96/87/a4/helga.jpg?w=600&h=-1&s=1"
        },
        {
            "name": "Рестораны и кафе 'Двор Подзноева'",
            "reviews": "678 отзывов",
            "status": "Открыто",
            "cuisine": "Европейская, Русская",
            "price_range": "$$ - $$$",
            "description": "Самый лучший из провинциальных ресторанов. Лучше, чем ожидали",
            "image": "https://dynamic-media-cdn.tripadvisor.com/media/photo-o/10/6b/18/0f/caption.jpg?w=600&h=-1&s=1"
        },
        {
            "name": "Mojo GastroBar",
            "reviews": "376 отзывов",
            "status": "Открыто",
            "cuisine": "Современная, Здоровая",
            "price_range": "$$ - $$$",
            "description": "Восторг! Пожалуй лучшее заведение",
            "image": "https://dynamic-media-cdn.tripadvisor.com/media/photo-o/1a/c2/91/74/caption.jpg?w=600&h=-1&s=1"
        },
        {
            "name": "Ресто-Бар Моя История",
            "reviews": "136 отзывов",
            "status": "Открыто",
            "cuisine": "Европейская, Азиатская",
            "price_range": "$$ - $$$",
            "description": "Долго, но вкусно. Первый визит. На 4+",
            "image": "https://dynamic-media-cdn.tripadvisor.com/media/photo-o/1a/c2/91/74/caption.jpg?w=600&h=-1&s=1"
        },
        {
            "name": "Трапезные палаты",
            "reviews": "271 отзыв",
            "status": "Открыто",
            "cuisine": "Европейская, Русская",
            "price_range": "$$ - $$$",
            "description": "Ел с удовольствием, счет изучал без удовольствия. Достойно, красиво и очень вкусно!",
            "image": "https://dynamic-media-cdn.tripadvisor.com/media/photo-o/17/9f/29/cb/interior.jpg?w=600&h=400&s=1"
        },
        {
            "name": "Кафе 'Пироговые палаты' Двора Подзноева",
            "reviews": "190 отзывов",
            "status": "Открыто",
            "cuisine": "Кафе, Русская",
            "price_range": "$",
            "description": "Настоящие вкусные пироги. На любой вкус и фантазию",
            "image": "https://dynamic-media-cdn.tripadvisor.com/media/photo-o/10/77/eb/06/caption.jpg?w=600&h=-1&s=1"
        },
        {
            "name": "Ресторан 'Покровский'",
            "reviews": "61 отзыв",
            "status": "Открыто",
            "cuisine": "Европейская, Азиатская",
            "price_range": "$$ - $$$",
            "description": "Достойный ресторан. Идеально!!! Давно не встречала такого качества!",
            "image": "https://dynamic-media-cdn.tripadvisor.com/media/photo-o/12/e8/0b/68/caption.jpg?w=600&h=-1&s=1"
        },
        {
            "name": "Пивной Бар 903",
            "reviews": "61 отзыв",
            "status": "Открыто",
            "cuisine": "Европейская",
            "price_range": "$$ - $$$",
            "description": "Уютное место возле Кремля. Приятный вечер",
            "image": "https://dynamic-media-cdn.tripadvisor.com/media/photo-o/1c/66/91/a9/img-20201205-123921-1.jpg?w=600&h=400&s=1"
        }
    ]
    return render_template('restaurants.html', restaurants=restaurants)

@app.route('/attractions')
def attractions():
    places = Place.query.all()
    return render_template('attractions.html', places=places)

@app.route('/places')
def places():
    places = Place.query.all()
    return render_template('places.html', places=places)

@app.route('/hotels')
def hotels():
    places = Place.query.all()
    return render_template('hotels.html', places=places)

@app.route('/events')
def events():
    places = Place.query.all()
    return render_template('events.html', places=places)

@app.route('/nature')
def nature():
    places = Place.query.all()
    return render_template('nature.html', places=places)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if User.query.filter_by(username=username).first():
            flash('Username already exists. Please choose a different username.', 'danger')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        user = User(username=username, password=hashed_password)
        try:
            db.session.add(user)
            db.session.commit()
            login_user(user)
            flash('Registration successful. You are now logged in.', 'success')
            return redirect(url_for('index'))
        except IntegrityError:
            db.session.rollback()
            flash('Registration failed. Please try again.', 'danger')

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Authentication successful! Enjoy your time exploring places!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Login failed. Check your username and/or password.', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/save/<int:place_id>', methods=['POST'])
@login_required
def save_place(place_id):
    if not SavedPlace.query.filter_by(user_id=current_user.id, place_id=place_id).first():
        saved_place = SavedPlace(user_id=current_user.id, place_id=place_id)
        db.session.add(saved_place)
        db.session.commit()
        flash('Place saved to your profile.', 'success')
    else:
        flash('Place is already saved.', 'info')
    return redirect(request.referrer)

@app.route('/profile')
@login_required
def profile():
    saved_places = SavedPlace.query.filter_by(user_id=current_user.id).all()
    return render_template('profile.html', saved_places=saved_places)

if __name__ == '__main__':
    app.run(debug=True)
