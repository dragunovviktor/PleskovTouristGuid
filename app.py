from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
from sqlalchemy.exc import IntegrityError
from models import db, User, Place, SavedPlace, SavedRestaurant

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
    places = Place.query.all()
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


@app.route('/save_restaurant', methods=['POST'])
@login_required
def save_restaurant():
    data = request.get_json()
    restaurant_name = data.get('restaurant_name')

    # Валидация формы: проверка, не пустые ли поля
    if not restaurant_name:
        flash('Пожалуйста, введите название ресторана.')
        return redirect(url_for('restaurants'))

    # Проверка, не сохранен ли уже ресторан
    existing_restaurant = SavedRestaurant.query.filter_by(user_id=current_user.id,
                                                          restaurant_name=restaurant_name).first()
    if existing_restaurant:
        flash('Этот ресторан уже сохранен.')
        return redirect(url_for('restaurants'))

    # Создание новой записи
    new_restaurant = SavedRestaurant(user_id=current_user.id, restaurant_name=restaurant_name)
    db.session.add(new_restaurant)
    db.session.commit()

    flash('Ресторан успешно сохранен!')
    return redirect(url_for('restaurants'))

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
    saved_places = SavedPlace.query.filter_by(user_id=current_user.id).all()  # Добавьте этот код
    saved_restaurants = SavedRestaurant.query.filter_by(user_id=current_user.id).all()  # Добавьте этот код
    return render_template('profile.html', saved_places=saved_places, saved_restaurants=saved_restaurants)

if __name__ == '__main__':
    app.run(debug=True)
