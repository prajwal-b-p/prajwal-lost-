import os
from flask import Flask, render_template, url_for, flash, redirect, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, current_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import secrets
import string

# Import our models and forms
from models import db, User, Item, Category, Match, Report
from forms import RegistrationForm, LoginForm, ItemForm, ReportForm, ClaimForm

app = Flask(__name__)
# Git sync check
app.config['SECRET_KEY'] = 'your_secret_key_here' # Keep this safe!
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site_v3.db'
app.config['UPLOAD_FOLDER'] = 'static/uploads'

db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# --- HELPER FUNCTIONS ---
def save_picture(form_picture):
    """Saves uploaded image to static/uploads"""
    if not form_picture:
        return None
    filename = secure_filename(form_picture.filename)
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    final_name = f"{timestamp}_{filename}"
    picture_path = os.path.join(app.root_path, app.config['UPLOAD_FOLDER'], final_name)
    form_picture.save(picture_path)
    return final_name

import base64
def save_base64_picture(data_url):
    """Saves a base64 camera capture to static/uploads"""
    if not data_url or ',' not in data_url:
        return None
    header, encoded = data_url.split(',', 1)
    ext = 'png'
    if 'jpeg' in header:
        ext = 'jpg'
    img_data = base64.b64decode(encoded)
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    final_name = f"{timestamp}_camera.{ext}"
    picture_path = os.path.join(app.root_path, app.config['UPLOAD_FOLDER'], final_name)
    with open(picture_path, 'wb') as f:
        f.write(img_data)
    return final_name

def find_matches(new_item):
    """Logic ported from Django utils.py"""
    target_type = 'FOUND' if new_item.type == 'LOST' else 'LOST'
    
    # Get candidates from DB
    potential_matches = Item.query.filter(Item.type == target_type, Item.status == 'OPEN', Item.category_id == new_item.category_id).all()
    
    new_keywords = set(new_item.title.lower().split()) | set(new_item.description.lower().split()) | set(new_item.location.lower().split())

    for potential in potential_matches:
        pot_keywords = set(potential.title.lower().split()) | set(potential.description.lower().split()) | set(potential.location.lower().split())
        
        common = new_keywords.intersection(pot_keywords)
        if len(common) > 0:
            score = len(common) * 10
            # Save Match
            match = Match(score=score, lost_item_id=new_item.id if new_item.type == 'LOST' else potential.id,
                          found_item_id=potential.id if new_item.type == 'LOST' else new_item.id)
            db.session.add(match)
    db.session.commit()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- ROUTES ---

@app.route("/")
@app.route("/home")
def home():
    # Show recent OPEN items
    items = Item.query.filter_by(status='OPEN').order_by(Item.created_at.desc()).limit(6).all()
    return render_template('home.html', items=items)

@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_pw = generate_password_hash(form.password.data)
        user = User(username=form.username.data, email=form.email.data, password=hashed_pw)
        db.session.add(user)
        db.session.commit()
        flash('Account created! You can now login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route("/post", methods=['GET', 'POST'])
@login_required
def post_item():
    form = ItemForm()
    # Populate categories dynamically
    form.category.choices = [(c.id, c.name) for c in Category.query.all()]
    
    if form.validate_on_submit():
        # Handle image: prefer camera capture, fall back to file upload
        camera_data = request.form.get('camera_image')
        if camera_data:
            pic_file = save_base64_picture(camera_data)
        else:
            pic_file = save_picture(form.image.data)

        item = Item(title=form.title.data, type=form.type.data, description=form.description.data,
                    location=form.location.data, date_occurred=form.date_occurred.data,
                    user_id=current_user.id, category_id=form.category.data, image_file=pic_file)
        
        # Generate verification code ONLY for LOST items
        if form.type.data == 'LOST':
            alphabet = string.ascii_uppercase + string.digits
            code = ''.join(secrets.choice(alphabet) for i in range(8))
            item.verification_code = code
        else:
            item.verification_code = None

        db.session.add(item)
        db.session.commit()
        
        flash('Item posted successfully!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('post_item.html', title='Post Item', form=form)

@app.route("/dashboard")
@login_required
def dashboard():
    user_items = Item.query.filter_by(user_id=current_user.id).order_by(Item.created_at.desc()).all()
    # Matches would be queried here similarly to Django
    return render_template('dashboard.html', items=user_items)

@app.route("/item/<int:item_id>")
def item_detail(item_id):
    item = Item.query.get_or_404(item_id)
    return render_template('item_detail.html', item=item)

@app.route("/search")
def search():
    query = request.args.get('q')
    items = Item.query.filter(
        (Item.title.contains(query)) | (Item.description.contains(query))
    ).all() if query else []
    return render_template('home.html', items=items, title="Search Results")

@app.route("/report/<int:item_id>", methods=['GET', 'POST'])
@login_required
def report_item(item_id):
    item = Item.query.get_or_404(item_id)
    form = ReportForm()
    if form.validate_on_submit():
        report = Report(reason=form.reason.data, item_id=item.id, reporter_id=current_user.id)
        db.session.add(report)
        db.session.commit()
        flash('Report submitted for review', 'success')
        return redirect(url_for('item_detail', item_id=item.id))
    return render_template('report_item.html', title='Report Item', form=form, item=item)

@app.route("/claim/<int:item_id>", methods=['GET', 'POST'])
@login_required
def claim_item(item_id):
    """Claim a FOUND item by providing the matching LOST item's verification code."""
    found_item = Item.query.get_or_404(item_id)
    if found_item.type != 'FOUND' or found_item.status != 'OPEN':
        flash('This item cannot be claimed.', 'warning')
        return redirect(url_for('item_detail', item_id=item_id))
    
    form = ClaimForm()
    if form.validate_on_submit():
        code = form.verification_code.data.strip().upper()
        lost_item = Item.query.filter_by(verification_code=code, type='LOST', status='OPEN').first()
        if lost_item:
            lost_item.status = 'CLAIMED'
            found_item.status = 'CLAIMED'
            db.session.commit()
            flash('Item claimed successfully! Both items are now marked as CLAIMED.', 'success')
            return redirect(url_for('item_detail', item_id=item_id))
        else:
            flash('Invalid verification code. No matching LOST item found.', 'danger')
    return render_template('claim_item.html', title='Claim Item', form=form, item=found_item)

# --- APP START ---
if __name__ == '__main__':
    with app.app_context():
        db.create_all() # Creates SQLite file
        # Create some default categories if they don't exist
        if not Category.query.first():
            db.session.add(Category(name='Electronics'))
            db.session.add(Category(name='Clothing'))
            db.session.add(Category(name='Keys'))
            db.session.commit()
    app.run(debug=True)