import os
import json
import hashlib
import datetime
import mimetypes

from flask import Flask, render_template, redirect, url_for, flash, request, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, 
    login_user, 
    logout_user, 
    login_required, 
    current_user, 
    UserMixin
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from PIL import Image, ExifTags

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB limit

# Create the uploads folder if it doesn't exist
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Setup database and login manager
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # If not logged in, user is redirected to /login

# -----------------------------
# Database Models
# -----------------------------
class User(db.Model, UserMixin):
    """User model for authentication."""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    images = db.relationship('ImageAnalysis', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class ImageAnalysis(db.Model):
    """Model to store uploaded image data and extracted metadata."""
    id = db.Column(db.Integer, primary_key=True)
    file_name = db.Column(db.String(300), nullable=False)
    upload_time = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    # 'metadata' is a reserved keyword in SQLAlchemy, so we use 'meta_data'
    meta_data = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# -----------------------------
# Helper Function: Metadata Extraction
# -----------------------------
def extract_metadata(file_path, filename):
    """Extracts metadata from the uploaded image using Pillow and other libraries."""
    metadata = {}

    # Calculate MD5 checksum
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    metadata['checksum'] = hash_md5.hexdigest()

    # Basic file details
    metadata['file_name'] = filename
    file_size = os.path.getsize(file_path)
    metadata['file_size'] = f"{file_size} bytes"
    file_ext = os.path.splitext(filename)[1].lower().replace('.', '')
    metadata['file_type_extension'] = file_ext
    mime_type, _ = mimetypes.guess_type(filename)
    metadata['mime_type'] = mime_type if mime_type else 'unknown'

    # Attempt to open the file as an image
    try:
        img = Image.open(file_path)
        width, height = img.size
        metadata['image_width'] = width
        metadata['image_height'] = height
        metadata['image_size'] = f"{width}x{height}"
        metadata['megapixels'] = round((width * height) / 1e6, 1)
        metadata['color_type'] = img.mode

        # Bit depth (may not be available in all images)
        metadata['bit_depth'] = img.info.get('bits', 'Not available')

        # Additional PNG info if the file is a PNG
        if file_ext.lower() == 'png':
            metadata['compression'] = img.info.get('compression', 'Not available')
            metadata['filter'] = img.info.get('filter', 'Not available')
            metadata['interlace'] = img.info.get('interlace', 'Not available')
            metadata['srgb_rendering'] = img.info.get('srgb', 'Not available')
            metadata['gamma'] = img.info.get('gamma', 'Not available')

        # EXIF data (mostly available in JPEGs)
        try:
            exif_data = img._getexif()
            if exif_data:
                exif = {}
                for tag, value in exif_data.items():
                    decoded = ExifTags.TAGS.get(tag, tag)
                    exif[decoded] = value
                metadata['exif'] = exif
        except Exception:
            metadata['exif'] = {}

    except Exception as e:
        metadata['error'] = f"Error processing image: {str(e)}"

    # Read raw header bytes (first 30 bytes) in hexadecimal format
    with open(file_path, 'rb') as f:
        raw = f.read(30)
    metadata['raw_header'] = ' '.join([f"{b:02X}" for b in raw])

    # Category
    metadata['category'] = 'image'
    return metadata

# -----------------------------
# Routes
# -----------------------------
@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration route."""
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        
        # Check if user already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose another one.')
            return redirect(url_for('register'))
        
        # Create new user
        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please log in.')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login route."""
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            flash('Logged in successfully.')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password. Please try again.')
            return redirect(url_for('login'))
    
    # GET request: simply render the login page
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    """User logout route."""
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('login'))

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    """Main dashboard where users can upload images and view metadata."""
    metadata = None

    # Handle file upload
    if request.method == 'POST':
        if 'image' not in request.files:
            flash('No file part in the request.')
            return redirect(request.url)
        
        file = request.files['image']
        if file.filename == '':
            flash('No file selected for uploading.')
            return redirect(request.url)
        
        if file:
            # Save the file
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

            # Extract metadata
            metadata = extract_metadata(file_path, filename)

            # Store record in database
            analysis = ImageAnalysis(
                file_name=filename,
                meta_data=json.dumps(metadata, indent=2),
                user_id=current_user.id
            )
            db.session.add(analysis)
            db.session.commit()
            
            flash('Image uploaded and metadata extracted successfully.')
    
    # Implement pagination for history logs
    page = request.args.get('page', 1, type=int)
    per_page = 5  # Adjust this as desired
    pagination = ImageAnalysis.query.filter_by(user_id=current_user.id)\
        .order_by(ImageAnalysis.upload_time.desc())\
        .paginate(page=page, per_page=per_page)

    images = pagination.items

    return render_template('dashboard.html', 
                           metadata=metadata, 
                           images=images, 
                           pagination=pagination)

@app.route('/download/<int:analysis_id>')
@login_required
def download_json(analysis_id):
    """
    Route to download the metadata analysis as a JSON file.
    Ensures the requested analysis belongs to the current user.
    """
    analysis = ImageAnalysis.query.get_or_404(analysis_id)

    # Authorization check
    if analysis.user_id != current_user.id:
        flash('You are not authorized to download this file.')
        return redirect(url_for('dashboard'))
    
    # Create JSON response
    meta_dict = json.loads(analysis.meta_data)
    response = make_response(json.dumps(meta_dict, indent=2))
    response.headers['Content-Type'] = 'application/json'
    # Force download with a .json filename
    response.headers['Content-Disposition'] = f'attachment; filename={analysis.file_name}.json'
    return response

# -----------------------------
# Main Entry
# -----------------------------
if __name__ == '__main__':
    # Create tables if they don't exist
    with app.app_context():
        db.create_all()
    app.run(debug=True)
