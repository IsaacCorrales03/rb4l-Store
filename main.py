from flask import Flask, render_template, jsonify, request, redirect, url_for, session
from flask_mysqldb import MySQL
import MySQLdb.cursors
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import os
import re
import email_validator
from functools import wraps

# Cargar variables de entorno
load_dotenv()

app = Flask(__name__)  
app.secret_key = 'clave_super_secreta'

# Configuración clave de sesión (debe ser fija para evitar que se pierda)
app.secret_key = os.getenv('SECRET_KEY', 'clave_secreta_por_defecto')

# Configuración de MySQL
app.config['MYSQL_HOST'] = os.getenv('host')
app.config['MYSQL_USER'] = os.getenv('user')
app.config['MYSQL_PASSWORD'] = os.getenv('password')
app.config['MYSQL_DB'] = os.getenv('db')
app.config['MYSQL_PORT'] = int(os.getenv('port'))

mysql = MySQL(app)

# Validaciones
def validate_email(email):
    try:
        valid = email_validator.validate_email(email)
        return valid.email
    except email_validator.EmailNotValidError:
        return None

def validate_password(password):
    return (
        8 <= len(password) <= 32 and
        re.search(r'[A-Z]', password) and
        re.search(r'[a-z]', password) and
        re.search(r'\d', password)
    )

def validate_username(username):
    return 3 <= len(username) <= 20 and re.match(r'^[a-zA-Z0-9_]+$', username)

def validate_nametag(nametag):
    return 3 <= len(nametag) <= 16 and re.match(r'^[a-zA-Z0-9_]+$', nametag)

# Decorador de sesión
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if not username or not password:
            return render_template('login.html', error="Both username and password are required")
        
        cur = mysql.connection.cursor()
        try:
            cur.execute("SELECT ID, UserName, Password FROM Usuarios WHERE UserName = %s", (username,))
            user = cur.fetchone()
            
            if user and check_password_hash(user[2], password):
                session['user_id'] = user[0]
                session['username'] = user[1]
                return redirect(url_for('dashboard'))
            
            return render_template('login.html', error="Invalid credentials")
            
        except Exception as e:
            app.logger.error(f"Login error: {e}")
            return render_template('login.html', error="An error occurred during login")
        finally:
            cur.close()
            
    return render_template('login.html')

@app.route('/store')
def store():
    return render_template('store.html',checkout_base_url='/checkout/')

@app.route('/dashboard')
@login_required
def dashboard():
    cur = mysql.connection.cursor()
    try:
        cur.execute("""
            SELECT UserName, Correo, Nametag, Points, Streak 
            FROM Usuarios 
            WHERE ID = %s
        """, (session['user_id'],))
        
        user_data = cur.fetchone()
        if not user_data:
            session.clear()
            return redirect(url_for('login'))
            
        return render_template('dashboard.html', 
                             user={
                                 'username': user_data[0],
                                 'email': user_data[1],
                                 'nametag': user_data[2],
                                 'streak': user_data[4],
                                 'points':user_data[3]
                             })
                             
    except Exception as e:
        app.logger.error(f"Dashboard error: {e}")
        return redirect(url_for('login'))
    finally:
        cur.close()

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        print("Se recibió una solicitud de registro")
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        nametag = request.form.get('nametag', '').strip()
        
        # Validate input
        errors = []
        
        if not validate_username(username):
            errors.append("El nombre de usuario debe tener entre 3 y 20 caracteres y solo puede contener letras, números y guiones bajos (_). No se permiten espacios ni caracteres especiales.")
            
        if not validate_email(email):
            errors.append("Dirección de correo electrónico no válida")
            
        if not validate_password(password):
            errors.append("La contraseña debe tener 8-32 caracteres y contener al menos una letra mayúscula, una letra minúscula y un número")
            
        if password != confirm_password:
            errors.append("Las contraseñas no coinciden")
            
        if not validate_nametag(nametag):
            errors.append("El nombre debe tener entre 3 y 16 caracteres y solo puede contener letras, números y guiones bajos (_). No se permiten espacios ni caracteres especiales.")
        
        if errors:
            return render_template('register.html', errors=errors)
        print(errors)
        # Check if username or email already exists
        cur = mysql.connection.cursor()
        try:
            cur.execute("SELECT ID FROM Usuarios WHERE UserName = %s OR Correo = %s", (username, email))
            if cur.fetchone():
                return render_template('register.html',      
                                     errors=["Nombre de usuario o correo ya está en uso"])

            # Create new user
            hashed_password = generate_password_hash(password)
            cur.execute("""
                INSERT INTO Usuarios (UserName, Correo, Password, Nametag) 
                VALUES (%s, %s, %s, %s)
            """, (username, email, hashed_password, nametag))
            mysql.connection.commit()

            
            # Log in the new user
            cur.execute("SELECT ID FROM Usuarios WHERE UserName = %s", (username,))
            user_id = cur.fetchone()[0]
            
            session['user_id'] = user_id
            session['username'] = username
            
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            app.logger.error(f"Registration error: {e}")
            return render_template('register.html', 
                                 errors=["An error occurred during registration"])
        finally:
            cur.close()
    
    return render_template('register.html')


@app.route('/checkout/<int:id>')
@login_required
def checkout(id):
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute(f'SELECT * FROM Productos WHERE Id = {id}')
    producto = cur.fetchone()
    print(producto)
    return render_template('checkout.html', product=producto)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/products')
def get_products():
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM Productos") 
    products = cur.fetchall()
    cur.close()
    return jsonify(products)

if __name__ == '__main__':
    app.run(port=8080, debug=True)
