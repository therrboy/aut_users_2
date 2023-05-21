from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from wtforms import Form, StringField, PasswordField, validators

app = Flask(__name__)

app.config['SECRET_KEY'] = 'any-secret-key-you-choose'  # Clave secreta de la aplicacion, protege cookies y datos sensibles.
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'  # Configura la URL de la base de datos.
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Desactiva el seguimiento de modificaciones en SQL Alchemy, mejorando el rendimiento de la app
db = SQLAlchemy(app)

login_manager = LoginManager(
    app)  # Crea una instancia de LoginManager y la asigna a su variable. Gestiona la autenticacion de usuarios.


@login_manager.user_loader  # Decorador que registra la funcion "load_user" como la funcion que de carga de usuarios. Recibe como argumento el "user_id"
def load_user(user_id):
    return User.query.get(int(user_id))  # Se carga el usuario de la base de datos


##CREATE TABLE IN DB
class User(UserMixin, db.Model):  # Define la clase User, representa el modelo de datos de los usuarios en la base de datos. Hereda de UserMixin y db.Model.
    #  UserMixin proporciona implementaciones predeterminadas para metodos de autenticacion de usuarios.
    #   db.Model indica que la clase se mapeara a una tabla en la base de datos usando SQL Alchemy

    # A partir de aqui se definen las propiedades de la clase User, que corresponden a las columnas de la tabla de la base de datos.
    id = db.Column(db.Integer, primary_key=True)  # db.column define la propiedad
    name = db.Column(db.String(1000))
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))

    def __init__(self, name, email, password):  # El metodo __init__ se define para inicializar las propiedades de la clase User, para las nuevas instancias
        #  Toma los valores de aqui abajo (las nuevas instancias son nuevos usuarios)
        self.name = name
        self.email = email
        self.password = password


@app.route('/')
def home():
    return render_template("index.html")


@app.route('/register', methods=["GET", "POST"])  #
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            flash('Ese correo electronico ya existe, si es tuyo ingresa.')
            return redirect(url_for('login'))
        else:
            password = request.form.get('password')
            if len(password) < 8:  # Restricción de longitud mínima del password
                flash('El password debe tener al menos 8 caracteres.')
                return redirect(url_for('register'))

            hash_and_salted_password = generate_password_hash(  # Generamos un hash y sal para la contraseña con "generate_password_hash"
                request.form.get('password'),
                method='pbkdf2:sha256',
                salt_length=8
            )

            # Creamos un nuevo usuario
            new_user = User(name=request.form['name'], email=request.form['email'], password=hash_and_salted_password)

            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)  # Iniciamos sesion con los datos anteriores atraves de new_user
            session['logged_in'] = True  # Establece la variable de sesión para indicar que se ha iniciado sesión correctamente

            return redirect(url_for('home'))

    return render_template("register.html")


@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()  # Consulta en la base de datos si existe un usuario con este email.

        if not user:
            flash('Error: Has introducido un correo electrónico incorrecto')
            return redirect(url_for('login'))

        if not check_password_hash(user.password, password):
            flash('Error: Has introducido una contraseña incorrecta')
            return redirect(url_for('login'))

        login_user(user)
        session['logged_in'] = True  # Establece la variable de sesión para indicar que se ha iniciado sesión correctamente
        return redirect(url_for('secrets'))

    # Las credenciales son inválidas o no se proporcionaron, muestra un mensaje de error en la misma página
    session.pop('logged_in', None)  # Elimina la variable de sesión si no se ha iniciado sesión
    return render_template('login.html', logged_in=False)




@app.route('/secrets')
@login_required
def secrets():
    print(current_user.name)
    return render_template("secrets.html", name=current_user.name, logged_in=session.get('logged_in', False))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/download/<path:filename>')
@login_required
def download(filename):
    return send_from_directory('static/files', filename, as_attachment=True)


if __name__ == "__main__":
    app.run(debug=True)