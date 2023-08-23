import jwt
import flask
from flask import Flask, request, jsonify, make_response, render_template, session, redirect, url_for
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity,create_refresh_token,set_refresh_cookies,unset_jwt_cookies

from werkzeug.security import generate_password_hash, check_password_hash
from flask_mysqldb import MySQL
from flask_jwt_extended import decode_token
from flask import flash
from datetime import datetime, timedelta

from jwt.exceptions import ExpiredSignatureError
from flask_jwt_extended import get_jwt

app = Flask(__name__)

app.config['SECRET_KEY'] = 'wg4evfdg54ervge45grbtyhtr4'

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'Avani@123'
app.config['MYSQL_DB'] = 'blog_db_final'


app.config['JWT_SECRET_KEY'] = '8gyufbiejwk09jio3nfeh'

app.config['JWT_TOKEN_LOCATION'] = ['cookies']

app.config['JWT_ACCESS_COOKIE_PATH'] = '/'
app.config['JWT_REFRESH_COOKIE_PATH'] = '/'

app.config['JWT_COOKIE_CSRF_PROTECT'] = False

app.config['JWT_ACCESS_COOKIE_NAME'] = 'access_token'




mysql = MySQL(app)

jwt = JWTManager(app)

class User:
    def __init__(self, user_id, email, password, fullname):
        self.fullname = fullname
        self.user_id = user_id
        self.email = email
        self.password = password


@app.route('/protected')

@jwt_required()
def protected_route():

    current_user = get_jwt_identity()

    current_time = datetime.utcnow()

    if current_time > get_jwt().get('exp'):

        refresh_token = create_refresh_token(identity=current_user)
        response = redirect(url_for('protected_route'))
        set_refresh_cookies(response, refresh_token)
        return response

    return jsonify(message='You are accessing a protected route', user=current_user), 200



@app.route('/')
@jwt_required(optional=True)
def index():

    access_token = request.cookies.get('access_token')
    current_user = None

    if access_token:

        try:
   
            user_id = get_jwt_identity()

            cur = mysql.connection.cursor()
     
            cur.execute("SELECT * FROM users WHERE user_id = %s", (user_id,))

            user_data = cur.fetchone()
     
            cur.close()


            if user_data:


                current_user = User(user_data[0], user_data[1], user_data[2], user_data[3])

        except ExpiredSignatureError:

            refresh_token = create_refresh_token(identity=user_id)
            response = redirect(url_for('index'))
            set_refresh_cookies(response, refresh_token)
            return response
        except Exception:

            pass

    cur = mysql.connection.cursor()
    cur.execute("SELECT blog_id, title FROM blogs")

    blogs = cur.fetchall()
    cur.close()

    return render_template('index.html', blogs=blogs, access_token=access_token, current_user=current_user)




@app.route('/signup', methods=['GET', 'POST'])
def signup():

    if request.method == 'POST':

        fullname = request.form['fullname']
        email = request.form['email']
        password = request.form['password']

        hashed_password = generate_password_hash(password)

        cur = mysql.connection.cursor()

        cur.execute("INSERT INTO users ( email, password, fullname) VALUES (%s, %s, %s)", (email, hashed_password, fullname))

        mysql.connection.commit()

        cur.close()

        return render_template('login.html', message=f'{email} successfully registered. Please login.')

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():

    if request.method == 'POST':

        email = request.form['email']
        password = request.form['password']

        cur = mysql.connection.cursor()

        cur.execute("SELECT * FROM users WHERE email = %s", (email,))

        user_data = cur.fetchone()
        #closing the cursor
        cur.close()

        if user_data and check_password_hash(user_data[2], password):

            user = User(user_data[0], user_data[1], user_data[2],user_data[3])

            access_token = create_access_token(identity=user.user_id)

            response = redirect(url_for('index'))
   
            response.set_cookie('access_token', access_token)  
            return response

        return jsonify({'message': 'Invalid email or password'}), 401

    return render_template('login.html')


@app.route('/logout')
def logout():

    response = make_response(redirect(url_for('index')))

    session.pop('access_token', None)
 
    response.delete_cookie('access_token')
    return response


@app.route('/blog', methods=['GET', 'POST'])        

@jwt_required()
def create_blog():
    if request.method == 'POST':

        title = request.form['title']
        content = request.form['content']

        user_id = get_jwt_identity()

        cur = mysql.connection.cursor()

        cur.execute("INSERT INTO blogs (title, content, user_id) VALUES (%s, %s, %s)", (title, content, user_id))
        mysql.connection.commit()
        cur.close()
        flash('Blog created successfully', 'success')
        return redirect(url_for('index'))

    return render_template('create_blog.html')


@app.route('/blog/<int:blog_id>', methods=['GET'])

@jwt_required(optional=True)
def manage_blog(blog_id):

    user_id = get_jwt_identity()
 
    access_token = request.cookies.get('access_token')
    current_user = None

    if access_token:

        try:
      
            user_id = get_jwt_identity()
            cur = mysql.connection.cursor()
            cur.execute("SELECT * FROM users WHERE user_id = %s", (user_id,))

            user_data = cur.fetchone()
            cur.close()

            if user_data:
    
                current_user = User(user_data[0], user_data[1], user_data[2], user_data[3])

        except ExpiredSignatureError:

            refresh_token = create_refresh_token(identity=user_id)
            response = redirect(url_for('index'))
            set_refresh_cookies(response, refresh_token)
            return response
        except Exception:

            pass

    if request.method == 'GET':
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM blogs WHERE blog_id = %s", (blog_id,))
        blog = cur.fetchone()
        cur.close()

        if blog:

            return render_template('view_blog.html', blog=blog, user_id=user_id)
        return render_template('404.html', current_user =current_user), 404


@app.route('/blog/<int:blog_id>', methods=['DELETE'])

@jwt_required()
def delete_blog(blog_id):

    user_id = get_jwt_identity()

    cur = mysql.connection.cursor()

    cur.execute("SELECT * FROM blogs WHERE blog_id = %s", (blog_id,))
    blog = cur.fetchone()

    if not blog:
        return jsonify({'message': 'blog not found'}), 404

    if blog[3] != user_id:
        return jsonify({'message': 'You do not have permission to delete this blog'}), 403

    cur.execute("DELETE FROM blogs WHERE blog_id = %s", (blog_id,))
    mysql.connection.commit()
    cur.close()
 
    return jsonify({'message': 'blog deleted successfully'}), 200


@app.route('/blog/<int:blog_id>', methods=['POST'])
@jwt_required()
def edit_blog(blog_id):
    user_id = get_jwt_identity()

    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM blogs WHERE blog_id = %s", (blog_id,))
    blog = cur.fetchone()

    if not blog:
        return jsonify({'message': 'Blog not found'}), 404

    if blog[3] != user_id:
        return jsonify({'message': 'You do not have permission to edit this blog'}), 403

    title = request.form.get('title')
    content = request.form.get('content')

    cur.execute("UPDATE blogs SET title = %s, content = %s WHERE blog_id = %s",(title, content, blog_id))
    mysql.connection.commit()
    cur.close()
    
    return redirect(url_for('manage_blog', blog_id=blog_id))

    # return jsonify({'message': 'Blog updated successfully'}), 200


# Initialize the app
#checking if the current module is the main module
if __name__ == '__main__':
    # configuring the lifetime of a user session
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)
    #configuring the expiration time for access tokens 
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=1)
    #configuring the expiration time for refresh tokens 
    app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=1)
    # run the app
    app.run(debug=True)


