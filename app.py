# for authentication & authorization
import jwt

from flask import Flask, request, jsonify, make_response, render_template, session, redirect, url_for
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity,create_refresh_token,set_refresh_cookies,unset_jwt_cookies

from werkzeug.security import generate_password_hash, check_password_hash
from flask_mysqldb import MySQL
from flask_jwt_extended import decode_token
from flask import flash
from datetime import datetime, timedelta

from jwt.exceptions import ExpiredSignatureError
from flask_jwt_extended import get_jwt


#creating application & initialization flask
app = Flask(__name__)
#confuguration setting for crytographic purpose-& used to encrypt session cookies, generate secure tokens, and protect against cross-site request forgery (CSRF) attacks.
app.config['SECRET_KEY'] = 'wg4evfdg54ervge45grbtyhtr4'
#define the MySQL database connection details-host, username,password, and database name
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'Avani@123'
app.config['MYSQL_DB'] = 'blog_db_final'

#  configuration setting specific to Flask-JWT-Extended -used as the secret key for signing JSON Web Tokens (JWTs)-which must match the key used to sign and verify the tokens.
app.config['JWT_SECRET_KEY'] = '8gyufbiejwk09jio3nfeh'
#specifing  where the JWTs will be expected & jwt stored in cookies
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
#paths to the access and refresh JWT cookies availbilty.  ()'/') - cookies will be accessible across all routes and paths.
app.config['JWT_ACCESS_COOKIE_PATH'] = '/'
app.config['JWT_REFRESH_COOKIE_PATH'] = '/'
#disabling CSRF protection for JWT tokens
app.config['JWT_COOKIE_CSRF_PROTECT'] = False
#specifing  name of the access token cookie -'access_token'
app.config['JWT_ACCESS_COOKIE_NAME'] = 'access_token'



#nitializing MySQL-to perform database operations-executing queries, retrieving data, and modifying records
mysql = MySQL(app)
#handling the configuration and operation of JWTs
jwt = JWTManager(app)

#data structure for a user entity -to store and manipulate user-related data
# User model
class User:
    def __init__(self, user_id, email, password, fullname):
        self.fullname = fullname
        self.user_id = user_id
        self.email = email
        self.password = password


# associating ' /protected' URL path with the protected_route() function
@app.route('/protected')
# ensuring a valid JWT is present
@jwt_required()
def protected_route():
     #retrieves the identity from the current JWT.
    current_user = get_jwt_identity()
    # storing the current UTC time
    current_time = datetime.utcnow()
#  retrieving the expiration time ('exp') claim from the JWT
    if current_time > get_jwt().get('exp'):
        # Token has expired, generate a new access token and set it as a cookie
        refresh_token = create_refresh_token(identity=current_user)
        response = redirect(url_for('protected_route'))
        set_refresh_cookies(response, refresh_token)
        return response

    return jsonify(message='You are accessing a protected route', user=current_user), 200



@app.route('/')
@jwt_required(optional=True)
def index():
    #retrieving the value of the 'access_token' cookie from the request made to the '/' route
    access_token = request.cookies.get('access_token')
    current_user = None
# checking existence of access token value -  access_token' cookie is present in the request
    if access_token:
       # try-except block to handle potential exceptions
        try:
            #retrieving  user identity  from the current valid JWT 
            user_id = get_jwt_identity()
            #creating  cursor object for interaction & connection to the database 
            cur = mysql.connection.cursor()
            #executing a SQL query to select all columns (*) from the 'users' table where the 'user_id' column matches the user_id value
            cur.execute("SELECT * FROM users WHERE user_id = %s", (user_id,))
            #fetching the result 
            user_data = cur.fetchone()
            #closing the cursor to release the database resources.
            cur.close()


#checking if user_data exists
            if user_data:
                # creating new User object using the retrieved user_data

                current_user = User(user_data[0], user_data[1], user_data[2], user_data[3])
        #exceptional handling when jwt has expired sign
        except ExpiredSignatureError:
            # Refresh the token
            refresh_token = create_refresh_token(identity=user_id)
            response = redirect(url_for('index'))
            set_refresh_cookies(response, refresh_token)
            return response
        except Exception:
            # Handle other exceptions if needed
            pass

    cur = mysql.connection.cursor()
    cur.execute("SELECT blog_id, title FROM blogs")
    #fetching all the rows and storing in 'blogs'
    blogs = cur.fetchall()
    cur.close()
    #rendering the 'index.html' template
    return render_template('index.html', blogs=blogs, access_token=access_token, current_user=current_user)


#  handling the signup process for new users.
# associating it with the '/signup' URL path & specifing that the function should handle both GET and POST
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    # checking if the current request is a POST
    if request.method == 'POST':
        #extracting  input values by the user in the signup form. 
        fullname = request.form['fullname']
        email = request.form['email']
        password = request.form['password']
        #hashing the user input password
        hashed_password = generate_password_hash(password)
        #connection creation for interacting with data base
        cur = mysql.connection.cursor()
        #inserting  new row into the 'users' table
        cur.execute("INSERT INTO users ( email, password, fullname) VALUES (%s, %s, %s)", (email, hashed_password, fullname))
        #commiting/saving the changes
        mysql.connection.commit()
        #closing the cursor
        cur.close()

        return render_template('login.html', message=f'{email} successfully registered. Please login.')

    return render_template('signup.html')

#associating it with the '/login' URL path and to handle both GET and POST HTTP requests to this URL. 
@app.route('/login', methods=['GET', 'POST'])
def login():
    # checking if the current request is a POST
    if request.method == 'POST':
        ##extracting  input values by the user in the login form
        email = request.form['email']
        password = request.form['password']
 #connection creation for interacting with data base
        cur = mysql.connection.cursor()
         #selecting  all columns  from the 'users' table where the 'email'
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        # fetching & retriving the result set-corresponding user data
        user_data = cur.fetchone()
        #closing the cursor
        cur.close()

        #checking user data existence and matching the hashed password to given password
        if user_data and check_password_hash(user_data[2], password):
            # creating new User object using the retrieved user_data
            user = User(user_data[0], user_data[1], user_data[2],user_data[3])
        #generating  access token -for user identification
            access_token = create_access_token(identity=user.user_id)
        #creating  redirect response to the 'index' route. 
            response = redirect(url_for('index'))
        # Set JWT token as a cookie
            response.set_cookie('access_token', access_token)  
            return response

        return jsonify({'message': 'Invalid email or password'}), 401

    return render_template('login.html')


@app.route('/logout')
def logout():
    # creating redirect response to the 'index' rout
    response = make_response(redirect(url_for('index')))
    #removing the 'access_token' key from the session dictionary
    session.pop('access_token', None)
    #deleting the 'access_token' cookie
    response.delete_cookie('access_token')
    return response


@app.route('/blog', methods=['GET', 'POST'])        
#CHECKS  user provide a valid JSON Web Token (JWT)
@jwt_required()
def create_blog():
    if request.method == 'POST':
        #extract  INPUT values by the user in the blog creation form
        title = request.form['title']
        content = request.form['content']
        # retrieving the user identity from the current valid JWT
        user_id = get_jwt_identity()
#connection creation for interacting with data base
        cur = mysql.connection.cursor()
         #inserting  new row into the 'blogs' table
        cur.execute("INSERT INTO blogs (title, content, user_id) VALUES (%s, %s, %s)", (title, content, user_id))
        mysql.connection.commit()
        cur.close()

        ###return render_template('index.html', message=f'Blog created successfully')
        ### return jsonify({'message': 'Blog created successfully'}), 201
        
        
        # storing temporary message in the session.
        flash('Blog created successfully', 'success')
        return redirect(url_for('index'))

    return render_template('create_blog.html')

#associating it with the '/blog/<blog_id>' URL path
@app.route('/blog/<int:blog_id>', methods=['GET'])
# specifying- user can access  route optionally with a valid JSON Web Token (JWT). 
@jwt_required(optional=True)
def manage_blog(blog_id):

    # retrieving the user identity from the current valid JWT
    user_id = get_jwt_identity()
     #retrieving the value of the 'access_token' cookie from the request. 
    access_token = request.cookies.get('access_token')
    current_user = None

    if access_token:
        #try-except block to handle potential exceptions
        try:
            #retrieving the user identity  from the current valid JWT 
            user_id = get_jwt_identity()
            cur = mysql.connection.cursor()
            #selecting all columns (*) from the 'users' table where the 'user_id' column matches the provided user_id.
            cur.execute("SELECT * FROM users WHERE user_id = %s", (user_id,))
            # retrieving the result set corresponding to the user data fetched from the database.
            user_data = cur.fetchone()
            cur.close()

                # checking if user_data exists
            if user_data:
                 #creates a new User object using the retrieved user_data
                current_user = User(user_data[0], user_data[1], user_data[2], user_data[3])
        #handling the case when the JWT has an expired signature.
        except ExpiredSignatureError:
            # Refresh the token
            refresh_token = create_refresh_token(identity=user_id)
            response = redirect(url_for('index'))
            set_refresh_cookies(response, refresh_token)
            return response
        except Exception:
            # Handle other exceptions if needed
            pass
#checking if the current request is a GET request
    if request.method == 'GET':
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM blogs WHERE blog_id = %s", (blog_id,))
        blog = cur.fetchone()
        cur.close()
            #finding a matching blog
        if blog:
            #displaying the blog details and the user's identity.
            return render_template('view_blog.html', blog=blog, user_id=user_id)
        
        # return jsonify({'message': 'blog not found'}), 404
        return render_template('404.html', current_user =current_user), 404


# API endpoint to delete a blog .
@app.route('/blog/<int:blog_id>', methods=['DELETE'])
#ensuring user must provide a valid JSON Web Token (JWT)
@jwt_required()
def delete_blog(blog_id):
    #retrieving  user_id from the current valid JWT
    user_id = get_jwt_identity()
#connection creation for interacting with data base
    cur = mysql.connection.cursor()
    #selecting all columns (*) from the 'blogs' table where the 'blog_id
    cur.execute("SELECT * FROM blogs WHERE blog_id = %s", (blog_id,))
    blog = cur.fetchone()

    if not blog:
        return jsonify({'message': 'blog not found'}), 404

    if blog[3] != user_id:
        return jsonify({'message': 'You do not have permission to delete this blog'}), 403
        #query to delete a row from the 'blogs' table where the 'blog_id' column
    cur.execute("DELETE FROM blogs WHERE blog_id = %s", (blog_id,))
    mysql.connection.commit()
    cur.close()
 
    return jsonify({'message': 'blog deleted successfully'}), 200


# API endpoint to edit a blog post
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


