import sqlite3, os


from flask import Flask, render_template, request, flash, redirect, url_for, session, send_from_directory, send_file
from flask_session import Session
from cachelib import FileSystemCache
from datetime import timedelta
from steganocryptopy.steganography import Steganography

con = sqlite3.connect("USER_INFO.db", check_same_thread=False)
cursor = con.cursor()
app = Flask(__name__)
app.secret_key = '1111'
app.config['SESSION_TYPE'] = 'cachelib'
app.config['SESSION_CACHELIB'] = FileSystemCache(cache_dir='flask_session', threshold=500)
Session(app)


@app.route("/")
def login():
    return render_template('login.html')

@app.route("/encryption_site/")
def encryption():
    return render_template('encryption_site.html')

@app.route("/encryption_process/", methods=['POST','GET'])
def encryption_proc():
    if request.method == 'POST':
        image = request.files['image']
        image.save(f'img/{session['username']}_{image.filename}_img')
        with open(f'{session['username']}_{image.filename}_secret_info.txt', 'w', encoding='utf-8') as sec_info:
            sec_info.write(str(request.form["description"]))
        with open(f'secret_keys/{session['username']}_secretkey.txt', 'w', encoding='utf-8') as sec_key:
            sec_key.write(str(session['secretkey']))
        secret = Steganography.encrypt(f'secret_keys/{session['username']}_secretkey.txt',
                                       f'img/{session['username']}_{image.filename}_img',
                                       f'{session['username']}_{image.filename}_secret_info.txt')
        secret.save(f"img/encryption_{image.filename}")
        return send_file(f'img/encryption_{image.filename}', mimetype='image/*')


@app.route("/decryption_site/")
def decryption():
    return render_template('decryption_site.html')

@app.route("/decryption_process/",methods=['POST','GET'])
def decryption_proc():
    image = request.files['image']
    image.save(f'img_dec/{image.filename}')
    with open(f'secret_keys/{session['username']}_secretkey.txt', 'w', encoding='utf-8') as file:
       file.write(session['secretkey'])
    result = Steganography.decrypt(f'secret_keys/{session['username']}_secretkey.txt', f"img_dec/{image.filename}")

    return render_template('decryption_output.html',text=result)


@app.route("/check_login/", methods=['POST','GET'])
def check_login():
    if request.method == 'POST':
        login = request.form['login']
        password = request.form['password']
        cursor.execute("SELECT * FROM users_info")
    for i in cursor:
        if login == i[1] and password == i[2]:
            session['login'] = True
            session['username'] = login
            session['id'] = i[0]
            session['secretkey'] = i[3]
            session.permanent = False
            app.permanent_session_lifetime = timedelta(minutes=100)
            session.modified = True
            flash('Вы авторозованны', 'success')
            return redirect(url_for('encryption'))

    flash('Неверный логин или пароль', 'danger')
    return redirect(url_for('login'))

@app.route("/register/")
def register():
    return render_template('register.html')

@app.route("/save_register/", methods=['POST','GET'])
def save_register():
    cursor.execute("SELECT * FROM users_info")
    check_data = cursor.fetchall()

    if request.method == 'POST':
        login = request.form['login']
        password = request.form['password']
        Steganography.generate_key('')
        with open('key.key', 'r', encoding='utf-8') as file:
            secretkey=file.read()


        for user in check_data:
            if user[1] == login:
                flash("такой параметр login уже существует","danger")
                return redirect(url_for('register'))
            if user[2] == password:
                flash("такой параметр password уже существует","danger")
                return redirect(url_for('register'))

        cursor.execute("INSERT INTO users_info (login, password, secretkey) VALUES (?,?,?)",
                       (login,password,secretkey))
        con.commit()
        return redirect(url_for('encryption'))

app.run(debug=True)