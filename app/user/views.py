import logging
import os.path
from flask_mail import Message

from app import mail
from flask import Blueprint, render_template, request, flash, redirect, url_for, g
from flask_login import login_required
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from wtforms import csrf

from app import db
from app.post.models import Post, Collect
from app.user.forms import RegistrationForm
from app.user.models import User
from config import Config

user_bp = Blueprint("user", __name__, url_prefix='/user')

login_required = ['/user/center', '/user/user_blog', '/user/information', '/post/newpost', '/post/detail']
File = ['jpg', 'png', 'bmp', 'JPG', 'PNG', 'BMP']


@user_bp.before_request
def login_require():
    if request.path in login_required:
        currentuid = request.cookies.get('uid', None)
        if not currentuid:
            return render_template('login.html')
        else:
            user = User.query.get(int(currentuid))
            g.user = user


@user_bp.route("/center", methods=['GET', 'POST'])
def center():
    cur_uid = request.cookies.get('uid', None)
    if cur_uid:
        cur_u = User.query.get(cur_uid)
        post = Post.query.order_by(Post.post_time).all()
        return render_template("center.html", user=cur_u, post=post)
    else:
        return redirect('index')


@user_bp.route("/collection", methods=['GET', 'POST'])
def collection():
    cur_uid = request.cookies.get('uid', None)
    cur_u = User.query.get(cur_uid)
    collection = Collect.query.filter(Collect.user_id == cur_uid)
    post = Post.query.order_by(Post.post_time).all()
    return render_template("collection.html", user=cur_u, post=post, collect=collection)

@user_bp.route('/deletepost', methods=['GET', 'POST'])
def deletepost():
    pid=request.args.get('pid')
    post = Post.query.get(pid)
    uid = request.cookies.get('uid')
    user = User.query.get(uid)
    db.session.delete(post)
    db.session.commit()
    logging.info(f'===============User:{user.username} delete post{post.title}.=============')
    return redirect('center')
@user_bp.route("/informatin", methods=['GET', 'POST'])
def information():
    cur_uid = request.cookies.get('uid')
    cur_u = User.query.get(cur_uid)
    if request.method == 'POST':
        username = request.form.get('username')
        phone = request.form.get('phone')
        email = request.form.get('email')
        icon = request.files.get('icon')
        icon_name = icon.filename

        filetype = icon_name.rsplit('.')[-1]
        if filetype in File:
            icon_name = secure_filename(icon_name)
            file_path = os.path.join(Config.UPLOAD_DIR, icon_name)

            icon.save(file_path)
        else:
            return render_template('information.html', user=cur_u, msg='File type is not allowed.')
        reuser = User.query.all()
        for u in reuser:
            if u.username == username and username != cur_u.username:
                return render_template('information.html', user=cur_u, msg='The username already exits!')
            if u.email == email and email != cur_u.email:
                return render_template('information.html', user=cur_u, msg='The email already exits!')
        current_user = cur_u
        current_user.username = username
        current_user.phone = phone
        current_user.email = email
        path = 'upload/'
        current_user.img = os.path.join(path, icon_name)
        db.session.commit()
        logging.info(f'==================={cur_u.username} modify his information.==============')
        return redirect(url_for('user.center'))
    return render_template('information.html', user=cur_u)


@user_bp.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        reuser = User.query.filter(User.username == username).all()
        for user in reuser:
            match = check_password_hash(user.password_hash, password)
            if match:
                response = redirect(url_for('blog'))
                response.set_cookie('uid', str(user.id), max_age=60 * 60 * 12)
                logging.info(f'User:{user.username} login successfully.')
                return response

        else:
            logging.info(f'================User:{username} input the wrong password.==================')
            return render_template("login.html", msg='Wrong username or wrong password!')

    return render_template("login.html")


@user_bp.route("/logout")
def logout():
    cur_uid = request.cookies.get('uid')
    cur_u = User.query.get(cur_uid)
    response = redirect(url_for('index'))
    response.delete_cookie('uid')

    logging.info(f'User{cur_u.username} logout')
    return response


@user_bp.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data, phone=form.phone.data, gender=form.Gender.data)
        user.set_password(form.password.data)
        db.session.add(user)

        db.session.commit()
        logging.info(f'================={user.username} become a new user.======================')
        flash('Congratulations on becoming a new user of Blog!')
        return redirect(url_for('user.login'))

    return render_template('register.html', title='Register', form=form)


@user_bp.route('newpassword', methods=['GET', 'POST'])
def newpassword():
    cur_uid = request.cookies.get('uid')
    cur_u = User.query.get(cur_uid)
    if request.method == 'POST':
        old = request.form.get('old_password')
        new = request.form.get('new_password')
        if check_password_hash(cur_u.password_hash, old):
            cur_u.password_hash = generate_password_hash(new)
            db.session.commit()
            logging.info(f'================User: {cur_u.username} change the password!=====================')
            return redirect(url_for('user.center'))
        else:
            return render_template('newpassword.html', user=cur_u,
                                   msg="The old password is wrong.Please check and try again")

    return render_template('newpassword.html', user=cur_u)
