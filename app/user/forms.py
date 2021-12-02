from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, RadioField
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError, Regexp, Length

from .models import User
from app.post.models import Post
from flask_wtf import FlaskForm

from wtforms import StringField, SelectField, SubmitField

from wtforms.validators import DataRequired

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    phone = StringField('Phone', validators=[DataRequired(),Regexp(r'1[3,5,6,7,8]\d{9}'),Length(min=8,max=11)])
    email = StringField('Email', validators=[DataRequired()])
    Gender = RadioField('Gender', choices=[('0', 'Male'), ('1', 'Female')],validators=[DataRequired()])

    password = PasswordField('Password', validators=[DataRequired()])
    password2 = PasswordField(
        'Ensure Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    # Verify whether the user name is duplicate
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('The username already exists, please use a different one!')
    def validate_phone(self, phone):
        user = User.query.filter_by(phone=phone.data).first()
        if user is not None:
            raise ValidationError('The phone number has already been registered, please use a different one!')
    # Verify whether the mailbox is duplicate
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('The email address already exists, please use a different one!')

