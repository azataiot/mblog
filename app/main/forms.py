from flask_wtf import FlaskForm
from flask_pagedown.fields import PageDownField
from wtforms import StringField, SubmitField, TextAreaField, BooleanField, SelectField
from flask_wtf.file import FileField, FileRequired, FileAllowed
from wtforms.validators import DataRequired, Email, Length, Regexp,ValidationError
from ..models import Role, User
from .. import photos

class PostForm(FlaskForm):
    title = StringField(validators=[DataRequired(),Length(1, 64)])
    body = TextAreaField(validators=[DataRequired()],render_kw = {"placeholder":"Жүктелуде..."})
    submit = SubmitField("Жіберу")

class CommentForm(FlaskForm):
    body = PageDownField(validators=[DataRequired()],render_kw = {"placeholder":"Пікіріңізді қалдырыңыз"})
    submit = SubmitField("Түсініктеме")

class NameForm(FlaskForm):
    name = StringField("Атың кім?",validators=[DataRequired(), Email()],render_kw = {"placeholder": "Пайдаланушы атын енгізіңіз"})
    submit = SubmitField("Жіберу")

class EditProfileForm(FlaskForm):
    photo = FileField(validators=[FileAllowed(photos,"Тек сурет қолдады")])
    location = StringField("Орналасуы",render_kw = {"placeholder": "Орналасуы"})
    about_me = TextAreaField("Мен туралы",render_kw = {"placeholder": "Өзіңді таныстыр"})
    submit = SubmitField("Өзгерістерді сақтау")

class EditProfileAdminForm(FlaskForm):
    photo = FileField(validators=[FileAllowed(photos,"Тек сурет қолдады")])
    email = StringField('Email', validators=[DataRequired(), Length(1, 64),
                                             Email()])
    username = StringField('Пайдаланушы аты', validators=[
        DataRequired(), Length(1, 64), Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
                                          'Пайдаланушы аттарында тек әріптер болуы керек, '
                                          'сандар, нүктелер немесе астын сызу')])
    confirmed = BooleanField('Расталған')
    role = SelectField('Рөл', coerce=int)
    location = StringField('Орналасуы', validators=[Length(0, 64)])
    about_me = TextAreaField('Мен туралы')
    submit = SubmitField('Жіберу')

    def __init__(self, user, *args, **kwargs):
        super(EditProfileAdminForm, self).__init__(*args, **kwargs)
        self.role.choices = [(role.id, role.name)
                             for role in Role.query.order_by(Role.name).all()]
        self.user = user

    def validate_email(self, field):
        if field.data != self.user.email and \
                User.query.filter_by(email=field.data).first():
            raise ValidationError('Электрондық пошта тіркелген.')

    def validate_username(self, field):
        if field.data != self.user.username and \
                User.query.filter_by(username=field.data).first():
            raise ValidationError('Қолданыстағы пайдаланушы аты.')
