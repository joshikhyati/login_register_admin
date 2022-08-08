import os

from flask import Flask,render_template, request,redirect,session,flash

from flask_bootstrap import Bootstrap

from flask_wtf.file import FileField,FileAllowed
from flask_wtf import FlaskForm

from wtforms import StringField,PasswordField,BooleanField,EmailField
from wtforms.validators import input_required,Email,Length

from flask_sqlalchemy import SQLAlchemy

from werkzeug.security import generate_password_hash,check_password_hash

from flask_login import LoginManager, login_manager,UserMixin,login_user,login_required,logout_user,current_user

from flask_admin import Admin,AdminIndexView
from flask_admin.contrib.sqla import ModelView
from flask_admin.menu import MenuLink

app=Flask(__name__)
app.config['SECRET_KEY']='Thisissupposedtobesecret!'
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:////database1.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']=False
admin=Admin(app, template_mode='bootstrap3')

app.config['upload_folder']="static\images"
Bootstrap(app)
db=SQLAlchemy(app)
login_manager=LoginManager()
login_manager.init_app(app)
login_manager.login_view='login'


class user(UserMixin,db.Model):
    id=db.Column(db.Integer,primary_key=True)
    name=db.Column(db.String())
    address=db.Column(db.String())
    email=db.Column(db.String(),unique=True)
    password=db.Column(db.String())
    # confirmpassword=db.Column(db.String())
    image_file=db.Column(db.String())
# @login_required
class SecureModelView(ModelView):
   
    def is_accessible(self):
         
       if "logged_in" in session:
            return current_user.is_authenticated

   
admin.add_view(SecureModelView(user,db.session))
@login_manager.user_loader
def load_user(user_id):
    return user.query.get(int(user_id))


class loginform(FlaskForm):
    email=EmailField('email',validators=[input_required()])
    password=PasswordField('password',validators=[input_required(),Length(min=6,max=80)])
    remember=BooleanField('remember me')

class registerform(FlaskForm): 
    name=StringField('name',validators=[input_required()])
    address=StringField('address',validators=[input_required()])
    email=EmailField('email',validators=[input_required()])
    password=PasswordField('password',validators=[input_required(),Length(min=6,max=80)])
    confirmpassword=PasswordField('password',validators=[input_required(),Length(min=6,max=80)])
    image_file=FileField('file',validators=[FileAllowed(['jpg','png','jpeg','jfif'])])


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login',methods=['GET','POST'])
def login():
    form=loginform()
    if request.method=='POST':
        email=request.form['uemail']
        password=request.form['upassword']
        
        User=user.query.filter_by(email=email).first()

        if User:
            if User.password and check_password_hash(User.password,password):
                login_user(User,remember=form.remember.data)
                return redirect("/home")
                        

            else:
                flash("password is incorrect")
                return redirect('/login')
        else:
           
            return redirect('/register')
    else:
        return render_template('login.html',form=form)

  


@app.route('/register',methods=['GET','POST'])
def register():
    form=registerform()
    if request.method=='POST':
        name=request.form['name']
        address=request.form['address']
        email=request.form['email']
        password=request.form['password']
        hashed_password=generate_password_hash(password,method='sha256')
        confirmpassword=request.form['confirmpassword']
        image_file=request.files['file']

        if password==confirmpassword:
             if image_file.filename!='':
                filepath=os.path.join(app.config['upload_folder'],image_file.filename)
                image_file.save(filepath)
                # import pdb;pdb.set_trace()
                new_user=user(name=name,address=address,email=email,password=hashed_password,image_file=image_file.filename,)
                db.session.add(new_user)
                db.session.commit()
                return render_template('login.html')
        else:
            redirect("/register")

    return render_template('register.html',form=form)


@app.route('/home')
@login_required
def home():
    return render_template('home.html',username=current_user.name,useraddress=current_user.address,useremail=current_user.email,userimg=current_user.image_file)




@app.route('/adminlogin',methods=['GET','POST'])
def adminlogin():
    if request.method=='POST':
        if request.form['email']=='khyati@gmail.com' and request.form['password']=='khyati123':
            session['logged_in']=True
            return redirect('/admin')
        else:
            return render_template('adminlogin.html')
    return render_template('adminlogin.html')

@app.route('/logout')
def logout():
    if logout_user():
        return redirect('/')

@app.route('/admin/logout')
def adminlogout():
    logout_user()
    return redirect('/')


if __name__=='__main__':
    app.run(debug=True)