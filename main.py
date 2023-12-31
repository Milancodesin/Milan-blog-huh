from flask import Flask, render_template, redirect, url_for, flash, request, abort
from functools import wraps
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, mapped_column, Mapped
from sqlalchemy import Integer, String, Text, ForeignKey
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
import hashlib
# from flask_gravatar import Gravatar

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
login_manager = LoginManager(app)
Bootstrap(app)


##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


##CONFIGURE TABLES

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    # name: Mapped[str] = mapped_column(String(250), nullable=False)
    author_id: Mapped[int] = mapped_column(Integer, ForeignKey("user_table.id"), nullable=False)
    author = relationship("User", back_populates="blog_post")
    title: Mapped[str] = mapped_column(db.String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(db.String(250), nullable=False)
    date: Mapped[str] = mapped_column(db.String(250), nullable=False)
    body: Mapped[str] = mapped_column(db.Text, nullable=False)
    img_url: Mapped[str] = mapped_column(db.String(250), nullable=False)

    comments = relationship("Comment", back_populates="parent_post")


class User(db.Model, UserMixin):
    __tablename__ = "user_table"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(150), nullable=False)
    password: Mapped[str] = mapped_column(String(250), nullable=False)
    name: Mapped[str] = mapped_column(String(150), nullable=False)

    blog_post = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")


class Comment(db.Model):
    __tablename__ = "comments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    text: Mapped[str] = mapped_column(Text, nullable=False)

    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("user_table.id"), nullable=False)
    comment_author = relationship("User", back_populates="comments")

    blog_post_id: Mapped[int] = mapped_column(Integer, ForeignKey("blog_posts.id"), nullable=False)
    parent_post = relationship("BlogPost", back_populates="comments")


# with app.app_context():
#     db.create_all()

def admin_only(function):
    @wraps(function)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.id != 1:
            abort(404)

        return function(*args, *kwargs)
    return decorated_function


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=["POST", "GET"])
def register():
    form = RegisterForm()
    password = form.password.data
    if form.validate_on_submit():
        users = User.query.all()
        for user in users:
            if user.email == form.email.data:
                flash("You've already signed up with that email, Log in instead")
                return redirect(url_for("login"))

        else:
            new_user = User()
            new_user.email = form.email.data
            new_user.password = generate_password_hash(password, method="pbkdf2:sha256", salt_length=8)
            new_user.name = form.name.data
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for("get_all_posts"))
    return render_template("register.html", form=form)


@app.route('/login', methods=["POST", "GET"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        password = request.form.get("password")
        email = request.form.get("email")
        user = User.query.filter_by(email=email).first()
        if user is None:
            flash("That email does not exist, please try again.")
            return redirect(url_for("login"))

        elif user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for("get_all_posts"))

        else:
            flash("Password is incorrect, please try again.")
            return redirect(url_for("login"))
    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["POST", "GET"])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    form = CommentForm()
    url = gravatar_url(email=requested_post.author.email)
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to Log in or register to comment.")
            return redirect(url_for("login"))

        comment = Comment(text=form.comment_text.data,
                          user_id=current_user.id,
                          blog_post_id=post_id)
        db.session.add(comment)
        db.session.commit()
    return render_template("post.html", post=requested_post, form=form, url=url)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["POST", "GET"])
@login_required
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>")
@login_required
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
@login_required
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


def gravatar_url(email, size=100, rating="g", default="retro", force_default=False):
    hash_value = hashlib.md5(email.lower().encode("utf-8")).hexdigest()
    return f"https://gravatar.com/avatar/{hash_value}?d={default}&s={size}&r={rating}&f={force_default}"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


if __name__ == "__main__":
    app.run(debug=True)


# https://github.com/zzzsochi/Flask-Gravatar/issues/31