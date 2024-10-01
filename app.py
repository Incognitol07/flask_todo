from flask import Flask, render_template, url_for, request, redirect, flash, session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['SECRET_KEY'] = 'e393d299bd4e957af1dce7b7b4a64af3'
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False, unique=True)
    password_hash = db.Column(db.String(200), nullable=False)
    todos = db.relationship('Todo', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(200), nullable=False)
    completed = db.Column(db.Integer, default=0)
    date_created = db.Column(db.DateTime, default=datetime.now())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self) -> str:
        return '<Task %r>' % self.id

# Registration Route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username and password:
            existing_user = User.query.filter_by(username=username).first()
            if existing_user:
                flash('Username already exists!', 'error')
            else:
                new_user = User(username=username)
                new_user.set_password(password)
                db.session.add(new_user)
                db.session.commit()
                flash('Account created successfully! Please log in.', 'success')
                return redirect(url_for('login'))
        else:
            flash('Please provide both username and password.', 'error')
    return render_template('register.html')

# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['user_id'] = user.id
            flash('Logged in successfully!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password.', 'error')
    return render_template('login.html')

# Logout Route
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

# Main Index Route for Task Management
@app.route("/", methods=['POST', 'GET'])
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    user = User.query.get(user_id)

    if request.method == 'POST':
        task_content = request.form['content'].title()
        if task_content:
            new_task = Todo(content=task_content, user_id=user.id)
            try:
                db.session.add(new_task)
                db.session.commit()
                flash('Task added successfully!', 'success')
                return redirect("/")
            except:
                flash('There was an issue adding your task.', 'error')
    
    tasks = Todo.query.filter_by(user_id=user_id).order_by(Todo.date_created).all()
    return render_template("index.html", tasks=tasks)

# Delete Task Route
@app.route("/delete/<int:id>")
def delete(id):
    task_to_delete = Todo.query.get_or_404(id)
    
    if task_to_delete.user_id != session['user_id']:
        flash("You are not authorized to delete this task!", 'error')
        return redirect(url_for('index'))

    try:
        db.session.delete(task_to_delete)
        db.session.commit()
        flash('Task deleted successfully!', 'success')
        return redirect('/')
    except:
        flash('There was a problem deleting that task.', 'error')
        return redirect('/')

# Update Task Route
# Update Task Route
@app.route("/update/<int:id>", methods=['GET', 'POST'])
def update(id):
    task = Todo.query.get_or_404(id)
    
    if task.user_id != session['user_id']:
        flash("You are not authorized to update this task!", 'error')
        return redirect(url_for('index'))

    if request.method == 'POST':
        task_content = request.form['content'].title()
        if task_content:
            task.content = task_content
            try:
                db.session.commit()
                flash('Task updated successfully!', 'success')
                return redirect('/')
            except:
                flash('There was an issue updating your task.', 'error')
        else:
            flash('Task content cannot be empty.', 'error')
    return render_template('update.html', task=task)


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
