from flask import Flask, render_template, request, redirect, url_for, flash
import sqlite3
import os  # Make sure to import os at the top of your script


# Initialize Flask app
app = Flask(__name__)
app.secret_key = 'supersecretkey'


    
    
# Initialize SQLite database
DATABASE = 'blog_db.sqlite'

# Check if the database file exists, and if not, create tables
if not os.path.exists(DATABASE):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Create a table for blog posts
    cursor.execute('''
    CREATE TABLE posts (
        id INTEGER PRIMARY KEY,
        title TEXT NOT NULL,
        content TEXT NOT NULL
    )
    ''')
    conn.commit()
    conn.close()
    
    



@app.route('/')
def index():
    """Display all blog posts."""
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM posts ORDER BY id DESC')
        posts = cursor.fetchall()
    return render_template('index.html', posts=posts)


@app.route('/post', methods=['POST'])
def post():
    """Add a new blog post."""
    title = request.form['title']
    content = request.form['content']
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('INSERT INTO posts (title, content) VALUES (?, ?)', (title, content))
        conn.commit()
    flash('Post added successfully!', 'success')
    return redirect(url_for('index'))

# Simple template for index
index_template = """
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Egge sin blogg</title>
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
  </head>
  <body>
    <div class="container mt-5">
      <h1>Egge sin blogg</h1>
      <form action="/post" method="post">
        <div class="form-group">
          <label for="title">Title:</label>
          <input type="text" class="form-control" id="title" name="title" required>
        </div>
        <div class="form-group">
          <label for="content">Content:</label>
          <textarea class="form-control" id="content" name="content" rows="4" required></textarea>
        </div>
        <button type="submit" class="btn btn-primary">Post</button>
      </form>
      <hr>
      {% with messages = get_flashed_messages(with_categories=true) %}
        {% if messages %}
          {% for category, message in messages %}
            <div class="alert alert-{{ category }}">
              {{ message }}
            </div>
          {% endfor %}
        {% endif %}
      {% endwith %}
      {% for post in posts %}
        <h3>{{ post[1] }}</h3>
        <p>{{ post[2] }}</p>
        <hr>
      {% endfor %}
    </div>
  </body>
</html>
"""



# Before saving the template
if not os.path.exists('templates'):
    os.mkdir('templates')

# Save the template
with open('templates/index.html', 'w') as f:
    f.write(index_template)

# Return the setup status
"Flask blog application setup completed."

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)

