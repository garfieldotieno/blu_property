from flask import Flask, Response, render_template
from flask_cors import CORS
import json

app = Flask(__name__)

# Enable CORS for all routes
CORS(app)

# Load data from db.json
def load_data():
    with open('db.json') as f:
        return json.load(f)

@app.route('/')
def load_welcome_view():
    return render_template('index.html')


@app.route('/posts', methods=['GET'])
def get_posts():
    data = load_data()
    posts = data.get('posts', [])
    
    # Transform JSON data into HTML
    html_posts = ''.join([
        f'<div class="post">'
        f'<h2>{post["title"]}</h2>'
        f'<p>{post["content"]}</p>'
        f'</div>'
        for post in posts
    ])
    
    return Response(html_posts, mimetype='text/html')

if __name__ == '__main__':
    app.run(port=3000, debug=True)
