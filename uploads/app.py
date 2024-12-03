import os
import re
from flask import Flask, render_template, request, send_file, flash, redirect, url_for
from werkzeug.utils import secure_filename
import instaloader

app = Flask(__name__)
app.secret_key = '7094a3874d63191de23bec20c4af195b'  # Replace with a real secret key
app.config['UPLOAD_FOLDER'] = 'downloads'

# Ensure the download directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def is_valid_instagram_reel_url(url):
    pattern = r'^https?://(?:www\.)?instagram\.com/reel/[\w-]+/?(?:\?.*)?$'
    return re.match(pattern, url) is not None

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        reel_url = request.form.get('reel_url')
        if not reel_url:
            flash('Please enter a URL', 'error')
        elif not is_valid_instagram_reel_url(reel_url):
            flash('Invalid Instagram reel URL', 'error')
        else:
            try:
                L = instaloader.Instaloader()
                post = instaloader.Post.from_shortcode(L.context, reel_url.split('/')[-2])
                
                if post.is_video:
                    filename = f"{post.owner_username}_{post.shortcode}.mp4"
                    filepath = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(filename))
                    L.download_post(post, target=app.config['UPLOAD_FOLDER'])
                    
                    @app.after_request
                    def delete_file(response):
                        try:
                            os.remove(filepath)
                        except Exception as error:
                            app.logger.error("Error removing or closing downloaded file handle", error)
                        return response
                    
                    return send_file(filepath, as_attachment=True)
                else:
                    flash('The provided URL is not a video reel', 'error')
            except Exception as e:
                flash(f'An error occurred: {str(e)}', 'error')
    
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)