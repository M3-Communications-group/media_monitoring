from flask import Flask, jsonify, request, redirect, url_for, send_from_directory, render_template
from bson import ObjectId
from flask.json import JSONEncoder
import requests
from bs4 import BeautifulSoup
from pymongo import MongoClient
from datetime import datetime
import dateutil.parser
import bleach
import re
from celery import Celery
from flask_cors import CORS
import os

class CustomJSONEncoder(JSONEncoder):
    def default(self, obj):
        if isinstance(obj, ObjectId):
            return str(obj)
        return super(CustomJSONEncoder, self).default(obj) 

app = Flask(__name__, static_url_path='', static_folder='mm3/build')
app.json_encoder = CustomJSONEncoder
CORS(app)
app.config.update(
    CELERY_BROKER_URL='redis://localhost:6379/0',
    CELERY_RESULT_BACKEND='redis://redis:6379/0'
)

def make_celery(app):
    celery = Celery(app.import_name, backend=app.config['CELERY_RESULT_BACKEND'],
                    broker=app.config['CELERY_BROKER_URL'])
    celery.conf.update(app.config)
    return celery

celery = make_celery(app)

client = MongoClient('mongodb://mongodb:27017/')
db = client['media_monitoring']
collection = db['alerts']

def load_config_from_db():
    config = db['configurations'].find_one({"name": "default"})
    if not config:
        raise Exception("Failed to load configuration from MongoDB")
    return config

@celery.task(bind=True)
def process_feeds_task(self, feeds, keywords):
    for index, site in enumerate(feeds, start=1):
        response = requests.get(site)
        soup = BeautifulSoup(response.content, 'xml')
        items = soup.findAll('item')
        for item in items:
            process_item(item, site, keywords)
        self.update_state(state='PROGRESS', meta={'current': index, 'total': len(feeds)})
    return {'current': len(feeds), 'total': len(feeds), 'status': 'Task completed'}


def process_item(item, site, keywords):
    title = get_clean_text(item.find('title')) or 'No Title'
    description = get_clean_text(item.find('description')) or 'No Description'
    pub_date = find_pub_date(item)
    link = item.find('link').text if item.find('link') else 'No Link'
    media_urls = [enclosure['url'] for enclosure in item.find_all('enclosure') if 'url' in enclosure.attrs]
    content = f"{title} {description}".lower()
    words = content.split()
    if any(word.lower() in keywords for word in words):
        collection.update_one(
            {"link": link}, 
            {"$setOnInsert": {
                "site": site,
                "title": title,
                "description": description,
                "pub_date": pub_date,
                "link": link,
                "media_urls": media_urls,
                "last_checked": datetime.now()
            }},
            upsert=True
        )
        send_telegram_notification('-1002000986167', f'New alert: {title} - {link} from {site}')

def find_pub_date(item):
    for field in ['pubDate', 'dc:date']:
        date_str = item.find(field)
        if date_str:
            return dateutil.parser.parse(date_str.text)
    return None

def get_clean_text(element):
    if element and element.text:
        soup = BeautifulSoup(element.text, 'lxml')
        return ' '.join(soup.get_text().split())
    return ""

def highlight_keywords(text, keywords):
    pattern = re.compile(r'\b(' + '|'.join(re.escape(keyword) for keyword in keywords) + r')\b', re.IGNORECASE)
    highlighted_text = pattern.sub(lambda match: f"<span class='highlight'>{match.group(0)}</span>", text)
    return highlighted_text

def send_telegram_notification(chat_id, message):
    token = '6716988388:AAGo4imuLdspREQ7jq8pkRAWLT4OFxNZxHk'
    url = f'https://api.telegram.org/bot{token}/sendMessage'
    data = {'chat_id': chat_id, 'text': message, 'parse_mode': 'HTML'}
    try:
        response = requests.post(url, data=data)
        response.raise_for_status()
    except Exception as e:
        print(f"Failed to send Telegram notification: {e}")

@app.route('/api/alerts')
def api_show_alerts():
    return show_alerts()

@app.route('/alerts')
def alerts():
    return show_alerts()

def show_alerts():
    page = int(request.args.get('page', 1))
    per_page = 20
    skip = (page - 1) * per_page
    search_query = request.args.get('search', '')
    query = {}
    if search_query:
        regex_pattern = f".*{search_query}.*"
        query = {"$or": [
            {"title": {"$regex": regex_pattern, "$options": "i"}},
            {"description": {"$regex": regex_pattern, "$options": "i"}}
        ]}
    alerts = collection.find(query).skip(skip).limit(per_page)
    total_alerts = collection.count_documents(query)
    total_pages = (total_alerts + per_page - 1) // per_page
    sanitized_alerts = []
    config = load_config_from_db()
    keywords = config.get('keywords', [])
    for alert in alerts:
        alert['description'] = bleach.clean(highlight_keywords(alert.get('description', ''), keywords), tags=['span'], attributes={'span': ['class']}, strip=True)
        alert['title'] = bleach.clean(highlight_keywords(alert.get('title', ''), keywords), tags=['span'], attributes={'span': ['class']}, strip=True)
        sanitized_alerts.append(alert)
    return jsonify({
        'alerts': sanitized_alerts,
        'total_pages': total_pages,
        'current_page': page,
    })

@app.route('/add-site', methods=['POST'])
def add_site():
    site_url = request.form.get('siteUrl')
    db['configurations'].update_one({"name": "default"}, {"$addToSet": {"sites": site_url}})
    return redirect(url_for('config_management'))

@app.route('/add-keyword', methods=['POST'])
def add_keyword():
    keyword = request.form.get('keyword').lower()
    db['configurations'].update_one({"name": "default"}, {"$addToSet": {"keywords": keyword}})
    return redirect(url_for('config_management'))

@app.route('/delete-site/<int:index>', methods=['GET'])
def delete_site(index):
    config = load_config_from_db()
    try:
        if 'sites' in config and 0 <= index < len(config['sites']):
            del config['sites'][index]
            db['configurations'].update_one({"name": "default"}, {"$set": {"sites": config['sites']}})
        else:
            print("Index out of bounds or 'sites' list not found.")
    except Exception as e:
        print(f"An error occurred: {e}")
    return redirect(url_for('config_management'))

@app.route('/delete-keyword/<int:index>', methods=['GET'])
def delete_keyword(index):
    config = load_config_from_db()
    try:
        if 'keywords' in config and 0 <= index < len(config['keywords']):
            del config['keywords'][index]
            db['configurations'].update_one({"name": "default"}, {"$set": {"keywords": config['keywords']}})
        else:
            print("Index out of bounds or no keywords list found.")
    except Exception as e:
        print(f"An error occurred: {e}")
    return redirect(url_for('config_management'))

@app.route('/run-script')
def run_script():
    config = load_config_from_db()
    task = process_feeds_task.apply_async(args=[config['sites'], config['keywords']])
    return jsonify({"task_id": task.id}), 202

@app.route('/task-status/<task_id>')
def task_status(task_id):
    task = process_feeds_task.AsyncResult(task_id)
    if task.state == 'PENDING':
        response = {'state': task.state, 'status': 'Pending...'}
    elif task.state != 'FAILURE':
        response = {
            'state': task.state,
            'progress': task.info.get('current', 0),
            'total': task.info.get('total', 1),
            'status': task.info.get('status', '')
        }
    else:
        response = {'state': task.state, 'status': str(task.info), 'error': 'Task failed'}
    return jsonify(response)

@app.route('/config-management')
def config_management():
    config = load_config_from_db()
    return render_template('config_management.html', sites=config['sites'], keywords=config['keywords'])

@app.route('/workers')
def show_workers():
    i = celery.control.inspect()
    workers = i.registered()
    if not workers:
        workers = "No workers found."
    return render_template('workers.html', workers=workers)

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve(path):
    if path != "" and os.path.exists(os.path.join(app.root_path, 'client', 'build', path)):
        return send_from_directory(os.path.join(app.root_path, 'client', 'build'), path)
    else:
        return send_from_directory(os.path.join(app.root_path, 'client', 'build'), 'index.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)