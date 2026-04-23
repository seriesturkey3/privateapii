import os
import json
import glob
import logging
from datetime import datetime
from functools import wraps
from flask import Flask, jsonify, request, g
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

# Rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["100 per hour", "10 per minute"]
)

# Configuration
API_KEY = os.environ.get('API_KEY')
if not API_KEY:
    raise ValueError("API_KEY environment variable must be set")

DATA_DIR = os.path.dirname(os.path.abspath(__file__))
CACHE = {}

def load_json_file(filename):
    """Load and cache JSON file from data folder"""
    filepath = os.path.join(DATA_DIR, 'data', filename)
    
    if filename in CACHE:
        return CACHE[filename]
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
            CACHE[filename] = data
            return data
    except FileNotFoundError:
        return None
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in {filename}: {e}")
        return None

def require_api_key(f):
    """Decorator to require API key"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        key = request.headers.get('X-API-Key') or request.headers.get('x-api-key')
        
        if not key:
            logger.warning(f"Missing API key from {request.remote_addr}")
            return jsonify({
                "error": "Unauthorized",
                "message": "API key required in X-API-Key header"
            }), 401
        
        if key != API_KEY:
            logger.warning(f"Invalid API key from {request.remote_addr}")
            return jsonify({
                "error": "Unauthorized",
                "message": "Invalid API key"
            }), 401
        
        return f(*args, **kwargs)
    return decorated_function

@app.before_request
def before_request():
    g.start_time = datetime.now()

@app.after_request
def after_request(response):
    if hasattr(g, 'start_time'):
        duration = (datetime.now() - g.start_time).total_seconds()
        logger.info(f"{request.method} {request.path} - {response.status_code} - {duration:.3f}s")
    
    # Security headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    return response

@app.errorhandler(404)
def not_found(error):
    return jsonify({
        "error": "Not Found",
        "message": "The requested resource does not exist"
    }), 404

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({
        "error": "Rate Limit Exceeded",
        "message": str(e.description)
    }), 429

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal error: {error}")
    return jsonify({
        "error": "Internal Server Error",
        "message": "Something went wrong"
    }), 500

# Health check (no auth required)
@app.route('/health')
def health():
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0"
    })

# API routes (auth required)
@app.route('/api/<country>')
@require_api_key
@limiter.limit("30 per minute")
def get_country(country):
    country = country.lower().strip()
    
    # Security: prevent directory traversal
    if '..' in country or '/' in country or '\\' in country:
        return jsonify({"error": "Invalid country name"}), 400
    
    data = load_json_file(f"{country}.json")
    
    if data is None:
        return jsonify({
            "error": "Not Found",
            "message": f"Country '{country}' not found"
        }), 404
    
    return jsonify({
        "success": True,
        "data": data,
        "cached": f"{country}.json" in CACHE
    })

@app.route('/countries')
@require_api_key
@limiter.limit("10 per minute")
def list_countries():
    try:
        files = glob.glob(os.path.join(DATA_DIR, 'data', '*.json'))
        countries = [os.path.basename(f).replace('.json', '') for f in files]
        
        return jsonify({
            "success": True,
            "countries": sorted(countries),
            "count": len(countries)
        })
    except Exception as e:
        logger.error(f"Error listing countries: {e}")
        return jsonify({"error": "Failed to list countries"}), 500

@app.route('/')
def home():
    return jsonify({
        "name": "Arab Carrier Lookup API",
        "version": "1.0.0",
        "author": "Mahdi Aboudallah",
        "endpoints": {
            "/health": "Health check (no auth)",
            "/countries": "List all countries (auth required)",
            "/api/<country>": "Get carrier data for country (auth required)"
        },
        "authentication": "X-API-Key header required"
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
