from flask import Flask, jsonify
from database_worker import DatabaseManager
from cve_matcher import CVEMatcher

app = Flask(__name__)

# Конфигурация БД
DB_CONFIG = {
    'dbname': 'event_db',
    'user': 'postgres',
    'password': 'postgres',
    'host': 'localhost',
    'port': '5432'
}

# Инициализация менеджеров
db_manager = DatabaseManager(DB_CONFIG)
cve_matcher = CVEMatcher(db_manager)

@app.route('/match_cves', methods=['GET'])
def match_cves():
    try:
        cve_data = main_parser()
        matches = cve_matcher.match_cves_with_events(cve_data)
        
        return jsonify({
            'status': 'success',
            'matches': matches,
            'count': len(matches)
        }), 200
    
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500
@app.route('/endpoints/add', methods=['POST'])
def add_endpoint():
    try:
        # Get JSON data from request
        data = request.get_json()
        
        # Validate required fields
        if not all(key in data for key in ['timestamp', 'endpoint', 'event']):
            return jsonify({'error': 'Missing required fields'}), 400
            
        if not all(key in data['event'] for key in ['type', 'argument']):
            return jsonify({'error': 'Event missing type or argument'}), 400
            
        # Validate timestamp format (try to parse it)
        try:
            timestamp = datetime.fromisoformat(data['timestamp'])
        except ValueError:
            return jsonify({'error': 'Invalid timestamp format'}), 400
            
        # Validate event type
        if data['event']['type'] not in ['ALERT', 'INFO']:
            return jsonify({'error': 'Invalid event type'}), 400
            
        # Validate argument fields based on type
        if data['event']['type'] == 'ALERT':
            required_fields = ['filename', 'task_name', 'sha256']
        else:  # INFO
            required_fields = ['filename', 'task_name', 'version']
            
        if not all(field in data['event']['argument'] for field in required_fields):
            return jsonify({'error': f'Missing required argument fields for {data["event"]["type"]} event'}), 400
            
        # If all validations pass, store the event
        events.append(data)
        
        # Return success response
        return jsonify({'message': 'Event added successfully'}), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/endpoints/list', methods=['GET'])
def list_endpoints():
    """Optional endpoint to list stored events (for testing)"""
    return jsonify({'events': events}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
