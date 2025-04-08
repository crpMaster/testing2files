from flask import Flask, render_template, request, flash, jsonify
from flask_bootstrap import Bootstrap5
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField
from wtforms.validators import DataRequired, IPAddress
import json
import threading
import time
from snmp_scanner import SNMPScanner

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'  # Change this in production
bootstrap = Bootstrap5(app)

# Scan results storage
scan_results = {}
scan_status = {}

class ScanForm(FlaskForm):
    ip_address = StringField('IP Address', validators=[DataRequired(), IPAddress()])
    username = StringField('Username', validators=[DataRequired()])
    auth_protocol = SelectField('Auth Protocol', 
                               choices=[('MD5', 'MD5'), ('SHA', 'SHA'), ('SHA224', 'SHA224'),
                                       ('SHA256', 'SHA256'), ('SHA384', 'SHA384'), ('SHA512', 'SHA512')],
                               default='SHA')
    auth_password = PasswordField('Auth Password', validators=[DataRequired()])
    priv_protocol = SelectField('Privacy Protocol', 
                               choices=[('DES', 'DES'), ('3DES', 'Triple DES'), ('AES', 'AES'),
                                       ('AES192', 'AES 192'), ('AES256', 'AES 256')],
                               default='AES')
    priv_password = PasswordField('Privacy Password', validators=[DataRequired()])
    submit = SubmitField('Scan Device')

@app.route('/', methods=['GET', 'POST'])
def index():
    form = ScanForm()
    
    if form.validate_on_submit():
        ip_address = form.ip_address.data
        username = form.username.data
        auth_protocol = form.auth_protocol.data
        auth_password = form.auth_password.data
        priv_protocol = form.priv_protocol.data
        priv_password = form.priv_password.data
        
        # Start scan in background thread
        scan_id = f"{ip_address}_{int(time.time())}"
        scan_status[scan_id] = "running"
        
        scan_thread = threading.Thread(
            target=run_scan, 
            args=(scan_id, ip_address, username, auth_protocol, auth_password, priv_protocol, priv_password)
        )
        scan_thread.daemon = True
        scan_thread.start()
        
        flash(f'Scan started for {ip_address}', 'info')
        return jsonify({'status': 'success', 'scan_id': scan_id})
    
    return render_template('index.html', form=form, scan_results=scan_results, scan_status=scan_status)

@app.route('/scan_status/<scan_id>', methods=['GET'])
def get_scan_status(scan_id):
    if scan_id in scan_status:
        status = scan_status[scan_id]
        result = scan_results.get(scan_id, {})
        return jsonify({'status': status, 'result': result})
    return jsonify({'status': 'not_found'})

def run_scan(scan_id, ip_address, username, auth_protocol, auth_password, priv_protocol, priv_password):
    try:
        scanner = SNMPScanner(
            ip_address=ip_address,
            username=username,
            auth_protocol=auth_protocol,
            auth_password=auth_password,
            priv_protocol=priv_protocol,
            priv_password=priv_password
        )
        
        # Perform the scan
        result = scanner.scan()
        scan_results[scan_id] = result
        scan_status[scan_id] = "completed"
    except Exception as e:
        scan_results[scan_id] = {"error": str(e)}
        scan_status[scan_id] = "failed"

if __name__ == '__main__':
    app.run(debug=True) 