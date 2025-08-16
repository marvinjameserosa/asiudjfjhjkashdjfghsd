# api/index.py
from flask import Flask, redirect, url_for, request, session, flash, make_response, jsonify
import os
import hashlib
import secrets
from functools import wraps

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# Flags for each challenge
FLAGS = {
    'intro': 'Ghost-In-The-Shellcode_v2.1',
    'challenge1': 'SEEN{The_Airlock_Is_Open}',
    'challenge2': 'FLAG{Pr1m3_Numb3r_Br34k3r_7331}',
    'challenge3': 'SEEN{KILL_0xDEADBEEFCAFED00D8BADF00D5EAF00D}'
}

# RSA PARAMETERS
P = 61
Q = 53
N = P * Q  # 3233
E = 17     # Public exponent
ENCRYPTED_MESSAGE = [2790, 1515, 1386, 3124, 2186, 1197, 2731, 1386, 1709, 3124, 765]
ENCRYPTED_FLAG_COMPONENT = 2170

# Helper Functions
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return jsonify({'error': 'You need to access the gateway first.', 'redirect': '/'}), 401
        return f(*args, **kwargs)
    return decorated_function

def challenge_access(level):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if session.get('challenge_level', 0) < level:
                return jsonify({'error': 'You need to complete the previous challenges first.', 'redirect': '/'}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Core Routes - Return JSON instead of templates
@app.route('/')
def index():
    if 'logged_in' in session:
        level = session.get('challenge_level', 1)
        return jsonify({
            'logged_in': True,
            'challenge_level': level,
            'redirect': f'/challenge{level}' if level <= 3 else '/challenge3'
        })
    return jsonify({
        'logged_in': False,
        'flag': FLAGS['intro'],
        'message': 'Welcome to the Gateway'
    })

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return jsonify({'message': 'Login required', 'method': 'POST'})
    
    data = request.get_json() if request.is_json else request.form
    username = data.get('username')
    password = data.get('password')
    
    if username and password:
        session['username'] = username
        session['logged_in'] = True
        session['challenge_level'] = 1
        return jsonify({
            'success': True,
            'message': f'Welcome, {username}! You have accessed the first challenge.',
            'redirect': '/challenge1'
        })
    else:
        return jsonify({'success': False, 'message': 'Invalid login credentials'}), 400

@app.route('/logout')
def logout():
    session.clear()
    return jsonify({'success': True, 'message': 'You have been logged out.', 'redirect': '/'})

# Challenge 1 Routes
@app.route('/challenge1')
@login_required
@challenge_access(1)
def challenge1():
    if 'bypass' in request.cookies and request.cookies.get('bypass') == 'true':
        if session.get('challenge_level', 0) < 2:
            session['challenge_level'] = 2
        return jsonify({
            'success': True,
            'message': 'Cookie manipulation successful! You bypassed the first challenge.',
            'redirect': '/challenge2'
        })
    return jsonify({
        'challenge': 1,
        'message': 'Challenge 1: Cookie Bypass',
        'hint': 'You need to set the right cookie to proceed'
    })

@app.route('/bypass_cookie')
def bypass_cookie():
    return jsonify({
        'message': 'Cookie set',
        'instruction': 'Set cookie "bypass=true" and visit /challenge1'
    })

# Challenge 2 Routes
@app.route('/challenge2')
@login_required
@challenge_access(2)
def challenge2():
    if 'rsa_n' not in session:
        session['rsa_n'] = N
        session['rsa_e'] = E
        session['encrypted_msg'] = ENCRYPTED_MESSAGE
    
    return jsonify({
        'challenge': 2,
        'previous_flag': FLAGS['challenge1'],
        'rsa_n': session['rsa_n'],
        'rsa_e': session['rsa_e'],
        'encrypted_msg': session['encrypted_msg'],
        'message': 'Break the RSA encryption'
    })

@app.route('/check_prime', methods=['POST'])
@login_required
@challenge_access(2)
def check_prime():
    try:
        data = request.get_json() if request.is_json else request.form
        p = int(data.get('prime_p', ''))
        q = int(data.get('prime_q', ''))
        
        if (p == P and q == Q) or (p == Q and q == P):
            session['found_primes'] = True
            return jsonify({'success': True, 'message': 'Correct prime factors! Now calculate the private key d.'})
        else:
            return jsonify({'success': False, 'message': 'Those are not the correct prime factors.'})
    except (ValueError, TypeError):
        return jsonify({'success': False, 'message': 'Please enter valid numbers.'})

@app.route('/solve_challenge2', methods=['POST'])
@login_required
@challenge_access(2)
def solve_challenge2():
    if not session.get('found_primes', False):
        return jsonify({'success': False, 'message': 'You must identify the correct prime factors first.'})
    
    try:
        data = request.get_json() if request.is_json else request.form
        d = int(data.get('private_key', ''))
        message = data.get('decrypted_message', '').strip().upper()
        
        phi = (P - 1) * (Q - 1)
        if (d * E) % phi != 1:
            return jsonify({'success': False, 'message': 'The private key is not valid for this RSA system.'})
        
        if message != "SOVEREIGNTY":
            return jsonify({'success': False, 'message': f'The decrypted message "{message}" is incorrect. Try again.'})
        
        decrypted_component = pow(ENCRYPTED_FLAG_COMPONENT, d, N)
        if decrypted_component == 104:  # Note: your comment says 1337 but code checks 104
            if session.get('challenge_level', 0) < 3:
                session['challenge_level'] = 3
            return jsonify({
                'success': True,
                'message': 'Congratulations! You have broken the RSA encryption.',
                'redirect': '/challenge3'
            })
        else:
            return jsonify({'success': False, 'message': 'Private key and message are correct, but final verification failed.'})
            
    except (ValueError, TypeError):
        return jsonify({'success': False, 'message': 'Please enter a valid number for the private key.'})

# Challenge 3 Routes
@app.route('/challenge3')
@login_required
@challenge_access(3)
def challenge3():
    return jsonify({
        'challenge': 3,
        'flag': FLAGS['challenge2'],
        'message': 'Final Challenge: Execute the kill transaction'
    })

@app.route('/execute_transaction', methods=['POST'])
@login_required
@challenge_access(3)
def execute_transaction():
    data = request.get_json() if request.is_json else request.form
    kill_key = data.get('kill_key', '').strip()
    transaction_data = f"user:{session.get('username', 'anonymous')}:time:{os.urandom(8).hex()}"
    transaction_hash = hashlib.sha256(transaction_data.encode()).hexdigest()
    
    if kill_key == FLAGS['challenge3']:
        return jsonify({
            'success': True,
            'message': 'Transaction executed! The Source Ledger has been neutralized.',
            'transaction_hash': transaction_hash,
            'flag': FLAGS['challenge3'],
            'victory': True
        })
    else:
        return jsonify({
            'success': False,
            'message': 'Transaction initiated but requires valid kill key.',
            'flag': FLAGS['challenge2'],
            'transaction_hash': transaction_hash,
            'invalid_attempt': True
        })

# Health check route
@app.route('/health')
def health():
    return jsonify({'status': 'healthy'})

# Catch all route for any undefined paths
@app.route('/<path:path>')
def catch_all(path):
    return jsonify({'error': 'Route not found', 'path': path}), 404