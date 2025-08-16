# Import all necessary functions from Flask
from flask import Flask, session, request, jsonify, render_template, redirect, url_for, flash
import os
import hashlib
import secrets
from functools import wraps
import traceback #

# --- Flask App Initialization ---
# This tells Flask where to find your HTML templates and static files (CSS, JS)
# since they are in the root directory, one level above this 'api' folder.
app = Flask(
    __name__,
    template_folder='../templates',
    static_folder='../public',
    static_url_path='/public'  # The URL path to serve static files from
)
app.secret_key = secrets.token_hex(16)


# --- Data and Constants (Unchanged) ---
FLAGS = {
    'intro': 'Ghost-In-The-Shellcode_v2.1',
    'challenge1': 'SEEN{The_Airlock_Is_Open}',
    'challenge2': 'FLAG{Pr1m3_Numb3r_Br34k3r_7331}',
    'challenge3': 'SEEN{KILL_0xDEADBEEFCAFED00D8BADF00D5EAF00D}'
}
P = 61
Q = 53
N = P * Q
E = 17
ENCRYPTED_MESSAGE = [2790, 1515, 1386, 3124, 2186, 1197, 2731, 1386, 1709, 3124, 765]
ENCRYPTED_FLAG_COMPONENT = 2170


# --- Helper Functions (Unchanged, they correctly redirect to page URLs) ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            flash('You need to access the gateway first.', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def challenge_access(level):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if session.get('challenge_level', 0) < level:
                flash('You need to complete the previous challenges first.', 'warning')
                # Redirect to the last challenge they have access to
                last_challenge = session.get('challenge_level', 1)
                return redirect(url_for(f'challenge{last_challenge}_page'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator


# ==============================================================================
#  PAGE RENDERING ROUTES - These routes serve your HTML pages
# ==============================================================================

@app.route('/')
def index():
    try:
        if 'logged_in' in session:
            level = session.get('challenge_level', 1)
            # If logged in, send them directly to the correct challenge page
            return redirect(url_for(f'challenge{level}_page'))

        # If not logged in, show the main index/login page
        return render_template('index.html', flag=FLAGS['intro'])
    
    except Exception as e:
        # This is our debug trap. It will catch any error.
        # It prints the full, detailed error traceback to your Vercel logs.
        print("--- AN EXCEPTION OCCURRED IN THE INDEX ROUTE ---")
        traceback.print_exc()
        print("-------------------------------------------------")
        
        # Return a simple error message to the browser
        return "An internal server error occurred. Please check the Vercel logs.", 500

@app.route('/challenge1')
@login_required
@challenge_access(1)
def challenge1_page():
    # Handle the cookie bypass logic directly here
    if 'bypass' in request.cookies and request.cookies.get('bypass') == 'true':
        if session.get('challenge_level', 0) < 2:
            session['challenge_level'] = 2
        flash('Cookie manipulation successful! You bypassed the first challenge.', 'success')
        return redirect(url_for('challenge2_page'))
        
    return render_template('challenge1.html')

@app.route('/challenge2')
@login_required
@challenge_access(2)
def challenge2_page():
    # Set up session variables for the RSA challenge
    if 'rsa_n' not in session:
        session['rsa_n'] = N
        session['rsa_e'] = E
        session['encrypted_msg'] = ENCRYPTED_MESSAGE
        
    return render_template(
        'challenge2.html',
        previous_flag=FLAGS['challenge1'],
        rsa_n=session['rsa_n'],
        rsa_e=session['rsa_e'],
        encrypted_msg=session['encrypted_msg']
    )

@app.route('/challenge3')
@login_required
@challenge_access(3)
def challenge3_page():
    return render_template('challenge3.html', flag=FLAGS['challenge2'])


# ==============================================================================
#  API ENDPOINTS - These routes handle form submissions and JS fetch requests
# ==============================================================================

@app.route('/api/login', methods=['POST'])
def login_action():
    username = request.form.get('username')
    password = request.form.get('password')
    
    if username and password:
        session['username'] = username
        session['logged_in'] = True
        session['challenge_level'] = 1
        flash(f'Welcome, {username}! You have accessed the first challenge.', 'success')
        return redirect(url_for('challenge1_page'))
    else:
        flash('Invalid login credentials.', 'error')
        return redirect(url_for('index'))

@app.route('/api/logout')
def logout_action():
    session.clear()
    flash('You have been logged out.', 'system')
    return redirect(url_for('index'))

@app.route('/api/check_prime', methods=['POST'])
@login_required
@challenge_access(2)
def check_prime():
    # This route is called by JavaScript, so it should return JSON
    try:
        data = request.get_json()
        p = int(data.get('prime_p', ''))
        q = int(data.get('prime_q', ''))
        
        if (p == P and q == Q) or (p == Q and q == P):
            session['found_primes'] = True
            return jsonify({'success': True, 'message': 'Correct prime factors! Now calculate the private key d.'})
        else:
            return jsonify({'success': False, 'message': 'Those are not the correct prime factors.'})
    except (ValueError, TypeError, AttributeError):
        return jsonify({'success': False, 'message': 'Invalid input. Please send valid numbers as JSON.'})

@app.route('/api/solve_challenge2', methods=['POST'])
@login_required
@challenge_access(2)
def solve_challenge2():
    # Also called by JavaScript, returns JSON
    if not session.get('found_primes', False):
        return jsonify({'success': False, 'message': 'You must identify the correct prime factors first.'})
    
    try:
        data = request.get_json()
        d = int(data.get('private_key', ''))
        message = data.get('decrypted_message', '').strip().upper()
        
        phi = (P - 1) * (Q - 1)
        if (d * E) % phi != 1:
            return jsonify({'success': False, 'message': 'The private key is not valid for this RSA system.'})
        
        if message != "SOVEREIGNTY":
            return jsonify({'success': False, 'message': f'The decrypted message "{message}" is incorrect. Try again.'})
        
        decrypted_component = pow(ENCRYPTED_FLAG_COMPONENT, d, N)
        if decrypted_component == 104:
            if session.get('challenge_level', 0) < 3:
                session['challenge_level'] = 3
            return jsonify({
                'success': True,
                'message': 'Congratulations! You have broken the RSA encryption.',
                'redirect': url_for('challenge3_page')  # Provide URL for JS to redirect
            })
        else:
            return jsonify({'success': False, 'message': 'Private key and message are correct, but final verification failed.'})
            
    except (ValueError, TypeError, AttributeError):
        return jsonify({'success': False, 'message': 'Invalid input. Please send valid numbers and text as JSON.'})

@app.route('/api/execute_transaction', methods=['POST'])
@login_required
@challenge_access(3)
def execute_transaction():
    # Final challenge action, returns JSON
    data = request.get_json()
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
            'transaction_hash': transaction_hash
        })
