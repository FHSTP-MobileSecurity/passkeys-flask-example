# Passkeys Implementation with Flask

This project demonstrates the simplest form of implementing passkeys (WebAuthn) using Python Flask. It was created as a challenge to understand the passkeys workflow and its implementation.

> :warning: **DO NOT USE THIS PROJECT AS A REFERENCE FOR IMPLEMENTATION IN PRODUCTION**

## Project Overview

This project consists of a Flask backend that handles WebAuthn registration and authentication processes, and a simple client-side JavaScript for interacting with the WebAuthn API.

## Prerequisites

- Python 3.x
- Pip (Python package installer)
- Web browser supporting WebAuthn (e.g., Chrome, Firefox)

## Setup Instructions

1. **Clone the Repository**
   ```bash
   git clone https://github.com/FHSTP-MobileSecurity/passkeys-flask-example.git
   cd passkeys-flask-example
   ```

2. **Create a Virtual Environment**
   ```bash
   python3 -m venv venv
   source venv/bin/activate     # On Windows use 'venv\Scripts\activate'
   ```

3. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the Flask Server**
   ```bash
   python app.py
   ```

## Project Structure

- **app.py**: Main Flask application file that handles the WebAuthn registration and authentication routes.
- **templates/index.html**: Simple HTML file containing buttons for registration and authentication.
- **static/index.js**: Client-side JavaScript to handle WebAuthn API interactions.
- **README.md**: Project description