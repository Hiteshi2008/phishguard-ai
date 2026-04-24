Live at : https://hiteshi2008.github.io/phishguard-ai/

🛡️ PhishGuard AI
Real-Time Phishing Detection System with ML + Browser Protection

PhishGuard AI is a full-stack cybersecurity project that detects phishing URLs using Machine Learning, provides real-time browser protection via a Chrome Extension, and sends instant email alerts when a threat is detected.

🚀 Live Demo

🌐 Website:
https://hiteshi2008.github.io/phishguard-ai

🔥 Features

🔍 URL Phishing Detection
Uses ML model + heuristic rules
Returns SAFE / PHISHING with confidence score


⚡ Real-Time Protection (Extension)
Detects phishing sites automatically while browsing
Shows warning banner on malicious pages


📩 Email Alert System
Sends instant Gmail notification when phishing detected
Includes URL, confidence, and threat indicators


📊 Dashboard UI
Scan URLs manually
View results with animations and confidence bar


🕒 History Tracking
Stores last 20 scans using localStorage


🟢 Backend Status Indicator
Shows whether API is online/offline


🧠 Tech Stack

Frontend

HTML, CSS, JavaScript

GitHub Pages (hosting)

Backend

Python (Flask)

Scikit-learn (RandomForest model)

Flask-CORS

Deployed on Render (Free tier)

Extension

Chrome Extension (Manifest V3)

JavaScript (background + popup)


⚙️ How It Works
User enters a URL (or extension detects automatically)

URL is sent to backend API:

/api/scan
Backend:

Extracts features from URL,
Runs ML model + heuristic rules

Returns:
Prediction (SAFE / PHISHING),
Confidence score

Reasons
If phishing:
Email alert is triggered,
Extension shows warning banner
