FRAUDSHIELD URL SCANNER - FRONTEND

This frontend uses plain HTML, CSS and JavaScript. No npm installation is required.

RUN IT:
1. Start the backend first:
   Open PowerShell in the Backend folder.
   Activate your virtual environment if you use one.
   Run: python app.py

2. Start the frontend:
   Double-click run_frontend.bat inside the Frontend folder.
   Or open PowerShell in Frontend and run:
   python -m http.server 8000

3. Open http://127.0.0.1:8000 in your browser.
4. Enter a URL and click Analyze URL.

BACKEND CONNECTION:
The frontend calls http://127.0.0.1:5001/detect_url.
Keep the backend server running while using the frontend.

TROUBLESHOOTING:
- If Python is not found, run the command from the same environment where Python is installed.
- If the page cannot connect, make sure Backend/app.py is running on port 5001.
- If port 8000 is already in use, use another port such as 8001:
  python -m http.server 8001
  Then open http://127.0.0.1:8001

NOTE:
The result is an ML-based screening result, not a live reputation check or a guarantee of safety.
For real deployment, restrict CORS to the exact frontend origin and use secure hosting.
