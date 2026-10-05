from fastapi import FastAPI, Form, Response
from fastapi.responses import HTMLResponse

app = FastAPI(title="FIREWATCH Local Demo Target")

@app.get("/", response_class=HTMLResponse)
def home():
    return """
    <html><head><title>Demo Target</title></head>
    <body>
      <h1>FIREWATCH Demo Target</h1>
      <p>Intentionally weak headers/cookie/form configuration for local scanner testing.</p>
      <form action='/login' method='post'>
        <input type='text' name='username'>
        <input type='password' name='password'>
        <button>Login</button>
      </form>
      <script src='http://cdn.example.invalid/demo.js'></script>
      <a href='/set-cookie'>Set cookie</a>
    </body></html>
    """

@app.get("/set-cookie")
def set_cookie(response: Response):
    response.set_cookie("session_id", "demo-value")
    return {"ok": True}

@app.post("/login")
def login(username: str = Form(...), password: str = Form(...)):
    return {"ok": False, "message": "Demo only"}

@app.get("/api/data")
def api_data():
    return {"items": [1,2,3], "status": "demo"}
