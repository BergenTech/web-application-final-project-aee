from app import app

if __name__ == "__main__":
    app.secret_key = "super_secret_key" 
    app.run()