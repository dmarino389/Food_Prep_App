from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Import your Flask app instance and other necessary modules here
from app import app  # Replace 'app' with the actual name of your Flask app instance if needed

if __name__ == "__main__":
    app.run()
