import os
from google import genai
from dotenv import load_dotenv

load_dotenv()
client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

# Chiede a Google la lista di tutti i modelli disponibili
for model in client.models.list():
    print(model.name)


