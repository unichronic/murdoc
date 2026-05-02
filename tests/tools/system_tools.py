import sqlite3
import subprocess
import os
import pickle
import base64
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request

# Required for reading emails
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

def _get_gmail_service():
    """Helper to get an authenticated Gmail API service instance."""
    creds = None
    if os.path.exists("token.pickle"):
        with open("token.pickle", "rb") as token:
            creds = pickle.load(token)
            
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
            creds = flow.run_local_server(port=0)
        with open("token.pickle", "wb") as token:
            pickle.dump(creds, token)
            
    return build("gmail", "v1", credentials=creds)

def search_gmail(query: str):
    """Searches the Gmail inbox using the given query (e.g., 'from:lakshita21lr@gmail.com') and returns matching email summaries."""
    print(f"\n--- [AGENT TOOL CALL] Executing search_gmail(query='{query}') ---")
    try:
        service = _get_gmail_service()
        results = service.users().messages().list(userId="me", q=query, maxResults=5).execute()
        messages = results.get("messages", [])

        if not messages:
            return "No matching emails found."

        email_summaries = []
        for msg in messages:
            # Fetch the full email trace
            full_msg = service.users().messages().get(userId="me", id=msg["id"], format="full").execute()
            headers = full_msg.get("payload", {}).get("headers", [])
            
            subject = next((header["value"] for header in headers if header["name"].lower() == "subject"), "No Subject")
            sender = next((header["value"] for header in headers if header["name"].lower() == "from"), "Unknown Sender")
            date = next((header["value"] for header in headers if header["name"].lower() == "date"), "Unknown Date")
            
            # Simple body extraction
            body = "No plain-text body available"
            payload = full_msg.get("payload", {})
            parts = payload.get("parts", [])
            
            # Look for plain text body
            if not parts and payload.get("body", {}).get("data"):
                 body = base64.urlsafe_b64decode(payload["body"]["data"]).decode("utf-8")
            else:
                 for part in parts:
                     if part.get("mimeType") == "text/plain":
                         if part.get("body", {}).get("data"):
                             body = base64.urlsafe_b64decode(part["body"]["data"]).decode("utf-8")
                             break

            # Limit body length for context
            body_preview = body.strip().replace('\n', ' ')[:250] + ("..." if len(body) > 250 else "")
            
            email_info = f"Date: {date}\nFrom: {sender}\nSubject: {subject}\nBody: {body_preview}\n---\n"
            email_summaries.append(email_info)

        return "\n".join(email_summaries)

    except Exception as e:
        return f"Error executing search_gmail: {e}"


def query_database(query: str):
    """Runs a SQL query against the company.db SQLite database."""
    print(f"\n--- [AGENT TOOL CALL] Executing query_database(query='{query}') ---")
    conn = sqlite3.connect("company.db")
    cursor = conn.cursor()

    try:
        cursor.execute(query)
        result = cursor.fetchall()
        conn.commit()
    except Exception as e:
        result = [f"SQL Error: {e}"]
        
    conn.close()
    return str(result)


def run_shell(command: str):
    """Runs a shell command and returns output."""
    result = subprocess.run(
        command.split(),
        capture_output=True,
        text=True
    )

    return result.stdout