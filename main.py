import os
import base64
import pickle
import openai
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from email.mime.text import MIMEText

# Set up OpenAI API
openai.api_key = "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"

def generate_response(prompt):
    response = openai.ChatCompletion.create(
        model="gpt-3.5-turbo",
        messages=[{"role": "system", "content": "You are a helpful assistant."}, {"role": "user", "content": prompt}],
        max_tokens=150,
        n=1,
        stop=None,
        temperature=0.8,
    )

    message = response.choices[0]['message']['content'].strip()
    return message

def send_email(service, user_id, email_data, response_text):
    # Find the recipient's email address
    to_email = None
    subject = None
    for header in email_data['payload']['headers']:
        if header['name'].lower() == 'to':
            to_email = header['value']
        if header['name'].lower() == 'subject':
            subject = header['value']
        if to_email is not None and subject is not None:
            break

    if to_email is None:
        print("Recipient's email address not found.")
        return None

    message = MIMEText(response_text)
    message['to'] = to_email
    message['subject'] = 'Re: ' + subject
    create_message = {'raw': base64.urlsafe_b64encode(message.as_bytes()).decode()}
    
    try:
        send_message = (service.users().messages().send(userId=user_id, body=create_message).execute())
        print(F'sent message to {message["to"]} Message Id: {send_message["id"]}')
    except HttpError as error:
        print(F'An error occurred: {error}')
        send_message = None
    
    return send_message

def main():
    creds = None
    if os.path.exists('token.pickle'):
        with open('token.pickle', 'rb') as token:
            creds = pickle.load(token)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', ['https://www.googleapis.com/auth/gmail.modify'])
            creds = flow.run_local_server(port=0)
        with open('token.pickle', 'wb') as token:
            pickle.dump(creds, token)

    service = build('gmail', 'v1', credentials=creds)
    user_id = 'me'

    # Get unread emails
    query = "is:unread"
    unread_emails = service.users().messages().list(userId=user_id, q=query).execute()

    print(f"Unread emails: {len(unread_emails['messages'])}")

    message_ids = [email['id'] for email in unread_emails['messages']]

    for msg_id in message_ids:
        email_data = service.users().messages().get(userId=user_id, id=msg_id).execute()

        print(f"Processing email with ID: {msg_id}")

        email_subject = None

        for header in email_data['payload']['headers']:
            if header['name'].lower() == 'subject':
                email_subject = header['value']
                break

        if 'parts' in email_data['payload']:
            try:
                email_body = base64.urlsafe_b64decode(email_data['payload']['parts'][0]['body']['data']).decode('utf-8')
            except KeyError:
                email_body = ''
        else:
            email_body = ''

        if email_subject is None:
            prompt = f"Compose a response to the following email:\nEmail Body: {email_body}\n"
        else:
            prompt = f"Compose a response to the following email:\nSubject: {email_subject}\nEmail Body: {email_body}\n"

        response_text = generate_response(prompt)

        if response_text:
            send_email(service, user_id, email_data, response_text)

            # Mark email as read
            service.users().messages().modify(
                userId=user_id, id=msg_id,
                body={'removeLabelIds': ['UNREAD']}
            ).execute()
        else:
            print(f"No response generated for email ID: {msg_id}")

if __name__ == '__main__':
    main()
