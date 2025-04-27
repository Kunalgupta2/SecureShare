# Secure File Sharing System

This FastAPI-based application allows users to sign up, verify their email, log in, upload files (for "Ops" role), and download them (for "Client" role). The system integrates email verification and encrypted download links for enhanced security.

## Features
- **User Signup**: Users can sign up with email and password.
- **Email Verification**: Upon signup, a verification email is sent with a unique encrypted URL.
- **Login**: Authenticated users can log in with their credentials, receiving a bearer token for further access.
- **File Upload**: Only users with the "Ops" role can upload files in specific formats (docx, pptx, xlsx).
- **File Download**: Users with the "Client" role can download files using an encrypted URL.

## Technologies Used
- **FastAPI**: Fast web framework for building APIs.
- **MongoDB**: A NoSQL database used to store user and file data.
- **JWT Authentication**: JSON Web Tokens are used for secure user authentication and authorization.
- **Email Verification**: SMTP (locally configured) for sending verification emails.
- **Cryptography**: Encrypting sensitive data such as URLs using Fernet symmetric encryption.

## Why MongoDB?
MongoDB is used here to demonstrate the integration of a NoSQL database with FastAPI. Although this could easily be achieved with SQLAlchemy and a relational database (like PostgreSQL or MySQL), MongoDB provides flexibility with schema-less data storage, which is beneficial for rapidly prototyping and scaling applications. MongoDB was chosen to showcase the skill in working with NoSQL databases, but it is not essential for the functionality of this simple project.

## Why Use SMTP Locally?
The SMTP server is configured to use localhost for testing purposes, making it easier to develop and test the email functionality locally. In a production environment, however, you would typically use an external email service like SendGrid or AWS SES to send verification emails, as using a local SMTP server is not ideal for production deployment. While developing, I can easily send emails to my other terminal using the local setup, which simplifies testing.

## Deployment to Production Environment
For production deployment, the following steps are recommended:

1. **Database**: Use a managed MongoDB service like MongoDB Atlas, or switch to a SQL-based database like PostgreSQL if needed.
2. **SMTP Configuration**: Switch from using the local SMTP server to a cloud-based email provider like SendGrid or AWS SES.
3. **API Hosting**: Deploy the application using services like Heroku, AWS EC2, or DigitalOcean. 
4. **Security Enhancements**: Enable HTTPS by using an SSL certificate, and ensure the app is behind a reverse proxy (like Nginx) in production.
5. **Scalability**: Consider using containerization (Docker) to facilitate scaling and ease of deployment.

## How to Run Locally

### Prerequisites
1. Python 3.8+
2. MongoDB (local instance or MongoDB Atlas)
3. SMTP server running on port 1025 (for testing email verification)
4. Install dependencies:

```bash
pip install -r requirements.txt
```

### Running the Application

## Start the FastAPI server:
```bash
uvicorn main:app --reload
```


### Start the SMTP server (for local testing):
## To use the local SMTP server, you can run a simple SMTP server in another terminal using the following command:

```bash
python -m smtpd -n -c DebuggingServer localhost:1025
```

