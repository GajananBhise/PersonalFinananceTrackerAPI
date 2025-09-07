📊 Personal Finance Tracker API

A Flask-RESTful API to manage personal finances.
This API allows users to register, log in, add transactions, view reports, and analyze expenses.
Authentication is handled with JWT (JSON Web Tokens), and transactions are stored in a relational database using SQLAlchemy ORM.

✨ Features

🔐 User Authentication

Register, Login, Logout with JWT tokens.

💸 Transactions

Add, Edit, Delete, and View income/expense transactions.

📑 Pagination & Filtering

Paginate results and filter by type, category, or date.

📈 Reports

Monthly summary (income, expense, balance).

Category breakdown.

🚫 Token Blacklisting

Secure logout by revoking JWT tokens.

📖 API Documentation

Swagger UI support.

🐳 Deployable with Docker.

⚙️ Tech Stack

Backend Framework: Flask + Flask-RESTful

Database: SQLite / PostgreSQL (configurable)

Authentication: Flask-JWT-Extended

Validation: Marshmallow

ORM: SQLAlchemy 2.0

Docs: Flasgger (Swagger UI)

📂 Project Structure
personal_finance_tracker/
│── main.py                 # Application entry point
│── models/                 # SQLAlchemy models
│── schemas/                # Marshmallow schemas
│── resources/              # API endpoints
📖 API Documentation

Swagger UI available at:
👉 pythongvb.pythonanywhere.com/apidocs/
│── requirements.txt        # Project dependencies
│── README.md               # Documentation
│── .env                    # Environment variables
