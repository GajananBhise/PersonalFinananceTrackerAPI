import datetime
from datetime import timedelta
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.sql import func
from sqlalchemy import Integer, String, DateTime, extract
from flask import Flask, request, render_template
from flask_restful import Api, Resource
from marshmallow import Schema, fields, validate
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
import os
from dotenv import load_dotenv
from flasgger import Swagger, swag_from

# ------------------ Config ------------------
app = Flask(__name__)
load_dotenv()
class Base(DeclarativeBase):
    pass

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("SQLALCHEMY_DATABASE_URI")
app.config['JWT_SECRET_KEY'] = os.environ.get("JWT_SECRET_KEY")
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours = 1)

db = SQLAlchemy(model_class=Base)
db.init_app(app)
api = Api(app)
jwt = JWTManager(app)

#---------------Swagger UI with authentication support---------------
swagger = Swagger(app, parse = True, template={
    "swagger": "2.0",
    "info": {
        "title": "Finance Tracker API",
        "description": "API documentation for Finance Tracker",
        "version": "1.0.0"
    },
    "securityDefinitions": {
        "Bearer": {
            "type": "apiKey",
            "name": "Authorization",
            "in": "header",
            "description": "JWT Authorization header using the Bearer scheme. Example: 'Bearer {token}'"
        }
    }
})

# ------------------ Models ------------------

class User(db.Model):
    __tablename__ = "user"
    user_id : Mapped[int] = mapped_column(Integer, primary_key = True)
    name : Mapped[str] = mapped_column(String, nullable = False)
    email : Mapped[str] = mapped_column(String, nullable = False, unique = True)
    password : Mapped[str] = mapped_column(String, nullable = False)
    created_at : Mapped[datetime.datetime] = mapped_column(DateTime, default = datetime.datetime.now)
    transactions = relationship(argument = "Transaction", back_populates = "user")

class TokenBlocklist(db.Model):
    __tablename__ = "token_blocklist"
    id : Mapped[int] = mapped_column(Integer, primary_key = True)
    jti : Mapped[str] = mapped_column(String, nullable = False, index = True)

class Transaction(db.Model):
    __tablename__ = "transaction"
    id : Mapped[int] = mapped_column(Integer, primary_key = True)
    user_id : Mapped[int] = mapped_column(Integer, db.ForeignKey("user.user_id"))
    amount : Mapped[int] = mapped_column(Integer, nullable = False)
    type : Mapped[str] = mapped_column(String, nullable = False)
    category : Mapped[str] = mapped_column(String, nullable = False)
    date : Mapped[datetime.datetime] = mapped_column(DateTime, default = datetime.date.today)
    note : Mapped[str] = mapped_column(String, default = "NA")
    user = relationship(argument = "User", back_populates = "transactions")



with app.app_context():
    db.create_all()

# ------------------ Marshmallow Schemas ------------------

class UserSchema(Schema):
    user_id = fields.Int(dump_only = True)
    name = fields.Str(required = True)
    email = fields.Str(required = True, validate = validate.Email())
    password = fields.Str(load_only = True, required = True)
    created_at = fields.DateTime(dump_only = True)

class TransactionSchema(Schema):
    id = fields.Int(dump_only = True)
    user_id = fields.Int(dump_only = True)
    amount = fields.Int(required = True, validate = validate.Range(min = 1, error = "amount must be positive"))
    type = fields.Str(required = True, validate = validate.OneOf(["income", "expense"]))
    category = fields.Str(required = True)
    date = fields.DateTime(load_default = datetime.date.today)
    note = fields.Str(load_default = "NA")



user_schema = UserSchema()
transaction_schema = TransactionSchema()
# ------------------ Global Error Handlers ------------------

@app.errorhandler(404)
def not_found(e):
    return { "error" : "Resource not found" }, 404

@app.errorhandler(500)
def server_error(e):
    return { "error" : "Internal server error" }, 500

@app.errorhandler(400)
def bad_request(e):
    return { "error" : "Bad request" }, 400

# ------------------ JWT Token Blacklist Check ------------------
@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    jti = jwt_payload["jti"]
    token = db.session.execute(db.select(TokenBlocklist).where(TokenBlocklist.jti == jti)).scalar()
    return token is not None

# ------------------ Resources ------------------

@app.route("/")
def home():
    return render_template("index.html")

class Register(Resource):
    @swag_from({
        "tags": ["Auth"],
        "description": "Register a new user.",
        "parameters": [
            {
                "name": "body",
                "in": "body",
                "required": True,
                "schema": {
                    "properties": {
                        "name": {"type": "string", "example": "john Alice"},
                        "email": {"type": "string", "example": "john@example.com"},
                        "password": {"type": "string", "example": "secret123"}
                    },
                    "required": ["name", "email", "password"]
                }
            }
        ],
        "responses": {
            201: {"description": "User registered successfully"},
            400: {"description": "Validation error"}
        }
    })
    def post(self):
        data = request.get_json()
        errors = user_schema.validate(data)
        if errors:
            return {"errors" : errors}, 400

        name = data["name"]
        email = data["email"]
        password = generate_password_hash(data["password"], method="pbkdf2:sha256", salt_length = 8)

        new_user = User(
            name = name,
            email = email,
            password = password
        )
        db.session.add(new_user)
        db.session.commit()
        return user_schema.dump(new_user), 201


class Login(Resource):
    @swag_from({
        "tags": ["Auth"],
        "description": "Login with email and password to get JWT access token.",
        "parameters": [
            {
                "name": "body",
                "in": "body",
                "required": True,
                "schema": {
                    "properties": {
                        "email": {"type": "string", "example": "john@example.com"},
                        "password": {"type": "string", "example": "secret123"}
                    },
                    "required": ["email", "password"]
                }
            }
        ],
        "responses": {
            200: {"description": "Login successful, JWT returned"},
            401: {"description": "Invalid credentials"}
        }
    })
    def post(self):
        data = request.get_json()
        errors = user_schema.validate(data, partial = ("name",))
        if errors:
            return { "errors" : errors }, 400

        email = data["email"]
        password = data["password"]

        user = db.session.execute(db.select(User).where(User.email == email)).scalar()
        if user and check_password_hash(user.password, password):
            access_token = create_access_token(identity = email)
            return { "access_token" : access_token }, 200

        return { "errors" : "email or password doesn't exist" }, 401

class Logout(Resource):
    @swag_from({
        "tags": ["Auth"],
        "description": "Logout the current user (invalidate JWT).",
        "responses": {
            200: {"description": "Successfully logged out"},
            401: {"description": "Unauthorized"}
        }
    })
    @jwt_required()
    def post(self):
        jti = get_jwt()["jti"]
        db.session.add(TokenBlocklist(jti = jti))
        db.session.commit()
        return { "message" : "successfully logged out" }, 200

class AddTransaction(Resource):
    @swag_from({
        "tags": ["Transactions"],
        "description": "Add a new transaction.",
        "parameters": [
            {
                "name": "body",
                "in": "body",
                "required": True,
                "schema": {
                    "properties": {
                        "amount": {"type": "integer", "example": 20000},
                        "type": {"type": "string", "enum": ["income", "expense"], "example": "income"},
                        "category": {"type": "string", "example": "salary"},
                        "date": {"type": "string", "format": "date", "example": "2025-09-01"},
                        "note": {"type": "string", "example": "monthly salary credited"}
                    },
                    "required": ["amount", "type", "category"]
                }
            }
        ],
        "responses": {
            201: {"description": "Transaction added successfully"},
            400: {"description": "Validation error"}
        }
    })
    @jwt_required()
    def post(self):
        data = request.get_json()
        errors = transaction_schema.validate(data)
        if errors:
            return { "errors" : errors }, 400
        user = db.session.execute(db.select(User).where(User.email == get_jwt_identity())).scalar()
        new_transaction = Transaction(user_id = user.user_id, **data)
        db.session.add(new_transaction)
        db.session.commit()
        return transaction_schema.dump(new_transaction), 201

class GetTransactions(Resource):
    @swag_from({
        "tags": ["Transactions"],
        "description": "Get all transactions of the logged-in user with pagination and filters.",
        "parameters": [
            {
                "name": "page",
                "in": "query",
                "type": "integer",
                "required": False,
                "default": 1,
                "description": "Page number for pagination"
            },
            {
                "name": "per_page",
                "in": "query",
                "type": "integer",
                "required": False,
                "default": 4,
                "description": "Number of results per page"
            },
            {
                "name": "type",
                "in": "query",
                "type": "string",
                "enum": ["income", "expense"],
                "required": False,
                "description": "Filter by transaction type"
            },
            {
                "name": "category",
                "in": "query",
                "type": "string",
                "required": False,
                "description": "Filter by category"
            },
            {
                "name": "start_date",
                "in": "query",
                "type": "string",
                "format": "date",
                "required": False,
                "description": "Filter transactions from this date (YYYY-MM-DD)"
            },
            {
                "name": "end_date",
                "in": "query",
                "type": "string",
                "format": "date",
                "required": False,
                "description": "Filter transactions until this date (YYYY-MM-DD)"
            }
        ],
        "responses": {
            200: {
                "description": "A paginated list of transactions",
                "examples": {
                    "application/json": {
                        "transactions": [
                            {
                                "id": 1,
                                "amount": 20000,
                                "type": "income",
                                "category": "salary",
                                "note": "monthly salary",
                                "date": "2025-09-01T00:00:00"
                            }
                        ],
                        "total": 10,
                        "page": 1,
                        "pages": 3,
                        "per_page": 4
                    }
                }
            },
            401: {"description": "Unauthorized - JWT token missing or invalid"}
        }
    })
    @jwt_required()
    def get(self):
        user = db.session.execute(db.select(User).where(User.email == get_jwt_identity())).scalar()

        #pagination params
        page = request.args.get("page", 1, type = int)
        per_page = request.args.get("per_page", 4, type = int)

        #filters params
        type = request.args.get("type")
        category = request.args.get("category")
        start_date = request.args.get("start_date")
        end_date = request.args.get("end_date")

        query = db.select(Transaction).where(Transaction.user_id == user.user_id)
        if type:
            query = query.where(Transaction.type == type)
        if category:
            query = query.where(Transaction.category == category)
        if start_date:
            query = query.where(Transaction.date >= start_date)
        if end_date:
            query = query .where(Transaction.date <= end_date)

        pagination = db.paginate(query,
                                 page = page,
                                 per_page = per_page,
                                 error_out = False)
        transactions = [ transaction_schema.dump(t) for t in pagination.items ]

        return {
            "transactions" : transactions,
            "total" : pagination.total,
            "page" : pagination.page,
            "pages" : pagination.pages,
            "per_page" : pagination.per_page
        }, 200

class EditTransaction(Resource):
    @swag_from({
        "tags": ["Transactions"],
        "description": "Edit an existing transaction (partial update).",
        "parameters": [
            {
                "name": "transaction_id",
                "in": "path",
                "type": "integer",
                "required": True,
                "description": "Transaction ID"
            },
            {
                "name": "body",
                "in": "body",
                "required": True,
                "schema": {
                    "properties": {
                        "amount": {"type": "integer", "example": 15000},
                        "type": {"type": "string", "enum": ["income", "expense"], "example": "expense"},
                        "category": {"type": "string", "example": "groceries"},
                        "note": {"type": "string", "example": "monthly shopping"}
                    }
                }
            }
        ],
        "responses": {
            200: {"description": "Transaction updated successfully"},
            404: {"description": "Transaction not found"}
        }
    })
    @jwt_required()
    def patch(self, transaction_id):
        data = request.get_json()
        errors = transaction_schema.validate(data, partial = True)
        if errors:
            return { "errors" : errors }, 400
        user = db.session.execute(db.select(User).where(User.email == get_jwt_identity())).scalar()
        transaction = db.session.execute(db.select(Transaction).where(Transaction.id == transaction_id,
                                                                      Transaction.user_id == user.user_id)).scalar()
        if not transaction:
            return { "error" : "transaction not found for this id or for current user" }, 404

        for key, value in data.items():
            setattr(transaction, key, value)
        db.session.commit()

        return transaction_schema.dump(transaction), 200

class DeleteTransaction(Resource):
    @swag_from({
        "tags": ["Transactions"],
        "description": "Delete a transaction.",
        "parameters": [
            {
                "name": "transaction_id",
                "in": "path",
                "type": "integer",
                "required": True,
                "description": "Transaction ID"
            }
        ],
        "responses": {
            200: {"description": "Transaction deleted successfully"},
            404: {"description": "Transaction not found"}
        }
    })
    @jwt_required()
    def delete(self, transaction_id):
        user = db.session.execute(db.select(User).where(User.email == get_jwt_identity())).scalar()
        transaction = db.session.execute(db.select(Transaction).where(Transaction.id == transaction_id,
                                                                      Transaction.user_id == user.user_id)).scalar()
        if not transaction:
            return { "error" : "transaction not found for this id or for current user" }, 404
        db.session.delete(transaction)
        db.session.commit()
        return { "message" : "transaction deleted successfully" }, 200

class MonthlySummary(Resource):
    @swag_from({
        "tags": ["Reports"],
        "description": "Get income, expense, and balance summary for a given month.",
        "parameters": [
            {"name": "year", "in": "query", "type": "integer", "example": 2025, "required": False},
            {"name": "month", "in": "query", "type": "integer", "example": 9, "required": False}
        ],
        "responses": {
            200: {"description": "Monthly summary returned successfully"},
            401: {"description": "Unauthorized"}
        }
    })
    @jwt_required()
    def get(self):
        user = db.session.execute(db.select(User).where(User.email == get_jwt_identity())).scalar()

        year = request.args.get("year", datetime.date.today().year, type = int)
        month  = request.args.get("month", datetime.date.today().month, type = int)

        income = db.session.execute(db.select(func.sum(Transaction.amount))
                                    .where(Transaction.user_id == user.user_id,
                                           Transaction.type == "income",
                                           extract("year", Transaction.date) == year,
                                           extract("month", Transaction.date) == month)).scalar() or 0

        expense = db.session.execute(db.select(func.sum(Transaction.amount))
                                     .where(Transaction.user_id == user.user_id,
                                            Transaction.type == "expense",
                                            extract("year", Transaction.date) == year,
                                            extract("month", Transaction.date) == month)).scalar() or 0

        balance = income - expense

        return {
            "monthly summary" : f"{year} - {month}",
            "income" : income,
            "expense" : expense,
            "balance" : balance
        }, 200

class CategoryBreakdown(Resource):
    @swag_from({
        "tags": ["Reports"],
        "description": "Get spending breakdown by category for a given month.",
        "parameters": [
            {"name": "year", "in": "query", "type": "integer", "example": 2025, "required": False},
            {"name": "month", "in": "query", "type": "integer", "example": 9, "required": False}
        ],
        "responses": {
            200: {"description": "Category breakdown returned successfully"},
            401: {"description": "Unauthorized"}
        }
    })
    @jwt_required()
    def get(self):
        user = db.session.execute(db.select(User).where(User.email == get_jwt_identity())).scalar()

        year = request.args.get("year", datetime.date.today().year, type = int)
        month = request.args.get("month", datetime.date.today().month, type = int)

        result = db.session.execute(db.select(Transaction.category, func.sum(Transaction.amount))
                                    .where(Transaction.user_id == user.user_id,
                                           extract("year", Transaction.date) == year,
                                           extract("month", Transaction.date) == month)
                                    .group_by(Transaction.category)).all()

        breakdown = [ { "category" : r[0], "total" : r[1] } for r in result ]

        return {
            "month" : f"{year} - {month}",
            "category breakdown" : breakdown
        }, 200

# ------------------ Route Bindings ------------------
api.add_resource(Register, "/register")
api.add_resource(Login, "/login")
api.add_resource(Logout, "/logout")
api.add_resource(AddTransaction, "/add_transaction")
api.add_resource(GetTransactions, "/get_transactions")
api.add_resource(EditTransaction, "/edit_transaction/<int:transaction_id>")
api.add_resource(DeleteTransaction, "/delete_transaction/<int:transaction_id>")
api.add_resource(MonthlySummary, "/report/monthly")
api.add_resource(CategoryBreakdown, "/report/category_breakdown")
if __name__ == "__main__":
    app.run(debug = False)