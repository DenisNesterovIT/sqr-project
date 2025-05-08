from fastapi import FastAPI, HTTPException, Depends, Query, Request
from pydantic import BaseModel, EmailStr
from sqlalchemy import (
    Column,
    Integer,
    String,
    Float,
    DateTime,
    ForeignKey,
    create_engine,
)
from sqlalchemy.orm import (
    sessionmaker,
    Session,
    relationship,
    declarative_base
)
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional, List
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from collections import defaultdict
from time import time
from prometheus_fastapi_instrumentator import Instrumentator
import sentry_sdk
import logging
import os
from dotenv import load_dotenv
load_dotenv()


sentry_sdk.init(
    dsn=os.getenv("SENTRY_DSN"),
    traces_sample_rate=1.0,
)

failed_login_attempts = defaultdict(list)

LOCKOUT_THRESHOLD = 5
LOCKOUT_TIME_WINDOW = 300
LOCKOUT_DURATION = 600
locked_accounts = {}


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


DATABASE_URL = "sqlite:///./finance.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


SECRET_KEY = os.environ.get("SECRET_KEY", "fallback_dev_key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7


app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    records = relationship("Record", back_populates="owner")
    categories = relationship("Category", back_populates="owner")


class Record(Base):
    __tablename__ = "records"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    amount = Column(Float, nullable=False)
    type = Column(String, nullable=False)
    category = Column(String, nullable=False)
    date = Column(DateTime, default=datetime.utcnow)
    description = Column(String, nullable=True)
    owner = relationship("User", back_populates="records")


class Category(Base):
    __tablename__ = "categories"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    name = Column(String, nullable=False)

    owner = relationship("User", back_populates="categories")


Base.metadata.create_all(bind=engine)


class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str


class UserLogin(BaseModel):
    username: str
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str


class RecordCreate(BaseModel):
    amount: float
    type: str
    category: str
    date: Optional[datetime] = None
    description: Optional[str] = None


class RecordUpdate(BaseModel):
    amount: Optional[float] = None
    type: Optional[str] = None
    category: Optional[str] = None
    date: Optional[datetime] = None
    description: Optional[str] = None


class CategoryCreate(BaseModel):
    name: str


class CategoryOut(BaseModel):
    id: int
    name: str

    class Config:
        orm_mode = True


class DashboardOut(BaseModel):
    total_income: float
    total_expense: float
    balance: float
    records: List[RecordCreate]


class UserProfileOut(BaseModel):
    id: int
    username: str
    email: EmailStr


class UserProfileUpdate(BaseModel):
    username: Optional[str]
    email: Optional[EmailStr]
    password: Optional[str]


def get_db():
    """
    Yield a new database session for dependency injection.

    Yields:
        Session: SQLAlchemy database session.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def verify_password(plain_password, hashed_password):
    """
    Verify that a plain password matches the hashed password.

    Args:
        plain_password (str): Raw password input.
        hashed_password (str): Hashed password from DB.

    Returns:
        bool: True if password matches, False otherwise.
    """
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: timedelta = None):
    """
    Create a JWT access token with optional expiry.

    Args:
        data (dict): Payload data to encode.
        expires_delta (timedelta, optional): Expiry time delta.

    Returns:
        str: Encoded JWT token string.
    """
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def get_user(username: str):
    """
    Retrieve a user by username.

    Args:
        username (str): Username to search for.

    Returns:
        User or None: User object if found, else None.
    """
    with SessionLocal() as db:
        return db.query(User).filter(User.username == username).first()


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
):
    """
    Retrieve the authenticated user based on JWT token.

    Args:
        token (str): JWT access token.
        db (Session): Database session.

    Returns:
        User: Authenticated user object.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401,
                                detail="Invalid token payload")
    except JWTError:
        raise HTTPException(status_code=401,
                            detail="Invalid or expired token")

    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise HTTPException(status_code=401,
                            detail="User not found")
    return user


def get_token(authorization: str = Depends(lambda: None)):
    if authorization and authorization.startswith("Bearer "):
        return authorization[7:]
    raise HTTPException(status_code=401,
                        detail="Invalid authorization header")


@app.post("/register")
def register(user: UserCreate, db: Session = Depends(get_db)):
    """
    Register a new user.

    Checks for existing username or email
    before creating a new user account.

    Args:
        user (UserCreate): User signup details.
        db (Session): Database session.

    Returns:
        dict: Success message and newly created user ID.
    """
    existing_user = db.query(User).filter(
        (User.username == user.username)
        | (User.email == user.email)).first()
    if existing_user:
        raise HTTPException(status_code=400,
                            detail="Username or email already registered.")

    hashed_password = get_password_hash(user.password)

    new_user = User(
        username=user.username,
        email=user.email,
        hashed_password=hashed_password
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {"message": "User registered successfully!",
            "user_id": new_user.id}


Instrumentator().instrument(app).expose(app)
error_count = 0
total_requests = 0


@app.middleware("http")
async def count_errors_and_requests(request: Request, call_next):
    global error_count, total_requests
    total_requests += 1
    try:
        response = await call_next(request)
        if response.status_code >= 400:
            error_count += 1
        return response
    except Exception as e:
        error_count += 1
        logging.error(f"Unhandled error: {e}")
        raise


@app.get("/metrics/errors")
def error_metrics():
    """
    Get current error metrics including error rate percentage.

    Returns:
        dict: Error rate, error count, and total request count.
    """
    if total_requests == 0:
        error_rate = 0
    else:
        error_rate = (error_count / total_requests) * 100
    return {
        "error_rate_percent": error_rate,
        "error_count": error_count,
        "total_requests": total_requests
    }


@app.post("/login", response_model=Token)
def login(user: UserLogin, db: Session = Depends(get_db)):
    """
    Authenticate user and issue a JWT token.

    Implements lockout after multiple failed
    attempts within a time window.

    Args:
        user (UserLogin): Login credentials.
        db (Session): Database session.

    Returns:
        Token: JWT access token upon successful login.
    """
    username = user.username
    current_time = time()

    if (
        username in locked_accounts
        and locked_accounts[username] > current_time
    ):
        lockout_time_remaining = int(locked_accounts[username] - current_time)
        raise HTTPException(
            status_code=403,
            detail=f"Account locked due to multiple failed logins. "
            f"Try again in {lockout_time_remaining} seconds."
        )
    elif username in locked_accounts:
        del locked_accounts[username]

    db_user = db.query(User).filter(
        User.username == user.username
    ).first()
    if not db_user or not verify_password(
        user.password,
        db_user.hashed_password
    ):

        failed_login_attempts[username].append(current_time)

        attempts = [
            t
            for t in failed_login_attempts[username]
            if current_time - t <= LOCKOUT_TIME_WINDOW
        ]

        failed_login_attempts[username] = attempts

        if len(attempts) >= LOCKOUT_THRESHOLD:
            locked_accounts[username] = current_time + LOCKOUT_DURATION
            # Optional: Send user notification here (email/SMS)
            raise HTTPException(
                status_code=403,
                detail="Account locked due to multiple failed login attempts. "
                "Please try again later."
            )

        raise HTTPException(status_code=401,
                            detail="Invalid username or password")

    failed_login_attempts.pop(username, None)

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": db_user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/records")
def create_record(
        record: RecordCreate, db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user)):
    """
    Create a financial record (income or expense) for the authenticated user.

    Args:
        record (RecordCreate): Record data.
        db (Session): Database session.
        current_user (User): Authenticated user.

    Returns:
        dict: Success message and record ID.
    """
    new_record = Record(
        user_id=current_user.id,
        amount=record.amount,
        type=record.type,
        category=record.category,
        date=record.date or datetime.utcnow(),
        description=record.description
    )
    db.add(new_record)
    db.commit()
    db.refresh(new_record)

    return {"message": "Record created successfully!",
            "record_id": new_record.id}


@app.put("/records/{record_id}")
def update_record(
        record_id: int,
        updates: RecordUpdate, db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user)):
    """
    Update an existing record belonging to the authenticated user.

    Args:
        record_id (int): ID of the record to update.
        updates (RecordUpdate): Fields to update.
        db (Session): Database session.
        current_user (User): Authenticated user.

    Returns:
        dict: Success message and updated record ID.
    """
    record = db.query(Record).filter(
        Record.id == record_id,
        Record.user_id == current_user.id
    ).first()
    if not record:
        raise HTTPException(status_code=404,
                            detail="Record not found")

    for var, value in vars(updates).items():
        if value is not None:
            setattr(record, var, value)

    db.commit()
    db.refresh(record)

    return {"message": "Record updated successfully!",
            "record_id": record.id}


@app.delete("/records/{record_id}")
def delete_record(
        record_id: int, db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user)):
    """
    Delete a record by ID belonging to the authenticated user.

    Args:
        record_id (int): ID of the record to delete.
        db (Session): Database session.
        current_user (User): Authenticated user.

    Returns:
        dict: Success message.
    """
    record = db.query(Record).filter(
        Record.id == record_id,
        Record.user_id == current_user.id
    ).first()
    if not record:
        raise HTTPException(status_code=404,
                            detail="Record not found")

    db.delete(record)
    db.commit()

    return {"message": "Record deleted successfully!"}


@app.post("/categories", response_model=CategoryOut)
def create_category(category: CategoryCreate,
                    db: Session = Depends(get_db),
                    current_user: User = Depends(get_current_user)):
    """
    Create a new category for organizing records.

    Args:
        category (CategoryCreate): Category details.
        db (Session): Database session.
        current_user (User): Authenticated user.

    Returns:
        CategoryOut: Created category object.
    """
    new_category = Category(user_id=current_user.id,
                            name=category.name)
    db.add(new_category)
    db.commit()
    db.refresh(new_category)
    return new_category


@app.get("/categories", response_model=List[CategoryOut])
def get_categories(
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user)):
    """
    Retrieve all categories belonging to the authenticated user.

    Args:
        db (Session): Database session.
        current_user (User): Authenticated user.

    Returns:
        List[CategoryOut]: List of user categories.
    """

    categories = db.query(Category).filter(
        Category.user_id ==
        current_user.id
    ).all()
    return categories


@app.get("/dashboard")
def get_dashboard(
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get dashboard summary including total income,
    expenses, balance, and records.

    Args:
        start_date (datetime, optional): Filter
            records starting from this date.
        end_date (datetime, optional): Filter records up to this date.
        db (Session): Database session.
        current_user (User): Authenticated user.

    Returns:
        dict: Summary with totals and records list.
    """
    query = db.query(Record).filter(Record.user_id == current_user.id)

    if start_date:
        query = query.filter(Record.date >= start_date)
    if end_date:
        query = query.filter(Record.date <= end_date)

    records = query.all()

    total_income = sum(
        r.amount
        for r in records
        if r.type.lower() == "income"
    )
    total_expense = sum(
        r.amount
        for r in records
        if r.type.lower() == "expense"
    )
    balance = total_income - total_expense

    record_list = [
        {
            "id": r.id,
            "amount": r.amount,
            "type": r.type,
            "category": r.category,
            "date": r.date,
            "description": r.description
        }
        for r in records
    ]

    return {
        "total_income": total_income,
        "total_expense": total_expense,
        "balance": balance,
        "records": record_list
    }


@app.get("/report")
def get_report(
    period: str = Query("monthly", pattern="^(monthly|yearly)$"),
    year: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get a financial report grouped by month or year.

    Args:
        period (str): Report period - 'monthly' or 'yearly'.
        year (int, optional): Year filter for the report.
        db (Session): Database session.
        current_user (User): Authenticated user.

    Returns:
        dict: Report summary with income, expenses, and balance.
    """
    query = db.query(Record).filter(Record.user_id == current_user.id)

    if year:
        query = query.filter(
            Record.date >= datetime(year, 1, 1),
            Record.date <= datetime(year, 12, 31)
        )

    records = query.all()

    summary = {}

    for r in records:
        if period == "monthly":
            key = r.date.strftime("%Y-%m")
        else:
            key = str(r.date.year)

        if key not in summary:
            summary[key] = {"income": 0.0, "expense": 0.0}

        if r.type.lower() == "income":
            summary[key]["income"] += r.amount
        elif r.type.lower() == "expense":
            summary[key]["expense"] += r.amount

    for key, values in summary.items():
        values["balance"] = values["income"] - values["expense"]

    return summary


@app.get("/profile", response_model=UserProfileOut)
def get_profile(current_user: User = Depends(get_current_user)):
    """
    Get authenticated user's profile information.

    Args:
        current_user (User): Authenticated user.

    Returns:
        UserProfileOut: User profile data.
    """
    return current_user


@app.put("/profile")
def update_profile(
        updates: UserProfileUpdate, db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user)):
    """
    Update user profile fields: username, email, and password.

    Args:
        updates (UserProfileUpdate): Fields to update.
        db (Session): Database session.
        current_user (User): Authenticated user.

    Returns:
        dict: Success message.
    """
    if updates.username:
        existing = db.query(User).filter(
            User.username == updates.username,
            User.id != current_user.id
        ).first()
        if existing:
            raise HTTPException(status_code=400,
                                detail="Username already in use.")
        current_user.username = updates.username

    if updates.email:
        existing = db.query(User).filter(
            User.email == updates.email,
            User.id != current_user.id
        ).first()
        if existing:
            raise HTTPException(status_code=400,
                                detail="Email already in use.")
        current_user.email = updates.email

    if updates.password:
        current_user.hashed_password = get_password_hash(updates.password)

    db.commit()
    db.refresh(current_user)

    return {"message": "Profile updated successfully."}
