from fastapi import FastAPI, HTTPException, Depends, Query
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
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional, List
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from collections import defaultdict
from time import time

# Track failed login attempts: {username: [timestamps]}
failed_login_attempts = defaultdict(list)

# Lockout config
LOCKOUT_THRESHOLD = 5  # 5 failed attempts
LOCKOUT_TIME_WINDOW = 300  # 5 minutes (in seconds)
LOCKOUT_DURATION = 600  # Lock account for 10 minutes
locked_accounts = {}  # {username: lockout_expiry_timestamp}


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


# Database setup
DATABASE_URL = "sqlite:///./finance.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT settings
SECRET_KEY = "your_secret_key_here"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days token


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
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def get_user(username: str):
    with SessionLocal() as db:
        return db.query(User).filter(User.username == username).first()


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
):
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


@app.post("/login", response_model=Token)
def login(user: UserLogin, db: Session = Depends(get_db)):
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
    period: str = Query("monthly", regex="^(monthly|yearly)$"),
    year: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
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
    return current_user


@app.put("/profile")
def update_profile(
        updates: UserProfileUpdate, db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user)):
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
