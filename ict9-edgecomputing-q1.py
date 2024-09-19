import os
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr
from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean, DateTime, JSON, ForeignKey, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import random
import string
import redis
import json
from uuid import uuid4

# Load environment variables (you should use python-dotenv in a real project)
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./advertising.db")
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-here")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost")

# FastAPI app
app = FastAPI(title="Interactive Advertising Platform", version="1.0.0")

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods
    allow_headers=["*"],  # Allows all headers
)

# Database setup
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Redis setup
redis_client = redis.Redis.from_url(REDIS_URL)

# Security
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Models
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    profile = Column(JSON)
    role = Column(String, default="user")
    points = Column(Integer, default=0)

class Host(Base):
    __tablename__ = "hosts"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    api_key = Column(String, unique=True, index=True)

class Campaign(Base):
    __tablename__ = "campaigns"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    description = Column(String)
    start_date = Column(DateTime)
    end_date = Column(DateTime)
    type = Column(String)
    config = Column(JSON)
    creator_id = Column(Integer, ForeignKey("users.id"))
    host_id = Column(Integer, ForeignKey("hosts.id"))
    creator = relationship("User")
    host = relationship("Host")

class DiscountCode(Base):
    __tablename__ = "discount_codes"
    id = Column(Integer, primary_key=True, index=True)
    code = Column(String, unique=True, index=True)
    value = Column(Float)
    is_public = Column(Boolean, default=False)
    campaign_id = Column(Integer, ForeignKey("campaigns.id"))
    host_id = Column(Integer, ForeignKey("hosts.id"))

class Widget(Base):
    __tablename__ = "widgets"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    type = Column(String)
    config = Column(JSON)
    campaign_id = Column(Integer, ForeignKey("campaigns.id"))

class AnalyticsEvent(Base):
    __tablename__ = "analytics_events"
    id = Column(Integer, primary_key=True, index=True)
    event_name = Column(String, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    campaign_id = Column(Integer, ForeignKey("campaigns.id"))
    host_id = Column(Integer, ForeignKey("hosts.id"))
    event_data = Column(JSON)
    timestamp = Column(DateTime, default=datetime.utcnow)

class Leaderboard(Base):
    __tablename__ = "leaderboards"
    id = Column(Integer, primary_key=True, index=True)
    campaign_id = Column(Integer, ForeignKey("campaigns.id"))
    user_id = Column(Integer, ForeignKey("users.id"))
    score = Column(Integer)

# Create tables
Base.metadata.create_all(bind=engine)

# Pydantic models
class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str

class UserInDB(BaseModel):
    id: int
    username: str
    email: EmailStr
    role: str
    points: int

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class CampaignCreate(BaseModel):
    name: str
    description: str
    start_date: datetime
    end_date: datetime
    type: str
    config: Dict[str, Any]
    host_id: int

class DiscountCreate(BaseModel):
    value: float
    is_public: bool = False
    campaign_id: Optional[int] = None
    host_id: int

class WidgetCreate(BaseModel):
    name: str
    type: str
    config: Dict[str, Any]
    campaign_id: int

class AnalyticsEventCreate(BaseModel):
    event_name: str
    user_id: Optional[int]
    campaign_id: int
    host_id: int
    event_data: Dict[str, Any]

class LeaderboardEntry(BaseModel):
    user_id: int
    score: int

# Helper functions
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

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def generate_discount_code():
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = db.query(User).filter(User.username == token_data.username).first()
    if user is None:
        raise credentials_exception
    return user

async def get_host_by_api_key(api_key: str, db: Session = Depends(get_db)):
    host = db.query(Host).filter(Host.api_key == api_key).first()
    if not host:
        raise HTTPException(status_code=400, detail="Invalid API key")
    return host

# API Endpoints
@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/users/", response_model=UserInDB)
async def create_user(user: UserCreate, db: Session = Depends(get_db)):
    db_user = User(
        username=user.username,
        email=user.email,
        hashed_password=get_password_hash(user.password)
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return UserInDB(id=db_user.id, username=db_user.username, email=db_user.email, role=db_user.role, points=db_user.points)

@app.get("/users/me", response_model=UserInDB)
async def read_users_me(current_user: User = Depends(get_current_user)):
    return UserInDB(id=current_user.id, username=current_user.username, email=current_user.email, role=current_user.role, points=current_user.points)

@app.post("/campaigns/", response_model=dict)
async def create_campaign(campaign: CampaignCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    db_campaign = Campaign(**campaign.dict(), creator_id=current_user.id)
    db.add(db_campaign)
    db.commit()
    db.refresh(db_campaign)
    return {"id": db_campaign.id, **campaign.dict()}

@app.get("/campaigns/", response_model=List[dict])
async def list_campaigns(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    campaigns = db.query(Campaign).all()
    return [{"id": c.id, "name": c.name, "description": c.description} for c in campaigns]

@app.post("/discounts/", response_model=dict)
async def create_discount(discount: DiscountCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    code = generate_discount_code()
    db_discount = DiscountCode(code=code, **discount.dict())
    db.add(db_discount)
    db.commit()
    db.refresh(db_discount)
    return {"id": db_discount.id, "code": code, **discount.dict()}

@app.get("/discounts/public", response_model=List[dict])
async def list_public_discounts(db: Session = Depends(get_db)):
    public_discounts = db.query(DiscountCode).filter(DiscountCode.is_public == True).all()
    return [{"code": d.code, "value": d.value} for d in public_discounts]

@app.post("/widgets/", response_model=dict)
async def create_widget(widget: WidgetCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    db_widget = Widget(**widget.dict())
    db.add(db_widget)
    db.commit()
    db.refresh(db_widget)
    return {"id": db_widget.id, **widget.dict()}

@app.post("/analytics/event", response_model=dict)
async def log_event(event: AnalyticsEventCreate, db: Session = Depends(get_db)):
    db_event = AnalyticsEvent(**event.dict(), timestamp=datetime.utcnow())
    db.add(db_event)
    db.commit()
    db.refresh(db_event)
    return {"message": "Event logged successfully", "event_id": db_event.id}

@app.get("/analytics/campaign/{campaign_id}", response_model=dict)
async def get_campaign_analytics(campaign_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    events = db.query(AnalyticsEvent).filter(AnalyticsEvent.campaign_id == campaign_id).all()
    total_interactions = len(events)
    unique_users = db.query(func.count(AnalyticsEvent.user_id.distinct())).filter(AnalyticsEvent.campaign_id == campaign_id).scalar()
    return {
        "campaign_id": campaign_id,
        "total_interactions": total_interactions,
        "unique_users": unique_users,
        "event_breakdown": [{"event_name": e.event_name, "count": events.count(e.event_name)} for e in set(events)]
    }

@app.post("/leaderboard/{campaign_id}", response_model=dict)
async def update_leaderboard(campaign_id: int, entry: LeaderboardEntry, db: Session = Depends(get_db)):
    db_entry = Leaderboard(campaign_id=campaign_id, **entry.dict())
    db.add(db_entry)
    db.commit()
    db.refresh(db_entry)
    return {"message": "Leaderboard updated successfully", "entry_id": db_entry.id}

@app.get("/leaderboard/{campaign_id}", response_model=List[dict])
async def get_leaderboard(campaign_id: int, db: Session = Depends(get_db)):
    leaderboard = db.query(Leaderboard).filter(Leaderboard.campaign_id == campaign_id).order_by(Leaderboard.score.desc()).limit(10).all()
    return [{"user_id": entry.user_id, "score": entry.score} for entry in leaderboard]

@app.post("/points/{user_id}", response_model=dict)
async def award_points(user_id: int, points: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Not authorized")
    user = db.query(User).filter


user = db.query(User).filter(User.id == user_id).first()
if not user:
    raise HTTPException(status_code=404, detail="User not found")
user.points += points
db.commit()
return {"message": f"Awarded {points} points to user {user_id}", "new_total": user.points}


@app.get("/admin/stats", response_model=dict)
async def get_system_stats(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Not authorized")
    user_count = db.query(User).count()
    campaign_count = db.query(Campaign).count()
    event_count = db.query(AnalyticsEvent).count()
    return {
        "total_users": user_count,
        "total_campaigns": campaign_count,
        "total_events": event_count,
    }


@app.get("/widget/{campaign_id}", response_model=dict)
async def get_widget(campaign_id: int, db: Session = Depends(get_db)):
    widget = db.query(Widget).filter(Widget.campaign_id == campaign_id).first()
    if not widget:
        raise HTTPException(status_code=404, detail="Widget not found")
    return {
        "id": widget.id,
        "name": widget.name,
        "type": widget.type,
        "config": widget.config
    }


@app.post("/host/", response_model=dict)
async def create_host(name: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Not authorized")
    api_key = str(uuid4())
    db_host = Host(name=name, api_key=api_key)
    db.add(db_host)
    db.commit()
    db.refresh(db_host)
    return {"id": db_host.id, "name": db_host.name, "api_key": db_host.api_key}


@app.get("/host/campaigns", response_model=List[dict])
async def get_host_campaigns(api_key: str, db: Session = Depends(get_db)):
    host = await get_host_by_api_key(api_key, db)
    campaigns = db.query(Campaign).filter(Campaign.host_id == host.id).all()
    return [{"id": c.id, "name": c.name, "description": c.description} for c in campaigns]


@app.post("/game/score", response_model=dict)
async def submit_game_score(campaign_id: int, user_id: int, score: int, db: Session = Depends(get_db)):
    campaign = db.query(Campaign).filter(Campaign.id == campaign_id).first()
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")

    # Update leaderboard
    db_entry = Leaderboard(campaign_id=campaign_id, user_id=user_id, score=score)
    db.add(db_entry)

    # Award points to user
    user = db.query(User).filter(User.id == user_id).first()
    if user:
        user.points += score

    db.commit()
    return {"message": "Score submitted successfully"}


@app.get("/user/profile/{user_id}", response_model=dict)
async def get_user_profile(user_id: int, api_key: str, db: Session = Depends(get_db)):
    host = await get_host_by_api_key(api_key, db)
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "points": user.points,
        "profile": user.profile
    }


@app.post("/discount/generate", response_model=dict)
async def generate_discount(campaign_id: int, value: float, api_key: str, db: Session = Depends(get_db)):
    host = await get_host_by_api_key(api_key, db)
    code = generate_discount_code()
    db_discount = DiscountCode(code=code, value=value, campaign_id=campaign_id, host_id=host.id)
    db.add(db_discount)
    db.commit()
    db.refresh(db_discount)
    return {"code": code, "value": value}


@app.get("/realtime/campaign/{campaign_id}", response_model=dict)
async def get_realtime_campaign_stats(campaign_id: int, api_key: str, db: Session = Depends(get_db)):
    host = await get_host_by_api_key(api_key, db)
    campaign = db.query(Campaign).filter(Campaign.id == campaign_id, Campaign.host_id == host.id).first()
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")

    # Get realtime stats from Redis
    active_users = redis_client.get(f"campaign:{campaign_id}:active_users")
    recent_events = redis_client.lrange(f"campaign:{campaign_id}:events", 0, -1)

    return {
        "campaign_id": campaign_id,
        "active_users": int(active_users) if active_users else 0,
        "recent_events": [json.loads(event) for event in recent_events]
    }


# Middleware for realtime analytics
@app.middleware("http")
async def analytics_middleware(request: Request, call_next):
    response = await call_next(request)

    # Extract relevant information
    path = request.url.path
    method = request.method
    campaign_id = request.path_params.get("campaign_id")

    if campaign_id:
        # Update active users
        redis_client.incr(f"campaign:{campaign_id}:active_users")
        redis_client.expire(f"campaign:{campaign_id}:active_users", 300)  # Expire after 5 minutes

        # Log event
        event = json.dumps({"path": path, "method": method, "timestamp": datetime.utcnow().isoformat()})
        redis_client.lpush(f"campaign:{campaign_id}:events", event)
        redis_client.ltrim(f"campaign:{campaign_id}:events", 0, 99)  # Keep only last 100 events

    return response


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)