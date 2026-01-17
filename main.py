from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from sqlalchemy.orm import Session
from typing import List
from datetime import timedelta, datetime
from jose import JWTError, jwt

from scanner import get_ssl_details, check_security_headers, scan_ports, check_security_txt
from report import generate_pdf
from database import ScanRecord, SessionLocal, init_db, User
from auth import verify_password, get_password_hash, create_access_token, SECRET_KEY, ALGORITHM

app = FastAPI(title="SecuWatch API", description="API SecuWatch V3 (Auth)", version="3.0")

init_db()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = db.query(User).filter(User.email == email).first()
    if user is None:
        raise credentials_exception
    return user

class ScanResult(BaseModel):
    domain: str
    ssl_status: dict
    headers_status: dict
    open_ports: List[int]
    security_txt: bool
    security_score: int

class HistoryItem(BaseModel):
    domain: str
    score: int
    date: datetime

class UserCreate(BaseModel):
    email: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

@app.post("/register", response_model=Token)
def register(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    hashed_password = get_password_hash(user.password)
    new_user = User(email=user.email, hashed_password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    access_token_expires = timedelta(minutes=60)
    access_token = create_access_token(
        data={"sub": new_user.email}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/token", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=60)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/scan", response_model=ScanResult)
def scan_domain(domain: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    clean_domain = domain.replace("https://", "").replace("http://", "").strip("/")
    
    ssl_res = get_ssl_details(clean_domain)
    score, headers_res = check_security_headers(f"https://{clean_domain}")
    ports_res = scan_ports(clean_domain)
    security_txt_res = check_security_txt(clean_domain)

    if ports_res:
        score -= 10 * len(ports_res)
    if security_txt_res:
        score += 10
    score = max(0, min(100, score))

    result_data = {
        "domain": clean_domain,
        "ssl_status": ssl_res,
        "headers_status": headers_res,
        "open_ports": ports_res,
        "security_txt": security_txt_res,
        "security_score": score
    }

    new_scan = ScanRecord(
        domain=clean_domain,
        score=score,
        details=result_data,
        owner_id=current_user.id
    )
    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)

    return result_data

@app.get("/history", response_model=List[HistoryItem])
def get_history(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    scans = db.query(ScanRecord).filter(ScanRecord.owner_id == current_user.id).order_by(ScanRecord.id.desc()).limit(10).all()
    return [
        HistoryItem(domain=s.domain, score=s.score, date=s.scan_date)
        for s in scans
    ]

@app.get("/report")
def get_report(domain: str):
    clean_domain = domain.replace("https://", "").replace("http://", "").strip("/")
    ssl_res = get_ssl_details(clean_domain)
    score, headers_res = check_security_headers(f"https://{clean_domain}")
    ports_res = scan_ports(clean_domain)
    security_txt_res = check_security_txt(clean_domain)
    
    if ports_res:
        score -= 10 * len(ports_res)
    if security_txt_res:
        score += 10
    score = max(0, min(100, score))

    pdf_bytes = generate_pdf(clean_domain, score, ssl_res, headers_res, ports_res, security_txt_res)
    
    return Response(content=pdf_bytes, media_type="application/pdf", headers={"Content-Disposition": f"attachment; filename=Rapport_{clean_domain}.pdf"})