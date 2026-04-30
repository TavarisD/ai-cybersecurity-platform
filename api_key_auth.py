from fastapi import Header, HTTPException, Depends
from sqlalchemy.orm import Session
from database import get_db
from models import User

def get_user_by_api_key(
    x_api_key: str = Header(None),
    db: Session = Depends(get_db)
):
    if not x_api_key:
        raise HTTPException(status_code=401, detail="API key required")

    user = db.query(User).filter(User.api_key == x_api_key).first()

    if not user:
        raise HTTPException(status_code=401, detail="Invalid API key")

    return user