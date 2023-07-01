from sqlalchemy import Boolean
from sqlalchemy import Column
from sqlalchemy import String, Integer
from db.base_class import Base

class User(Base):
    __tablename__ = "users"

    user_id = Column(Integer, primary_key=True, index = True, autoincrement=True)
    name = Column(String, nullable=False)
    surname = Column(String, nullable=False)
    email = Column(String, nullable=False, unique=True)
    is_active = Column(Boolean(), default=True)
    hashed_password = Column(String, nullable=False)