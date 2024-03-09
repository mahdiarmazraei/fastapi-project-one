from sqlalchemy import Column, Integer, String
from database import Base
from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    
class Owner(Base):
    __tablename__ = "owners"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    shop_name = Column(String,index=True)
    first_name = Column(String,index=True)
    last_name = Column(String,index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    products = relationship("Product", back_populates="owner")

class Product(Base):
    __tablename__ = "products"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    disc = Column(String, unique=True, index=True)
    quantity = Column(Integer)
    owner_id = Column(Integer, ForeignKey("owners.id"))
    owner = relationship("Owner", back_populates="products")