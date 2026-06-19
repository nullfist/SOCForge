import uuid
from sqlalchemy import Column, String, Boolean, DateTime, Integer, JSON, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from src.app.db.session import Base

def generate_uuid():
    return str(uuid.uuid4())

class Company(Base):
    __tablename__ = "companies"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    name = Column(String(100), nullable=False)
    industry = Column(String(50), nullable=False)
    domain = Column(String(100), nullable=False)
    
    departments = relationship("Department", back_populates="company", cascade="all, delete-orphan")
    hosts = relationship("Host", back_populates="company", cascade="all, delete-orphan")
    simulation_runs = relationship("SimulationRun", back_populates="company", cascade="all, delete-orphan")

class Department(Base):
    __tablename__ = "departments"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    company_id = Column(String(36), ForeignKey("companies.id"), nullable=False)
    name = Column(String(100), nullable=False)
    code = Column(String(10), nullable=False)
    
    company = relationship("Company", back_populates="departments")
    employees = relationship("Employee", back_populates="department", cascade="all, delete-orphan")

class Employee(Base):
    __tablename__ = "employees"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    department_id = Column(String(36), ForeignKey("departments.id"), nullable=False)
    first_name = Column(String(50), nullable=False)
    last_name = Column(String(50), nullable=False)
    username = Column(String(50), nullable=False)
    email = Column(String(100), nullable=False)
    role_profile = Column(String(50), nullable=False)  # Admin, HR, Finance, IT, User, etc.
    
    department = relationship("Department", back_populates="employees")

class Host(Base):
    __tablename__ = "hosts"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    company_id = Column(String(36), ForeignKey("companies.id"), nullable=False)
    hostname = Column(String(100), nullable=False)
    ip_address = Column(String(50), nullable=False)
    os_type = Column(String(20), nullable=False)  # Windows, Linux, Mac, Cloud
    role = Column(String(50), nullable=False)      # DomainController, Workstation, FileServer, MailServer
    has_sysmon = Column(Boolean, default=True)
    
    company = relationship("Company", back_populates="hosts")

class SimulationScenario(Base):
    __tablename__ = "simulation_scenarios"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    name = Column(String(100), nullable=False, unique=True)
    description = Column(String(255), nullable=False)
    category = Column(String(50), nullable=False)  # Phishing, Ransomware, APT, etc.
    stages = Column(JSON, nullable=False)          # Details of execution steps

class SimulationRun(Base):
    __tablename__ = "simulation_runs"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    scenario_id = Column(String(36), ForeignKey("simulation_scenarios.id"), nullable=True)
    company_id = Column(String(36), ForeignKey("companies.id"), nullable=False)
    status = Column(String(20), nullable=False, default="PENDING")  # PENDING, RUNNING, COMPLETED, PAUSED
    start_time = Column(DateTime, nullable=False)
    end_time = Column(DateTime, nullable=False)
    speed_multiplier = Column(Integer, default=1)
    
    company = relationship("Company", back_populates="simulation_runs")
    alerts = relationship("Alert", back_populates="simulation_run", cascade="all, delete-orphan")

class Alert(Base):
    __tablename__ = "alerts"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    simulation_run_id = Column(String(36), ForeignKey("simulation_runs.id"), nullable=False)
    rule_name = Column(String(100), nullable=False)
    severity = Column(String(20), nullable=False)  # LOW, MEDIUM, HIGH, CRITICAL
    host = Column(String(100), nullable=True)
    username = Column(String(100), nullable=True)
    mitre_mapping = Column(JSON, nullable=True)     # Technique ID, Name, Tactic
    description = Column(String(255), nullable=False)
    timestamp = Column(DateTime, nullable=False)
    
    simulation_run = relationship("SimulationRun", back_populates="alerts")
