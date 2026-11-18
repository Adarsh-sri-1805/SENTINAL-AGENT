"""User fixtures and access control roles."""

from typing import Dict, Literal, Optional
from pydantic import BaseModel, Field

UserRole = Literal["guest", "employee", "admin"]


class User(BaseModel):
    """User profile model with role-based access attributes."""

    user_id: str = Field(..., description="Unique user identifier")
    name: str = Field(..., description="Full user name")
    email: str = Field(..., description="Email address")
    role: UserRole = Field(..., description="Access control role: guest, employee, or admin")
    department: Optional[str] = Field(default=None, description="Department name")


# In-memory fixture of mock users
MOCK_USERS: Dict[str, User] = {
    "guest": User(
        user_id="guest",
        name="Guest Visitor",
        email="visitor@external.org",
        role="guest",
        department="External",
    ),
    "user_alice": User(
        user_id="user_alice",
        name="Alice Smith",
        email="alice.smith@omnicorp.com",
        role="employee",
        department="Customer Support",
    ),
    "employee": User(
        user_id="employee",
        name="Standard Employee",
        email="employee@omnicorp.com",
        role="employee",
        department="Operations",
    ),
    "admin_bob": User(
        user_id="admin_bob",
        name="Bob Vance",
        email="bob.vance@omnicorp.com",
        role="admin",
        department="Security Engineering",
    ),
    "admin": User(
        user_id="admin",
        name="System Administrator",
        email="admin@omnicorp.com",
        role="admin",
        department="Information Security",
    ),
}


def get_user(user_id: Optional[str] = None) -> User:
    """Retrieve user profile by ID, defaulting to guest if unauthenticated or unknown."""
    if not user_id:
        return MOCK_USERS["guest"]
    return MOCK_USERS.get(user_id.lower().strip(), MOCK_USERS["guest"])

