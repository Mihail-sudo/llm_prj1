from typing import Optional
from uuid import uuid4
from passlib.context import CryptContext
from .auth_abs import BaseAuthService, UserDTO, UserRepository


class AuthService(BaseAuthService):

    def __init__(self, user_repository: UserRepository):
        self._user_repository = user_repository

    async def login(self, username: str, password: str) -> Optional[UserDTO]:
        users = await self._user_repository.get_all(username=username)
        for user in users:
            if self._verify_password(password, user.hashed_password):
                return user
        return None

    async def register(self, name: str, username: str, password: str) -> UserDTO:
        user_id = str(uuid4())
        hashed_password = self._hash_password(password)
        user = UserDTO(id=user_id, name=name, username=username, hashed_password=hashed_password)
        await self._user_repository.add_one(user)
        return user

    async def get_user_by_id(self, user_id: str) -> Optional[UserDTO]:
        user = await self._user_repository.get_one(user_id)
        return user

    @staticmethod
    def _hash_password(password: str) -> str:
        ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
        hashed_password = ctx.hash(password)
        return hashed_password

    @staticmethod
    def _verify_password(password: str, hashed_password: str) -> bool:
        ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
        is_verified = ctx.verify(password, hashed_password)
        return is_verified
    

class InMemoryUserRepository(UserRepository):

    _instance: Optional["InMemoryUserRepository"] = None
    _initialized: bool = False

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if not self._initialized:
            self._users: list[UserDTO] = []
            self._initialized = True

    def get_one(self, user_id):
        for user in self._users:
            if user.id == user_id:
                return user
        return None
    
    def get_all(self, **filters):
        users = []
        for user in self._users:
            is_passed = True
            for filter_key, filter_value in filters.items():
                if getattr(user, filter_key) != filter_value:
                    is_passed = False
            if is_passed:
                users.append(user)
        return users
    
    def add_one(self, data):
        user = self.get_one(data.id)
        if user:
            return 'this user already exist'
        self._users.append(data)
        return data