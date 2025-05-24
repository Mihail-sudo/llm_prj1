from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional


@dataclass
class UserDTO:
    id: str
    name: str
    username: str
    hashed_password: str


class UserRepository(ABC):

    @abstractmethod
    async def get_one(self, user_id: str) -> Optional[UserDTO]:
        raise NotImplementedError

    @abstractmethod
    async def get_all(self, **filters) -> list[UserDTO]:
        raise NotImplementedError

    @abstractmethod
    async def add_one(self, data: UserDTO) -> UserDTO:
        raise NotImplementedError
    

class BaseAuthService(ABC):

    @abstractmethod
    async def login(self, username: str, password: str) -> Optional[UserDTO]:
        raise NotImplementedError

    @abstractmethod
    async def register(self, name: str, username: str, password: str) -> UserDTO:
        raise NotImplementedError
    
    @abstractmethod
    async def get_user_by_id(self, user_id: str) -> Optional[UserDTO]:
        raise NotImplementedError
    