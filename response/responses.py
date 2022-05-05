from pydantic import BaseModel

class HTTPException(BaseModel):
    detail: str

UNAUTORIZED = {
    401: {
        "model": HTTPException,
        "description": "Authorization failed."
    }
}

USER_ALREADY_REGISTERED = {
    400: {
        "model": HTTPException,
        "description": "User with this username is already registered."
    }
}

ENTITY_NOT_FOUND = {
    404: {
        "model": HTTPException,
        "description": "Entity with specified id was not found."
    }
}

INCORRECT_MEDIA_TYPE = {
    415: {
        "model": HTTPException,
        "description": "Incorrect media type provided."
    }
}