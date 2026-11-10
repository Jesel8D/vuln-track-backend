class APIError(Exception):
    def __init__(self, status: int, code: str, message: str):
        self.status = status
        self.code = code
        self.message = message


def unauthorized():
    return APIError(401, "INVALID_CREDENTIALS", "Credenciales inválidas o expiradas")
