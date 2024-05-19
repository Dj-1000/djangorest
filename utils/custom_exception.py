from rest_framework.exceptions import APIException

class MethodNotAllowed(APIException):
    def __init__(self, error, detail=''):
        self.error = error
        self.detail = detail
