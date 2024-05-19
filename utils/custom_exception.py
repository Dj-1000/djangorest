from rest_framework.exceptions import APIException

class ValidationError(APIException):
    def __init__(self, detail=''):
        self.detail = detail
