from rest_framework.views import exception_handler
from .custom_exception import MethodNotAllowed
from rest_framework.response import Response
def custom_exception_handler(exc, context):
    # Call REST framework's default exception handler first,
    # to get the standard error response.
    payload = {
        "status":"",
        "error_message":"",
        "resultCode":0
    }
    response = exception_handler(exc, context)
    print("Response :",response)
    print("View generated from :",context["view"])
    # Now add the HTTP status code to the response.
    if response is not None:
        payload['status'] = response.status_code
        payload['error_message'] = exc.detail
        resp = Response(payload)
    return response 