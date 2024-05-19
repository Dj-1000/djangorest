from rest_framework import views
from rest_framework.response import Response

def custom_exception_handler(exc, context):
    # Defining the customer error message here
    payload = {
        "status":"",
        "error_message":"",
        "resultCode":0
    }
    response = views.exception_handler(exc, context)
    print("Response :",response)
    # Now add the HTTP status code to the response.
    if response is not None:
        payload['status'] = response.status_code
        payload['error_message'] = exc.detail
        resp = Response(payload)
        return resp
    return response 