import email
import random
from datetime import datetime, timedelta
import re
import json
from tokenize import group
from utils.otp.otpsender import generate_otp

from django.shortcuts import render
from django.db.utils import IntegrityError
from rest_framework_simplejwt.views import TokenRefreshView
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from django.contrib.auth.hashers import make_password,check_password
from django.utils import timezone
from django.db.models import Q
from rest_framework.parsers import MultiPartParser, JSONParser,FormParser
from django.contrib.auth.models import Group
from rest_framework.generics import ListAPIView
from django.db.models import BooleanField, Case, When

from .serializers import(
        CustomTokenRefreshSerializer, 
        RegisterSerializer,
        FCMDeviceSerializer,
        AdminListingSerializer,
        DriverSerializer,
    )
from tenant.serializers import OrganizationSerializer
from .models import (
        OtpRecord, 
        UserProfile,
        DriverCertificate, 
        ProfileImage,
        MobileOtpRecord
    )
from tenant.models import Organization, UserOrganization, ActivatedPlan
from tenant.serializers import ActivatedPlanSerializer
from utils.exceptions.custom_exception import ValidationError
from utils.otp.otpsender import send_mobile_otp, send_otp
from utils.decorators.allow_users import allowed_users
from tenant.utils import (
        get_schema_name_by_request, 
        set_tenant_schema_by_name,
        set_tenant_schema_for_request
    )
from utils.reponse.renders import CustomJSONRenderer
from utils.email.new_registeration import (create_company_registration_email,
                                           send_company_congratulations_email,
                                           send_driver_login_email)

class CustomTokenRefreshView(TokenRefreshView):
    serializer_class = CustomTokenRefreshSerializer

class SendMobileOTP(APIView):
    permission_classes = (AllowAny,)
    def post(self, request):
        user_mobile = request.data.get('mobile_no')
        country_code = request.data.get('country_code', '+91')
        is_registration = request.data.get('is_registration', 'false')
        is_registration = json.loads(is_registration)
        
        if not user_mobile:
            raise ValidationError("Please enter a valid  mobile no")
        if not country_code:
            raise ValidationError("Please enter country code")
        
        numbers = random.sample(range(10), 6)
        otp = ''.join(map(str, numbers))
        if not is_registration:
            user = UserProfile.objects.filter(phone_number=user_mobile).first()
            if user:
                if user.country_code !=country_code:
                    raise ValidationError('Sorry, The country code entered for the mobile no is invalid.')
                user_mobile= user.phone_number
                user_name = user.username
                try:
                    user_mobile = country_code+ ' ' + user_mobile
                    result = send_mobile_otp(user_mobile, otp)
                    if result:
                        otp_rec, created = OtpRecord.objects.get_or_create(user=user)
                        otp_rec.otp = otp 
                        otp_rec.save()
                        resp = {
                            'resultCode': '1',
                            'message': ' Login OTP has been sent on your registered mobile',
                            'result': {}
                            } 
                        return Response(resp, status=status.HTTP_200_OK)
                    else:
                        resp = {
                            'resultCode': '0',
                            'message': 'Something went wrong please try again',
                            'result': {}

                            }     
                        return Response(resp, status=status.HTTP_200_OK)
                except Exception as ex:
                    print("error>>>", ex, flush=True)
                    resp = {
                            'resultCode': '0',
                            'message': 'Unable to connect with sms gateway',
                            'result': {}

                            }     
                    return Response(resp, status=status.HTTP_200_OK)
            
            raise ValidationError('Sorry, You are not registered with this mobile no')
        
        else:
            try:
                user_mobile = country_code+ ' ' + user_mobile
                result = send_mobile_otp(user_mobile, otp)
                if result:
                    otp_rec, created = MobileOtpRecord.objects.get_or_create(mobile_no=user_mobile)
                    otp_rec.otp = otp 
                    otp_rec.save()
                    resp = {
                        'resultCode': '1',
                        'message': 'Mobile verification OTP has been sent on your entered mobile',
                        'result': {}
                        } 
                    return Response(resp, status=status.HTTP_200_OK)
                else:
                    resp = {
                        'resultCode': '0',
                        'message': 'Something went wrong please try again',
                        'result': {}

                        }     
                    return Response(resp, status=status.HTTP_200_OK)
            except Exception as ex:
                print("error>>>", ex, flush=True)
                resp = {
                        'resultCode': '0',
                        'message': 'Invalid mobile no or insufficient balance in sms gateway',
                        'result': {}

                        }     
                return Response(resp, status=status.HTTP_200_OK)
        #return Response(resp, status=status.HTTP_200_OK)

class SendResetOTP(APIView):
    permission_classes = (AllowAny,)
    def post(self, request):
        user_email = request.data.get('email')
        country_code = request.data.get('country_code', '+91')
        reg = '^(\+\d{1,3}[- ]?)?\d{10}$'
        numbers = random.sample(range(10), 6)
        otp = ''.join(map(str, numbers))
        if re.match(reg, user_email):
            mobile_no = user_email
            user = UserProfile.objects.filter(phone_number=mobile_no).first()
            if not user:
                raise ValidationError("Invalid mobile")
            user_mobile = country_code+ ' ' + mobile_no
            mid = send_mobile_otp(user_mobile, otp)
            if mid:
                otp_rec, created = OtpRecord.objects.get_or_create(user=user)
                otp_rec.otp = otp 
                otp_rec.save()
                resp = {
                    'resultCode': '1',
                    'message': 'OPT for reset password has been sent on your registered mobile no',
                    'result': {}
                    }
                return Response(resp, status=status.HTTP_200_OK)
            
            resp = {
                    'resultCode': '0',
                    'message': 'Something went wrong please try again',
                    'result': {}

                    }     
            return Response(resp, status=status.HTTP_200_OK)

        else:
            user = UserProfile.objects.filter(email=user_email).first()
            if user:
                user_email= user.email
                user_name = user.username
                result = send_otp(user_name, user_email, otp)
                if result == 1:
                    otp_rec, created = OtpRecord.objects.get_or_create(user=user)
                    otp_rec.otp = otp 
                    otp_rec.save()
                    resp = {
                        'resultCode': '1',
                        'message': 'OPT for reset password has been sent on your registered email id',
                        'result': {}
                        } 
                    return Response(resp, status=status.HTTP_200_OK)
                else:
                    resp = {
                        'resultCode': '0',
                        'message': 'Something went wrong please try again',
                        'result': {}

                        }     
                    return Response(resp, status=status.HTTP_200_OK)
            resp = {
                'resultCode': '0',
                'message': 'Invalid email address or phone no',
                'result': {}
                }        
            return Response(resp, status=status.HTTP_200_OK)


class VerifyOTP(APIView):
    permission_classes = (AllowAny,)

    def post(self, request):
        user_email = request.data.get('email')
        user_otp = request.data.get('otp')
        user = None
        if user_email:
            queryset = OtpRecord.objects.filter(Q(user__email=user_email) | Q(user__phone_number=user_email))
            if queryset:
                user = queryset.filter(otp=user_otp).first()
        if user:
            otp_time_stamp = user.time_stamp
            # current_time_stamp = datetime.now()
            current_time_stamp = timezone.now()
            time_diff = current_time_stamp - otp_time_stamp
            otp_age = time_diff.total_seconds()//60
            if otp_age<=2:
                resp = {
                        'resultCode': '1', 
                        'result' : [],
                        'message': 'OTP has been successfully verified' 
                        }
                return Response(resp, status=status.HTTP_200_OK)
            
            resp = {
                    'resultCode': '0',
                    'message': 'Sorry, OTP has been expired',
                    'result': {}
                }
            return Response(resp, status=status.HTTP_200_OK)    
        
        resp = {
            'resultCode': '0',
            'message': 'Invalid OTP please try again',
            'result': {}
            }
        return Response(resp, status=status.HTTP_200_OK)    
    
class ResetPassword(APIView):
    permission_classes = (AllowAny,)
    def put(self, request):
        user_email = request.data.get('email')
        new_password  = request.data.get('new_password')
        new_password = make_password(new_password)
        user = UserProfile.objects.filter(Q(email=user_email)|Q(phone_number=user_email)).first()
        if user:
            user.is_first_login=False
            user.password = new_password
            user.save()
            resp = {
                    'resultCode': '1',
                    'message': 'Password has been successfully changed, You can Login with new password',
                    'result': {}
                }
            
            return Response(resp, status=status.HTTP_200_OK)
        
        resp = {
            'resultCode': '0',
            'message': 'Sorry, This user account does not exists',
            'result': {}
            }
        
        return Response(resp, status=status.HTTP_200_OK)  

class ChangePassword(APIView):
    def put(self, request):
        pk=request.user.id
        old_password = request.data.get('old_password')
        new_password = request.data.get('new_password')
        if not old_password:
            raise ValidationError("Old password can't be blank")
        if not new_password:
            raise ValidationError("New password can't be blank")
        user=UserProfile.objects.filter(id=pk).first()
        # Check if old password matches
        if not check_password(old_password, user.password):
            resp = {
                'resultCode': '0',
                'message': 'Old password is incorrect.',
                'result': {}
            }
            return Response(resp, status=status.HTTP_200_OK)
        
        # Check if old password and new password are the same
        if old_password == new_password:
            resp = {
                'resultCode': '0',
                'message': 'Your new password must be different from your old password.',
                'result': {}
            }
            return Response(resp, status=status.HTTP_200_OK)

        # Update password
        user.set_password(new_password)
        user.save()

        resp = {
            'resultCode': '1',
            'message': 'Password has been successfully changed.',
            'result': {}
        }

        return Response(resp, status=status.HTTP_200_OK)

class UserProfileView(APIView):
    @allowed_users(["Super Admin", 'Organization Admin', 'Driver', 'Customer', 'Head Driver','Associate Driver'])
    def get(self, request):
        pk = request.user.id
        if pk:
            user = UserProfile.objects.filter(id=pk).first()
            if not user:
                raise ValidationError("Login again to view profile")
            # filter group for getting organization details 
            checkgroup=Group.objects.filter(user=user).first()
            if checkgroup.name=='Organization Admin':
                """ get  to request current schema """
                schema_name=get_schema_name_by_request(request)

                """ switching  to public schema """
                set_tenant_schema_by_name('public')

                org = Organization.objects.filter(schema_name=schema_name).first()
                activated_plan = ActivatedPlan.objects.filter(company__id=org.id).last()
                activated_serializer = ActivatedPlanSerializer(activated_plan)
                global_activated_serializer = activated_serializer.data

                """ swiching back to respective schema """
                set_tenant_schema_for_request(request)

                admin_user = UserProfile.objects.filter(id=pk).first()
                user_ser = RegisterSerializer(admin_user)
                user_deatils=user_ser.data

                resp = {
                    "result": {"organization": global_activated_serializer,
                                "admin": user_deatils},
                    "resultCode": "1",
                    "resultDescription": "Organization with admin data"
                }
                return Response(resp, status=status.HTTP_200_OK)

            else:
                serializer = RegisterSerializer(user)        
                resp = {
                "result": serializer.data,
                "resultCode": "1",
                "resultDescription": "User profile datails"
                }
                return Response(resp, status=status.HTTP_200_OK)
        raise ValidationError("Login again to view profile")
    
    @allowed_users(["Super Admin", 'Organization Admin','Driver', 'Customer', 'Head Driver','Associate Driver'])
    def put(self, request, pk=None):
        """
        Method to update user data by admin or account holder itself.
        """
        payload = request.data
        user = UserProfile.objects.filter(pk=pk).first()
        if not user:
            raise ValidationError("Sorry, requested user not found")
        first_name = payload.get('first_name')
        last_name = payload.get('last_name')
        phone_number = payload.get('phone_number')
        contry_code = payload.get('country_code')
        prof_image = payload.get('profile_image')
        if prof_image:
            ProfileImage.objects.filter(user__id=pk).delete()
            ProfileImage.objects.create(user=user, image=prof_image)
        
        if first_name is not None and first_name != '':
            if_first_name_special_char = re.findall("[^a-zA-Z ]", first_name)
            if if_first_name_special_char:
                raise ValidationError("Name can not have special characters")
        
        if last_name is not None:
            if_last_name_special_char = re.findall("[^a-zA-Z ]", last_name)
            if if_last_name_special_char:
                raise ValidationError("Last name can not have special characters")
        if phone_number is not None:
            if_phone_number_special_char = re.findall("[^0-9]", phone_number)
            if if_phone_number_special_char:
                raise ValidationError("Phone number can not have special characters")
        user.first_name = first_name
        user.last_name = last_name
        user.phone_number = phone_number
        user.country_code = contry_code
        user.save()
        seriliser = RegisterSerializer(user)
        resp = {
        'results': seriliser.data,
        'resultCode': '1',
        'resultDescription': "Your profile has been updated successfully",
        }
        return Response(resp, status=status.HTTP_200_OK)
    
    @allowed_users(['Super Admin','Organization Admin'])
    def post(self,request):
        '''
        Method to add a new organization admin
        '''
        payload = request.data
        first_name = payload.get('first_name')
        last_name = payload.get('last_name')
        admin_email = payload.get('email')
        phone_number = payload.get('phone_number')
        # password = payload.get('password')
        country_code = payload.get('country_code')
        prof_image = payload.get('profile_image')
        if not admin_email :
            raise ValidationError("Email is required")
        
        if not phone_number:
            raise ValidationError("Phone number is required")

        if country_code is not None:
            country_code = country_code
            
        if phone_number is not None and phone_number != "":
            if_phn_special_char = re.findall("[^0-9]", phone_number)
            if if_phn_special_char:
                raise ValidationError("Invalid phone no")
            
        if not first_name:
            raise ValidationError("Please enter admin name")
        
        pattern = r"^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{6,}$"

        '''Uncomment before deploying'''
        # if not re.match(pattern,password):
        #     raise ValidationError('Invalid password')
       
        password=generate_otp()
        mailpassword=password
        password = make_password(password)

        '''getting the no of admin available from public'''
        schema = get_schema_name_by_request(request)
        
        set_tenant_schema_by_name('public')    
        
        org = Organization.objects.filter(schema_name = schema).first()
        activated_plan = ActivatedPlan.objects.filter(company__id=org.id).first()
        activated_serializer = ActivatedPlanSerializer(activated_plan) 
        admin_remain = activated_serializer.data['current_plan']['admin_remaining']   

        '''switching to respective schema'''
        set_tenant_schema_for_request(request)
        group = Group.objects.filter(name='Organization Admin').first()
        if admin_remain<=0:
            raise ValidationError('No more admin can be added')
        
        '''adding the admin details into UserProfile'''
        admin_user = UserProfile()
        admin_user.email = admin_email
        admin_user.username=admin_email
        admin_user.first_name = first_name
        if last_name is not None:
            admin_user.last_name = last_name
        admin_user.phone_number = phone_number
        admin_user.password = password
        if prof_image:
            ProfileImage.objects.create(user=admin_user, image=prof_image)
        if country_code:
            admin_user.country_code = country_code
        admin_user.is_active = True
        admin_user.is_superuser = True
        admin_user.is_staff = True 
        seri = RegisterSerializer(request.user)

        try:
            admin_user.save()
        except IntegrityError as ex:
            raise ValidationError("User already registered with this email address")
        if group:
            group.user_set.add(admin_user)
        '''switching to public schema'''  
        set_tenant_schema_by_name('public')
        if request.user is None:
            raise ValidationError("Resquest failed : request user doesn't exists")
        another_org_admin = UserOrganization.objects.filter(email = request.user.email).first()
        user_org = UserOrganization()
        user_org.phone_number = phone_number
        
        if UserOrganization.objects.filter(Q(email = admin_email) & Q(organization_id = another_org_admin.id)):
            raise ValidationError("User already registered with current organization")
        user_org.email = admin_email
        user_org.organization = another_org_admin.organization
        if country_code:
            user_org.country_code = country_code
        user_org.save()
        if user_org:
            registeration_mail=create_company_registration_email(organization_name=' Realtime Trac ',company_link=org.domain_url,
                                                 password= mailpassword,plan_name= activated_plan.plan.title,plan_description=activated_plan.plan.desecription
                                                        ,plan_price=activated_plan.plan.price,admin_email=admin_user.email)
            print(registeration_mail,"registermail")
            if registeration_mail==1:
                org.is_login_mail_sent=True
                org.save()
        
        '''switching to respective schema'''
        set_tenant_schema_for_request(request)
        
        resp = {
            'resultDescription' : f"Organization Admin {first_name} has been added successfully",
            'resultCode': "1",
            'actionPerformed': f"Organization Admin {first_name} has been added successfully"   
        }
        return Response(resp, status=status.HTTP_200_OK)
        
        
    
    @allowed_users(['Super Admin','Organization Admin'])
    def delete(self,request):
        payload = request.data
        admin_id = request.query_params.get('admin_id')
        admin_user = UserProfile.objects.filter(pk = admin_id).first()
        if not admin_user:
            raise ValidationError("Organization admin does not exist")
        if admin_user.is_staff:
            raise ValidationError("Sorry, you don't have permission to delete the organization's admin")
        email = admin_user.email
        admin_user.delete()
        
        """switching to public"""
        set_tenant_schema_by_name('public')
        userOrg = UserOrganization.objects.filter(email = email).first()
        userOrg.delete()
        '''switching to respective schema'''
        set_tenant_schema_for_request(request)
        
        resp = {
            'resultDescription' : "Admin has been deleted successfully",
            'resultCode': '1',
            'actionPerformed': 'Admin has been deleted successfully'
        }
        return Response(resp,status=status.HTTP_200_OK)
    
class AdminListingView(ListAPIView):
    
    queryset = UserProfile.objects.select_related().filter(groups__name = 'Organization Admin')
    serializer_class = AdminListingSerializer
    
    def paginate_quryset(self,queryset):
        return super().paginate_queryset(queryset)



class DriverView(APIView):
    
    parser_classes = (MultiPartParser, FormParser)
    @allowed_users(['Organization Admin', 'Head Driver'])
    def post(self, request):
        request.data._mutable=True
        payload = request.data
        first_name = payload.get('first_name')
        last_name = payload.get('last_name')
        email = payload.get('email')
        phone_number = payload.get('phone_number')
        country_code = payload.get('country_code', "+91")
        address = payload.get('address')
        password = payload.get('password')
        other_certificates = []
        if 'other_certificates' in payload:
            other_certificates = payload.pop('other_certificates')
        driver_license = payload.get("driver_license")
        driver_abstract = payload.get("driver_abstract")
        driver_certificate = payload.get("driver_certificate")
        driver_cvor = payload.get("driver_cvor")
        driver_safety = payload.get("driver_safety")
        driver_insurance = payload.get("driver_insurance")
        is_head_driver = payload.get('is_head_driver', 'false')
        is_head_driver = json.loads(is_head_driver)
        is_active = payload.get('is_active', 'false')
        is_active = json.loads(is_active)
        group = 'Associate Driver'
        if is_head_driver:
            group = 'Head Driver'
        
        prof_image = payload.get('image')
        # if group not in ['Associate Driver', 'Head Driver']:
        #     raise ValidationError("Invalid driver group, It should be Associate Driver or Head Driver")
        if not first_name:
            raise ValidationError("Enter driver first name")
        if not email:
            raise ValidationError("Enter driver email id")
        if not password:
            raise ValidationError("Enter driver password")
        if not phone_number:
            raise ValidationError("Enter driver Phone number")
        if not address:
            raise ValidationError("Enter driver address ")
        group = Group.objects.filter(name=group).first()
        if not group:
            raise ValidationError("Driver Group not found in database")
        
        user_exists = UserProfile.objects.filter(email=email).first()
        if user_exists:
            group_name = user_exists.groups.values_list('name', flat=True).first()
            raise ValidationError(f"{group_name} with this email already exists")
        user_exists = UserProfile.objects.filter(phone_number=phone_number).first()
        if user_exists:
            group_name = user_exists.groups.values_list('name', flat=True).first()
            raise ValidationError(f"{group_name} with this phone number already exists")
                
        user = UserProfile.objects.create(
            first_name=first_name,
            last_name=last_name,
            email=email,
            is_active=is_active,
            phone_number=phone_number,
            address=address,
            username=email,
            country_code=country_code

        )
        email_password=password
        user.groups.add(group.id)
        user.set_password(password)
        user.save()

        '''code to upload certificates '''
        certificate_list = []
        if driver_license:
            certificate_list.append(DriverCertificate(
                user=user,
                doc_name='License',
                image=driver_license
            ))
        
        if driver_abstract:
            certificate_list.append(DriverCertificate(
                user=user,
                doc_name='Abstract',
                image=driver_abstract
            ))
        
        if driver_certificate:
            certificate_list.append(DriverCertificate(
                user=user,
                doc_name='Certificate',
                image=driver_certificate
            ))
        
        if driver_cvor:
            certificate_list.append(DriverCertificate(
                user=user,
                doc_name='CVOR',
                image=driver_cvor
            ))
        
        if driver_safety:
            certificate_list.append(DriverCertificate(
                user=user,
                doc_name='Safety Certificate',
                image=driver_safety
            ))
        
        if driver_insurance:
            certificate_list.append(DriverCertificate(
                user=user,
                doc_name='Insurance',
                image=driver_insurance
            ))

        '''apending other certificates'''
        i = 1
        for certificate in other_certificates:
            title = 'Other-'+str(i) 
            certificate_list.append(DriverCertificate(
                user=user,
                doc_name=title,
                image=certificate
            ))
            i += 1
        try:
            DriverCertificate.objects.bulk_create(certificate_list)
        except Exception as ex:
            raise ValidationError("Driver added successfully but failed to upload certificates")

        '''uploading profile image'''

        if prof_image:
            ProfileImage.objects.create(user=user, image=prof_image)
        schema = get_schema_name_by_request(request)
        set_tenant_schema_by_name('public')
        org = Organization.objects.filter(schema_name=schema).first()
        if not org:
            set_tenant_schema_by_name(schema)
            raise ValidationError("Driver failed to register with company")
        UserOrganization.objects.create(
            email=email,
            phone_number=phone_number,
            organization=org,
            country_code=country_code
            )
        set_tenant_schema_by_name(schema)
        send_driver_login_email(organization_name=org.name,password=email_password
                                   ,driver_email=user.email,driver_name=user.first_name+last_name,)

        resp = {
        "result": 'Driver has been added successfully',
        "resultCode": "1",
        "resultDescription": "Driver has been added successfully"
        }
        
        return Response(resp, status=status.HTTP_200_OK)


    @allowed_users(['Organization Admin', 'Head Driver'])
    def delete(self, request, pk):
        if not pk:
            raise ValidationError("Enter driver id in url")
        driver = UserProfile.objects.filter(id=pk).first()
        if not driver:
            raise ValidationError("Record not found") 
        email = driver.email
        driver.delete()
        set_tenant_schema_by_name('public')
        user_org = UserOrganization.objects.filter(email=email).first()
        if user_org:
            user_org.delete()
        set_tenant_schema_for_request(request)
        
        resp = {
            "result": 'Driver has been deleted successfully ',
            "resultCode": "1",
            "resultDescription": "Driver has been deleted successfully"
        }
        
        return Response(resp, status=status.HTTP_200_OK)
    
    @allowed_users(['Organization Admin', 'Head Driver'])
    def put(self, request, pk):
            if not pk:
                raise ValidationError("Enter driver id in url")
            driver_status = request.data.get('status', 'false')
            driver_status = json.loads(driver_status)
            driver = UserProfile.objects.filter(id=pk).first()
            if not driver:
                raise ValidationError("Record not found") 
            driver.is_active=driver_status
            driver.save()
            if driver_status:
                message = 'Driver has been activated successfully '
            else:
                message = 'Driver has been deactivated successfully '

            resp = {
                "result": message ,
                "resultCode": "1",
                "resultDescription": message
            }
            
            return Response(resp, status=status.HTTP_200_OK)
    
    @allowed_users(['Organization Admin', 'Head Driver', 'Associate Driver'])
    def get(self, request, pk):
        if not pk:
            raise ValidationError("Enter driver id in url")
        driver = UserProfile.objects.filter(id=pk).first()
        if not driver:
            raise ValidationError("Record not found")
        serializer = DriverSerializer(driver)
        resp = {
                "result": serializer.data,
                "resultCode": "1",
                "resultDescription": "Driver details"
            }
        return Response(resp, status=status.HTTP_200_OK)

class DriverEditView(APIView):
    parser_classes = (MultiPartParser, FormParser)
    @allowed_users(['Organization Admin', 'Head Driver', 'Associate Driver'])
    def put(self, request, pk):
        if not pk:
            raise ValidationError("Enter driver id in url")
        user = UserProfile.objects.filter(id=pk).first()
        if not user:
            raise ValidationError("Record not found with your given driver id")
        existing_email = user.email
        request.data._mutable=True
        payload = request.data
        first_name = payload.get('first_name')
        last_name = payload.get('last_name')
        email = payload.get('email')
        phone_number = payload.get('phone_number')
        country_code = payload.get('country_code')
        address = payload.get('address')
        is_active = payload.get('is_active')
        if not is_active:
            raise ValidationError("please select driver active status") 
        is_active = json.loads(is_active)
        is_head_driver = payload.get('is_head_driver', 'false')
        if not is_head_driver:
            raise ValidationError("Please select driver role")
        if not first_name:
            raise ValidationError("Enter driver first name")
        if not email:
            raise ValidationError("Enter driver email id")
        if not phone_number:
            raise ValidationError("Enter driver Phone number")
        if not address:
            raise ValidationError("Enter driver address ")
                
        user_exists = UserProfile.objects.filter(Q(email=email) & ~Q(id=pk)).first()
        if user_exists:
            raise ValidationError("Another Driver with this email already exists")
        user_exists = UserProfile.objects.filter(Q(phone_number=phone_number) & ~Q(id=pk)).first()
        if user_exists:
            raise ValidationError("Another Driver with this phone number already exists")
        if is_head_driver:
            is_head_driver = json.loads(is_head_driver)
        group = 'Associate Driver'
        if is_head_driver:
            group = 'Head Driver'
        user_group = Group.objects.filter(name=group).first()
        if not user_group:
            raise ValidationError("Driver Group not found in database")
        
        # reset driver personal details
        user.first_name = first_name
        user.last_name = last_name
        user.email = email
        user.is_active = is_active
        user.phone_number = phone_number
        user.address = address
        user.username = email
        if country_code:
            user.country_code = country_code
        
        # removing existing group
        user.groups.clear()
        user.groups.add(user_group)
        # user_group.user_set.remove(user)
        # user_group.user_set.add(user)
        user.save()
        
        #editing profile pic
        prof_image = payload.get('image')
        if prof_image:
            ProfileImage.objects.filter(user__id=pk).delete()
            ProfileImage.objects.create(user=user, image=prof_image)
        
        #editing driver certificates
        driver_license = payload.get("driver_license")
        driver_abstract = payload.get("driver_abstract")
        driver_certificate = payload.get("driver_certificate")
        driver_cvor = payload.get("driver_cvor")
        driver_safety = payload.get("driver_safety")
        driver_insurance = payload.get("driver_insurance")
        other_cert_ids = payload.get("other_cert_ids")
        other_certificates = payload.get("other_certificates")
                
        '''code to upload certificates '''
        certificate_list = []
        driver_certi = DriverCertificate.objects.filter(user__id=pk)
        if driver_license:
            lice_qs = driver_certi.filter(doc_name='License').first()
            if lice_qs:
                lice_qs.image=driver_license
                lice_qs.save()
            else:
                certificate_list.append(DriverCertificate(
                    user=user,
                    doc_name='License',
                    image=driver_license
                    ))

        if driver_abstract:
            abs_qs = driver_certi.filter(doc_name='Abstract').first()
            if abs_qs:
                abs_qs.image=driver_abstract
                abs_qs.save()
            else:
                certificate_list.append(DriverCertificate(
                    user=user,
                    doc_name='Abstract',
                    image=driver_abstract
                    ))
                    
        if driver_certificate:
            cert_qs = driver_certi.filter(doc_name='Certificate').first()
            if cert_qs:
                cert_qs.image=driver_certificate
                cert_qs.save()
            else:
                certificate_list.append(DriverCertificate(
                    user=user,
                    doc_name='Certificate',
                    image=driver_certificate
                    ))
                    
        if driver_cvor:
            cvor_qs = driver_certi.filter(doc_name='CVOR').first()
            if cvor_qs:
                cvor_qs.image=driver_cvor
                cvor_qs.save()
            else:
                certificate_list.append(DriverCertificate(
                    user=user,
                    doc_name='CVOR',
                    image=driver_cvor
                    ))
                    
        if driver_safety:
            safety_qs = driver_certi.filter(doc_name='Safety Certificate').first()
            if safety_qs:
                safety_qs.image=driver_safety
                safety_qs.save()
            else:
                certificate_list.append(DriverCertificate(
                    user=user,
                    doc_name='Safety Certificate',
                    image=driver_safety
                    ))
        
        if driver_insurance:
            insurance_qs = driver_certi.filter(doc_name='Insurance').first()
            if insurance_qs:
                insurance_qs.image=driver_insurance
                insurance_qs.save()
            else:
                certificate_list.append(DriverCertificate(
                    user=user,
                    doc_name='Insurance',
                    image=driver_insurance))
        
        if len(certificate_list)>0:
            try:
                DriverCertificate.objects.bulk_create(certificate_list)
            except Exception as ex:
                raise ValidationError("Driver record updated successfully but failed to update certificates")

        '''apending other certificates'''
        
        other_certificates = []
        other_certi_ids = []
        certificate_list = []
        if 'other_certificates' in payload:
            other_certificates = payload.pop('other_certificates')
        if 'other_cert_ids' in payload:
            other_certi_ids = json.loads(payload.get('other_cert_ids'))

        
        i = 0
        for id, certificate in zip(other_certi_ids, other_certificates):
            driver_cert = DriverCertificate.objects.filter(id=id)
            if driver_cert:
                driver_cert = driver_cert.first()
                driver_cert.image=certificate
                driver_cert.save()
            else:
                title = 'Other-'+str(id)
                certificate_list.append(DriverCertificate(
                    user=user,
                    doc_name=title,
                    image=certificate
                ))        
        try:
            if len(certificate_list)>0:
                DriverCertificate.objects.bulk_create(certificate_list)
        except Exception as ex:
            raise ValidationError("Driver added successfully but failed to upload certificates")
        
        schema = get_schema_name_by_request(request)
        set_tenant_schema_by_name('public')
        
        org = Organization.objects.filter(schema_name=schema).first()
        if not org:
            set_tenant_schema_by_name(schema)
            raise ValidationError("Driver failed to register with company")
        user_org = UserOrganization.objects.filter(organization__schema_name=schema)
        user_org = user_org.filter(email=existing_email).first()
        user_org.email = email
        user_org.phone_number=phone_number
        if country_code:
            user_org.country_code = country_code
        user_org.save()
        set_tenant_schema_by_name(schema)

        resp = {
        "result": 'Driver record has been updated successfully',
        "resultCode": "1",
        "resultDescription": "Driver has been updated successfully"
        }
        
        return Response(resp, status=status.HTTP_200_OK)

class DriverListingView(ListAPIView):
    
    queryset = UserProfile.objects.select_related().filter(
        Q(groups__name='Head Driver') | Q(groups__name='Associate Driver')
        )
    serializer_class = DriverSerializer
    renderer_classes = [CustomJSONRenderer]

    def paginate_queryset(self, queryset):
        
        queryset = queryset.annotate(
            is_head_driver=Case(
            When(groups__name='Head Driver', then=True),
            default=False,
            output_field=BooleanField()
            ),
        ).order_by('-is_head_driver', '-is_active', 'first_name')

        if 'all' in self.request.query_params.values():

            return None
                
        qs = super().paginate_queryset(queryset)
        return qs        

class FCMDeviceView(APIView):
    @allowed_users(["Organization Admin", "Head Driver", 'Associate Driver', 'Customer'])
    def post(self, request):
        serialize = FCMDeviceSerializer(data=request.data)
        if serialize.is_valid(raise_exception=True):
            serialize.save()
            resp = {
                'resultCode': '1',
                'resultDescription': 'Device details has been added successfully',
                'result': serialize.data
                } 
        
            return Response(resp, status=status.HTTP_200_OK)