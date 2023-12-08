from email_validator import EmailNotValidError, validate_email
from flask import request
from flask_jwt_extended import create_access_token, get_jwt, jwt_required
from flask_restful import Resource

from mysql_connection import get_connection
from mysql.connector import Error

from utils import check_password, hash_password


class UserRegisterResource(Resource) :

    def post(self) :
        
        data = request.get_json()
        print()
        print(data)
        print()

        # 이메일 체크
        try :
            validate_email(data['email'])

        except  EmailNotValidError as e :
            print(e)
            return {'error' : '올바른 이메일 형식이 아닙니다.'},400 

        # 비밀번호 체크   
        if len(data['password']) < 4 and len(data['password']) > 14 :
            return {'error' : '비밀번호 길이가 맞지 않습니다'}, 400

        # 비밀번호 암호화
        password = hash_password(data['password'])
        print(password)

        #  DB 저장
        try :

            connection = get_connection()

            query = '''insert into user
                            (email,password,nickname)
                            values
                            (%s,%s,%s);'''
            
            record = (data['email'],
                      password,
                      data['nickname'])
            
            cursor = connection.cursor()
            cursor.execute(query,record)

            connection.commit()

            # 회원가입 한 유저 ID 가져오기
            user_id = cursor.lastrowid
            print(user_id)

            cursor.close()
            connection.close()


        except Error as e :
            print(e)
            cursor.close()
            connection.close()
            return {'error' : str(e)}, 500
        
        # 클라이언트에게 토큰으로 ID값 반환하기
        access_token = create_access_token(user_id)

        return {'reult' : 'success',
                'access_token' : access_token}, 200

class UserLoginResource(Resource) :
    # 포스트맨 데이터 받아오기
    def post(self) :

        data= request.get_json()
        print()
        print(data)
        print()

        # DB 호출
        try : 
            connection = get_connection()
            query = '''select *
                            from user
                            where email = %s;'''
            
            record = ( data['email'] ,  )

            # 쿼리가 select면 딕셔너리 추가
            cursor = connection.cursor(dictionary=True)
            cursor.execute(query,record)

            # 쿼리가 select면 fetchall() 추가
            result_list = cursor.fetchall()

            print(result_list)
            print()

            cursor.close()
            connection.close()

            

        except Error as e :
            print(e)
            cursor.close()
            connection.close()
            return {'error' : str(e)}, 500
        
        # 회원정보가 DB에 있는지 확인하기
        if len(result_list) == 0 :
            return {'error' : '회원가입을 하시길 바랍니다.'} , 400
        
        # 비밀번호 체크하기 유틸파일에서 미리 만들어둔 함수 불러오기
        check = check_password(data['password'], result_list[0]['password'])
        if check == False :
            return {'error' : '비밀번호가 맞지 않습니다'}, 400
        
        # 클라이언트에게 토큰처리된 ID 반환하기
        access_token = create_access_token(result_list[0]['id'])


        return {'result' : 'success',
                'access_token' : access_token}, 200     
    

jwt_blocklist = set()
class UserLogoutResource(Resource) :

    @jwt_required()
    def delete(self) :

        jti = get_jwt()['jti']
        print()
        print(jti)
        print()

        jwt_blocklist.add(jti)

        return {'result' : 'success'} , 200

