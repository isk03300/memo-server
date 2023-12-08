from flask import Flask
from flask_jwt_extended import JWTManager
from flask_restful import Api
from config import Config
from resources.memo import MemoListResource, MemoMyResource, MemoResource
from resources.user import UserLoginResource, UserLogoutResource, UserRegisterResource
from resources.user import jwt_blocklist

app = Flask(__name__)

# 환경변수 셋팅
app.config.from_object(Config)

# JWT 매니저 초기화
jwt = JWTManager(app)

@jwt.token_in_blocklist_loader
def check_if_token_is_revoked(jwt_header,jwt_payload) :
    jti = jwt_payload['jti']
    return jti in jwt_blocklist

api = Api(app)

# 경로와 리소스 연결.
api.add_resource( UserRegisterResource ,  '/user/register' )
api.add_resource( UserLoginResource   , '/user/login')
api.add_resource( UserLogoutResource, '/user/logout')
api.add_resource( MemoListResource  ,  '/memos')
api.add_resource(  MemoResource  , '/memos/<int:memo_id>')
api.add_resource(MemoMyResource, '/memos/me')

if __name__ == '__main__' :
    app.run()