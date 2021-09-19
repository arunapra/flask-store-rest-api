
from flask import Flask,jsonify
from flask_restful import Api
from flask_jwt_extended import JWTManager,decode_token

from resources.user import UserRegister,User,UserLogin,UserLogout,TokenRefresh
from resources.item import Item,ItemList
from resources.store import Store,StoreList

from blacklist import BLACKLIST 

app=Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']=False
app.config['PROPAGATE_EXCEPTIONS']=True
#app.config['JWT_BLOCKLIST_ENABLED']=True
#app.config['JWT_BLOCKLIST_TOKEN_CHECKS']=['access','refresh']
app.secret_key="aruna" # app.config['JWT_SECRET_KEY']
api=Api(app)

@app.before_first_request
def create_tables():
    db.create_all()
    
jwt=JWTManager(app)

@jwt.additional_claims_loader     #decorator: which adds the claims to the jwt
def add_claims_to_jwt(identity):
    if(identity==1):         # Instead of hard coding, read from a config file or a database
        return {'is_admin':True}
    return {'is_admin':False}

@jwt.token_in_blocklist_loader
def check_if_token_in_blacklist(jwt_headers,jwt_payload):
    return jwt_payload.get('jti') in BLACKLIST

@jwt.expired_token_loader
def expired_token_callback(jwt_headers,jwt_payload):
    return jsonify({
        'description':'The token has expired',
        'error':'Token Expired'
        }),401

@jwt.invalid_token_loader
def invalid_token_callback(error):
    return jsonify({
        'description':'Signature verification failed',
        'error':'Invalid Token'
        }),401

@jwt.unauthorized_loader
def missing_token_callback(error):
    return jsonify({
        'description':'Request does not contain access_token',
        'error':'Authorisation required'
        }),401

@jwt.needs_fresh_token_loader
def token_not_fresh_callback(jwt_headers,jwt_payload):
    return jsonify({
        'description':'The token is not fresh',
        'error':'Fresh token required'
        }),401

@jwt.revoked_token_loader
def revoked_token_callback(jwt_headers,jwt_payload):
    return jsonify({
        'description':'The token is revoked',
        'error':'Token revoked'
        }),401

api.add_resource(Store,'/store/<string:name>')
api.add_resource(Item,'/item/<string:name>')
api.add_resource(ItemList,'/items')
api.add_resource(StoreList,'/stores')
api.add_resource(UserRegister,'/register')
api.add_resource(User,'/user/<int:user_id>')
api.add_resource(UserLogin,'/login')
api.add_resource(UserLogout,'/logout')
api.add_resource(TokenRefresh,'/refresh')

if __name__=='__main__':
    from db import db
    db.init_app(app)
    app.run(port=5000,debug=True)
