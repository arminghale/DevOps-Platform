import datetime
import typing
import uuid


class User:
    def __init__(self,username:str,password:str,token:str='',expired_date:str='',access_level:int=0,id:str=''):
        self.id=id if id else str(uuid.uuid4())
        self.username=username
        self.password=password
        self.token=token if token else str(uuid.uuid4())
        self.expired_date=expired_date if expired_date else (datetime.datetime.now()+datetime.timedelta(30)).strftime("%Y-%m-%d, %H:%M:%S")
        self.access_level=access_level
    
    def json(self):
        return {
            'id':self.id,
            'username':self.username,
            'password':self.password,
            'token':self.token,
            'expired_date':self.expired_date,
            'access_level':self.access_level
        }

    def extend_date(self):
        self.expired_date=(datetime.datetime.strptime(self.expired_date,"%Y-%m-%d, %H:%M:%S")+datetime.timedelta(30)).strftime("%Y-%m-%d, %H:%M:%S")

def Decode_Users(users_json):
    users:typing.List[User]=[]
    for item in users_json:
        users.append(Decode_User(item))
    return users

def Decode_User(json):
    return User(
            json['username'],
            json['password'],
            json['token'],
            json['expired_date'],
            json['access_level'],
            json['id']
        )

