import asyncio
import hashlib
import json
import logging
import os
import socket
import subprocess
import sys
import typing
import time

import docker.models
import docker.models.containers
import docker

import redis
import nginx

import tornado.escape
import tornado.ioloop
import tornado.web

from GitlabModel import CheckGitlab, GitlabInfo, GitlabModel
from UserModel import Decode_User, User


def getIP():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0)
        try:
            s.connect(('10.254.254.254', 1))
            IP = s.getsockname()[0]
        except Exception:
            IP = '127.0.0.1'
        finally:
            s.close()
        return IP


class BaseHandler(tornado.web.RequestHandler):
    def get_current_user(self):
        return self.get_signed_cookie("credential")

    def get_user_access(self):
        if self.get_current_user():
            token=self.get_signed_cookie("credential").decode("utf-8")
            user:User=self.find_user(token=token)
            return user.access_level
        return 0

    def get_user_username(self):
        if self.get_current_user():
            token=self.get_signed_cookie("credential").decode("utf-8")
            user:User=self.find_user(token=token)
            return user.username
        return None

    def find_user(self,token:str='',username:str='',id:str=''):
        r=redis.Redis(host=LOCAL_IPADDRESS, port=REDIS_PORT)
        users:typing.List[dict]=json.loads(r.get("users"))
        r.close()
        
        if username:
            user_json=next((x for x in users if x['username'] == username), None)
        elif id:
            user_json=next((x for x in users if x['id'] == id), None)
        elif token:
            user_json=next((x for x in users if x['token'] == token), None)
 
        user:User=Decode_User(user_json)
        return user

    def get_template_namespace(self):
        namespace = super(BaseHandler, self).get_template_namespace()
        namespace.update({
            'access_level': self.get_user_access(),
            'error': '',
            'title':"Home",
            'items':[],
            'item':'',
            'nginx':NGINX,
        })
        return namespace


class HomeHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self) -> None:
        try:
            error=self.get_argument("e","")
            if error:
                self.render("home.html",error=error)
                return
            
            self.render("home.html")
            return
        except Exception as e:
            self.render("home.html",error=f"system error: {e}")
            return

class LoginHandler(BaseHandler):
    async def get(self) -> None:
        self.render("login.html")
        return

    async def post(self) -> None:
        try:
            username= self.get_argument("username")
            password= self.get_argument("password")
            if not username or not password:
                self.render("login.html", error="enter username and password")
                return
            
            hash_password=hashlib.sha256(password.encode("utf-8")).hexdigest()

            user=self.find_user(username=username)
            
            if not user:
                self.render("login.html", username=username, error="user not found")
                return

            if user.password!=hash_password:
                self.render("login.html", username=username, error="wrong password")
                return

            self.set_signed_cookie("credential", user.token)
            self.set_cookie("access_level",str(user.access_level))
            self.redirect(self.get_query_argument('next', '/'))
        except Exception as e:
            self.render("login.html", error=f"system error: {e}")
            return

class LogoutHandler(BaseHandler):
    async def get(self) -> None:
        self.clear_cookie("credential")
        self.redirect(self.get_argument("next", "/"))


class ListUserHandler(BaseHandler):
    @tornado.web.authenticated
    async def get(self) -> None:
        try:
            if self.get_user_access()<1:
                self.redirect(f"/?e=no access")
            
            error=self.get_argument("e","")
            if error:
                self.render("User/list.html",error=error,title="Users List")
                return

            r=redis.Redis(host=LOCAL_IPADDRESS, port=REDIS_PORT)
            users:typing.List[dict]=json.loads(r.get("users"))
            r.close()

            self.render("User/list.html",items=users,title="Users List")
            return
        except Exception as e:
            self.render("User/list.html",error=f"system error: {e}",title="Users List")
            return

class DeleteUserHandler(BaseHandler):
    @tornado.web.authenticated
    async def get(self) -> None:
        try:
            if self.get_user_access()<1:
                self.redirect(f"/?e=no access")
            
            id=self.get_argument("id","")
            if not id:
                self.redirect("/users")

            r=redis.Redis(host=LOCAL_IPADDRESS, port=REDIS_PORT)
            users:typing.List[dict]=json.loads(r.get("users"))
            
            user=next((x for x in users if x['id'] == id), None)
            if not user:
                self.redirect(f"/user?e=user not found")

            users.remove(user)
            r.set("users",json.dumps(users))
            r.close()

            self.redirect("/user")
        except Exception as e:
            self.redirect(f"/user?e=system error: {e}")

class CreateUserHandler(BaseHandler):
    @tornado.web.authenticated
    async def get(self) -> None:
        try:
            if self.get_user_access()<1:
                self.redirect(f"/?e=no access")
            
            self.render("User/create.html",title="Create User")
            return
        except Exception as e:
            self.redirect(f"/user?e=system error: {e}")
    
    @tornado.web.authenticated
    async def post(self) -> None:
        try:
            if self.get_user_access()<1:
                self.redirect(f"/?e=no access")
            
            username= self.get_argument("username")
            password= self.get_argument("password")
            access_level= self.get_argument("access_level")

            if not username or not password:
                self.render("User/create.html", error="enter username and password",title="Create User")
                return
            if access_level<0:
                self.render("User/create.html", error="enter positive number for access level",title="Create User")
                return

            r=redis.Redis(host=LOCAL_IPADDRESS, port=REDIS_PORT)
            users:typing.List[dict]=json.loads(r.get("users"))

            if self.find_user(username=username):
                self.render("User/create.html", error="user with this username exists",title="Create User")
                return

            user=User(username,hashlib.sha256(password.encode("utf-8")).hexdigest(),access_level=access_level)

            users.append(user.json())
            r.set("users",json.dumps(users))
            r.close()

            self.redirect("/user")
        except Exception as e:
            self.render("User/create.html",error=f"system error: {e}",title="Create User")
            return

class EditUserHandler(BaseHandler):
    @tornado.web.authenticated
    async def get(self) -> None:
        try:
            if self.get_user_access()<1:
                self.redirect(f"/?e=no access")
            
            id=self.get_argument("id","")
            if not id:
                self.redirect("/users")

            r=redis.Redis(host=LOCAL_IPADDRESS, port=REDIS_PORT)
            users:typing.List[dict]=json.loads(r.get("users"))
            r.close()

            user=next((x for x in users if x['id'] == id), None)
            if not user:
                self.render("User/list.html",error=f"user not found",title="Users List")
                return

            self.render("User/edit.html",item=user,title="Edit User")
            return
        except Exception as e:
            self.redirect(f"/user?e=system error: {e}")
    
    @tornado.web.authenticated
    async def post(self) -> None:
        try:
            if self.get_user_access()<1:
                self.redirect(f"/?e=no access")
            
            username= self.get_argument("username")
            password= self.get_argument("password")
            access_level= self.get_argument("access_level")
            id= self.get_argument("id")

            if not username:
                self.render("User/edit.html", error="enter username and password",title="Edit User")
                return
            if access_level<0:
                self.render("User/edit.html", error="enter positive number for access level",title="Edit User")
                return
            user=self.find_user(id=id)
            if not user:
                self.render("User/edit.html", error="user not found",title="Edit User")
                return

            if self.find_user(username=username).id!=id:
                self.render("User/edit.html", error="user with this username exists",title="Edit User")
                return
            
            r=redis.Redis(host=LOCAL_IPADDRESS, port=REDIS_PORT)
            users:typing.List[dict]=json.loads(r.get("users"))

            users.remove(user.json())

            user.username=username
            user.access_level=access_level
            if password:
                user.password=hashlib.sha256(password.encode("utf-8")).hexdigest()

            users.append(user.json())
            r.set("users",json.dumps(users))
            r.close()

            self.redirect("/user")
        except Exception as e:
            self.render("User/edit.html",error=f"system error: {e}",title="Edit User")
            return


class ListGitlabHandler(BaseHandler):
    @tornado.web.authenticated
    async def get(self) -> None:
        try:
            error=self.get_argument("e","")
            if error:
                self.render("Gitlab/list.html",error=error,title="Gitlabs List")
                return


            r=redis.Redis(host=LOCAL_IPADDRESS, port=REDIS_PORT)
            gitlabs:typing.List[dict]=json.loads((r.get("gitlabs")) if (r.get("gitlabs")) else '[]' )
            r.close()
            if self.get_user_access()<1:
                user=self.get_user_username()
                gitlabs=list(filter(lambda x: user==x['user'], gitlabs))

            self.render("Gitlab/list.html",items=gitlabs,title="Gitlabs List")
            return
        except Exception as e:
            self.render("Gitlab/list.html",error=f"system error: {e}",title="Gitlabs List")
            return

class CreateGitlabHandler(BaseHandler):
    @tornado.web.authenticated
    async def get(self) -> None:
        try:
            self.render("Gitlab/create.html",title="Create Gitlab")
            return
        except Exception as e:
            self.redirect(f"/gitlab/credential?e=system error: {e}")

    @tornado.web.authenticated
    async def post(self) -> None:
        try:
            
            token= self.get_argument("token")
            domain= self.get_argument("domain")

            if not token or not domain:
                self.render("Gitlab/create.html", error="enter token and domain",title="Create Gitlab")
                return
            
            r=redis.Redis(host=LOCAL_IPADDRESS, port=REDIS_PORT)
            gitlabs:typing.List[dict]=json.loads((r.get("gitlabs")) if (r.get("gitlabs")) else '[]')

            try:
                CheckGitlab(domain,token)
            except:
                self.render("Gitlab/create.html",error=f"Can't login with this information",title="Create Gitlab")
                return
   
            gitlab=GitlabInfo(token,domain,self.get_user_username())

            gitlabs.append(gitlab.json())
            r.set("gitlabs",json.dumps(gitlabs))
            r.close()

            self.redirect("/gitlab/credential")
        except Exception as e:
            self.render("Gitlab/create.html",error=f"system error: {e}",title="Create Gitlab")
            return

class DeleteGitlabHandler(BaseHandler):
    @tornado.web.authenticated
    async def get(self) -> None:
        try:
            id=self.get_argument("id","")
            if not id:
                self.redirect("/gitlab/credential")

            r=redis.Redis(host=LOCAL_IPADDRESS, port=REDIS_PORT)
            gitlabs:typing.List[dict]=json.loads(r.get("gitlabs"))
            
            gitlab=next((x for x in gitlabs if x['id'] == id), None)
            if not gitlab:
                self.redirect("/gitlab/credential?e=gitlab not found")
                return

            gitlabs.remove(gitlab)
            r.set("gitlabs",json.dumps(gitlabs))
            r.close()

            self.redirect("/gitlab/credential")
        except Exception as e:
            self.redirect(f"/gitlab/credential?e=system error: {e}")

class ListProjectGitlabHandler(BaseHandler):
    @tornado.web.authenticated
    async def get(self) -> None:
        try:
            selected_gitlab=self.get_cookie("selected_gitlab","")
            gitlab=None
            projects=[]

            r=redis.Redis(host=LOCAL_IPADDRESS, port=REDIS_PORT)
            gitlabs:typing.List[dict]=json.loads(r.get("gitlabs"))
            r.close()
            if self.get_user_access()<1:
                user=self.get_user_username()
                gitlabs=list(filter(lambda x: user==x['user'], gitlabs))

            if selected_gitlab:
                gitlab=next((item for  i,item in enumerate(gitlabs) if item['id']==selected_gitlab), None)
            
                gl=GitlabModel(gitlab['token'],gitlab['domain'])  
                projects=gl.Projects()
                for i in range(len(projects)): projects[i]=json.loads(projects[i].to_json())
                selected_project=self.get_argument("pid","")
                if selected_project:
                    project=gl.Project(selected_project)
                    project=project.to_json()
                    self.render("details_json.html",item=project,title="Gitlabs Project")
                    return

            self.render("Gitlab/project_list.html",items=projects,list=gitlabs, selected_gitlab=selected_gitlab,title="Gitlabs Projects List")
            return
        except Exception as e:
            self.render("Gitlab/project_list.html",error=f"system error: {e}",title="Gitlabs Projects List")
            return

class ListBranchGitlabHandler(BaseHandler):
    @tornado.web.authenticated
    async def get(self) -> None:
        try:
            error=self.get_argument("e","")
            if error:
                self.render("Gitlab/branch_list.html",error=error,title="Gitlabs Project Branches List")
                return


            selected_gitlab=self.get_cookie("selected_gitlab","")
            selected_project=self.get_cookie("selected_project","")
            gitlab=None
            projects=[]
            branches=[]

            r=redis.Redis(host=LOCAL_IPADDRESS, port=REDIS_PORT)
            gitlabs:typing.List[dict]=json.loads(r.get("gitlabs"))
            r.close()
            if self.get_user_access()<1:
                user=self.get_user_username()
                gitlabs=list(filter(lambda x: user==x['user'], gitlabs))

            if selected_gitlab:
                gitlab=next((item for  i,item in enumerate(gitlabs) if item['id']==selected_gitlab), None)
            
                gl=GitlabModel(gitlab['token'],gitlab['domain'])  
                projects=gl.Projects()
                for i in range(len(projects)): projects[i]=json.loads(projects[i].to_json())
                
                if selected_project:
                    branches=gl.Branches(selected_project)
                    for i in range(len(branches)): branches[i]=json.loads(branches[i].to_json())
                    
                    selected_branch=self.get_argument("bname","")
                    if selected_branch:
                        brnach=gl.Branch(selected_project,selected_branch)
                        brnach=brnach.to_json()
                        self.render("details_json.html",item=brnach,title="Gitlabs Project Branch")
                        return

            self.render("Gitlab/branch_list.html",items=branches,list=gitlabs, list2=projects
                        , selected_gitlab=selected_gitlab,selected_project=selected_project,title="Gitlabs Project Branches List")
            return
        except Exception as e:
            self.render("Gitlab/branch_list.html",error=f"system error: {e}",title="Gitlabs Project Branches List")
            return


class ListImageDockerHandler(BaseHandler):
    @tornado.web.authenticated
    async def get(self) -> None:
        try:
            error=self.get_argument("e","")
            if error:
                self.render("Docker/image_list.html",error=error,title="Docker Image List")
                return

            docker_client=docker.from_env()
            images=docker_client.images.list()
            containers=docker_client.containers.list()
            in_use=[]
            for i in images:
                if next((x for x in containers if x.image.tags[0] == i.tags[0]), None):
                    in_use.append("in use")
                else: in_use.append("unused")

            self.render("Docker/image_list.html",items=images,in_use=in_use,title="Docker Image List")
            return
        except Exception as e:
            self.render("Docker/image_list.html",error=f"system error: {e}",title="Docker Image List")
            return

class DeleteImageDockerHandler(BaseHandler):
    @tornado.web.authenticated
    async def get(self) -> None:
        try:
            id=self.get_argument("id","")
            if not id:
                self.redirect("/docker/image")

            docker_client=docker.from_env()
            docker_client.images.remove(id)

            self.redirect("/docker/image")
        except Exception as e:
            self.redirect(f"/docker/image?e=system error: {e}")

class RunImageDockerHandler(BaseHandler):
    @tornado.web.authenticated
    async def get(self) -> None:
        try:
            id=self.get_argument("id","")
            if not id:
                self.redirect("/docker/image")
            docker_client=docker.from_env()
            image=docker_client.images.get(id)
            volumes=docker_client.volumes.list()
            self.render("Docker/run.html",image=image,volumes=volumes,error=self.get_argument("e",""),title="Run Docker Image")
            return
        except Exception as e:
            self.redirect(f"/docker/image?e=system error: {e}")

    @tornado.web.authenticated
    async def post(self) -> None:

        id= self.get_argument("id")
        docker_client=docker.from_env()
        try:
            
            env=self.get_argument("env")
            port=int(self.get_argument("port"))
            name=self.get_argument("name")
            ip=self.get_argument("ip","127.0.0.1")
            restart_policy=self.get_argument("restart_policy")
            on_failure_retry=int(self.get_argument("on_failure_retry","1"))
            volumes=self.get_argument("volumes").split(",")

            logging.debug(restart_policy,volumes)
            if restart_policy!="always" and restart_policy!="on-failure":
                self.redirect(f"/docker/image/run?id={id}&e=restart policy is invalid")

            if ip=="expose":
                ip=getIP()
            container_ports: typing.Dict[str, tuple] = {}
            container_ports[f'{port}/tcp']=(ip,port)

            restart_policy={"Name":restart_policy}
            if restart_policy=="on-failure": restart_policy['MaximumRetryCount']=on_failure_retry

            volumes_config={}
            for v in volumes:
                vol=docker_client.volumes.get(v.split("||")[0])
                volumes_config[vol.name]={"bind":v.split("||")[1],"mode":v.split("||")[2]}

            container=docker_client.containers.run(id, environment=env.split(",") if len(env)>0 else None
                                                   , ports=container_ports, network_mode='bridge'
                                                   , name= name, detach=True
                                                   , restart_policy=restart_policy
                                                   , volumes=volumes_config)
            
            while container.status != 'running':
                container.reload()
                time.sleep(0.1)

            self.redirect("/docker/container")
        except Exception as e:
            self.redirect(f"/docker/image/run?id={id}&e=system error: {e}")

class PullImageDockerHandler(BaseHandler):
    @tornado.web.authenticated
    async def get(self) -> None:
        try:
            self.render("Docker/pull_image.html",title="Pull Docker Image")
            return
        except Exception as e:
            self.redirect(f"/docker/image?e=system error: {e}")

    @tornado.web.authenticated
    async def post(self) -> None:
        try:
            
            repository= self.get_argument("repository")
            tag= self.get_argument("tag","latest")
            username= self.get_argument("username","")
            password= self.get_argument("password","")
            platform = self.get_argument("platform","")

            if not repository:
                self.render("Docker/pull_image.html", error="enter repository",title="Pull Docker Image")
                return
            
            auth_config={}
            if username and password:
                auth_config={'username':username,'password':password}

            docker_client=docker.from_env()
            docker_client.images.pull(repository=repository, tag=tag
                                      , auth_config=auth_config if auth_config else None
                                      , platform=platform if platform else None)

            self.redirect("/docker/image")
        except Exception as e:
            self.render("Docker/pull_image.html",error=f"system error: {e}",title="Pull Docker Image")
            return

class BuildImageDockerHandler(BaseHandler):
    @tornado.web.authenticated
    async def get(self) -> None:
        try:
            branch= self.get_argument("bname")
            project=self.get_argument("pid")
            gitlab=self.get_argument("gitlab")
            if not branch or not project or not gitlab:
                self.redirect("/gitlab/branch")

            run=self.get_argument("run","0")
            self.render("Docker/build_image.html",branch=branch,project=project,gitlab=gitlab,run=run,title="Build Docker Image")
            return
        except Exception as e:
            self.redirect(f"/docker/image?e=system error: {e}")

    @tornado.web.authenticated
    async def post(self) -> None:

        branch= self.get_argument("bname")
        project=self.get_argument("pid")
        run=int(self.get_argument("run","0"))
        gitlab=self.get_argument("gitlab")

        try:
            
            path= self.get_argument("path")
            tag= self.get_argument("tag")

            if not path or not tag or not branch or not project or not gitlab:
                self.redirect(f"/docker/image/build?bname={branch}&pid={project}&gitlab={gitlab}&error=fill out all entries")

            r=redis.Redis(host=LOCAL_IPADDRESS, port=REDIS_PORT)
            gitlabs:typing.List[dict]=json.loads(r.get("gitlabs"))
            r.close()
            if self.get_user_access()<1:
                user=self.get_user_username()
                gitlabs=list(filter(lambda x: user==x['user'], gitlabs))
            selected_gitlab=next((item for  i,item in enumerate(gitlabs) if item['id']==gitlab), None)
            if not selected_gitlab:
                self.redirect(f"/docker/image/build?bname={branch}&pid={project}&gitlab={gitlab}&error=no access to selected gitlab")

            gl=GitlabModel(selected_gitlab['token'],selected_gitlab['domain'])  
            gl.Clone(project,branch,path)

            docker_client=docker.from_env()
            image=docker_client.images.build(tag=tag, path=path, rm=True)[0]

            os.rmdir(path)

            if run>0:
                self.redirect(f"/docker/image/run?id={image.id}")

            self.redirect("/docker/image")
        except Exception as e:
            self.redirect(f"/docker/image/build?bname={branch}&pid={project}&gitlab={gitlab}&error=system error: {e}")
            
class ListContainerDockerHandler(BaseHandler):
    @tornado.web.authenticated
    async def get(self) -> None:
        try:
            error=self.get_argument("e","")
            if error:
                self.render("Docker/container_list.html",error=error,title="Docker Container List")
                return

            docker_client=docker.from_env()
            containers=docker_client.containers.list()
            self.render("Docker/container_list.html",items=containers,title="Docker Container List")
            return
        except Exception as e:
            self.render("Docker/container_list.html",error=f"system error: {e}",title="Docker Container List")
            return

class DeleteContainerDockerHandler(BaseHandler):
    @tornado.web.authenticated
    async def get(self) -> None:
        try:
            id=self.get_argument("id","")
            if not id:
                self.redirect("/docker/container")

            docker_client=docker.from_env()
            docker_client.containers.get(id).remove(force=True)

            self.redirect("/docker/container")
        except Exception as e:
            self.redirect(f"/docker/container?e=system error: {e}")

class ListVolumeDockerHandler(BaseHandler):
    @tornado.web.authenticated
    async def get(self) -> None:
        try:
            error=self.get_argument("e","")
            if error:
                self.render("Docker/volume_list.html",error=error,title="Docker Volume List")
                return

            docker_client=docker.from_env()
            volumes=docker_client.volumes.list()
            self.render("Docker/volume_list.html",items=volumes,title="Docker Volume List")
            return
        except Exception as e:
            self.render("Docker/volume_list.html",error=f"system error: {e}",title="Docker Volume List")
            return

class CreateVolumeDockerHandler(BaseHandler):
    @tornado.web.authenticated
    async def get(self) -> None:
        try:
            self.render("Docker/create_volume.html",title="Create Docker Volume")
            return
        except Exception as e:
            self.redirect(f"/docker/volume?e=system error: {e}")

    @tornado.web.authenticated
    async def post(self) -> None:
        try:
            
            name= self.get_argument("name")
            driver= self.get_argument("driver","local")
            driver_opts= self.get_argument("driver_opts","{}")

            if not name:
                self.render("Docker/create_volume.html", error="enter name",title="Create Docker Volume")
                return
            
            try:
                driver_opts=json.loads(driver_opts)
            except:
                self.render("Docker/create_volume.html", error="driver options not in write format",title="Create Docker Volume")
                return

            docker_client=docker.from_env()
            docker_client.volumes.create(name=name,driver=driver,driver_opts=driver_opts)

            self.redirect("/docker/volume")
        except Exception as e:
            self.render("Docker/create_volume.html",error=f"system error: {e}",title="Create Docker Volume")
            return

class DeleteVolumeDockerHandler(BaseHandler):
    @tornado.web.authenticated
    async def get(self) -> None:
        try:
            id=self.get_argument("id","")
            if not id:
                self.redirect("/docker/volume")

            docker_client=docker.from_env()
            docker_client.volumes.get(id).remove(force=True)

            self.redirect("/docker/volume")
        except Exception as e:
            self.redirect(f"/docker/volume?e=system error: {e}")


class ListMonitorHandler(BaseHandler):
    @tornado.web.authenticated
    async def get(self) -> None:
        try:
            error=self.get_argument("e","")

            monitors=list(m.name for m in os.scandir("./monitors") if m.is_dir())
            
            docker_client=docker.from_env()
            containers=docker_client.containers.list()
            in_use=[]
            href=[]
            for m in monitors:
                if next((x for x in containers if x.name == m), None):
                    in_use.append("active")
                    with open(f'./monitor/{m}/setting.json') as f:
                        href.append(json.loads(f)['ip:port'])
                else: 
                    in_use.append("deactivate")
                    href.append("")

            self.render("Monitor/list.html",items=monitors,in_use=in_use,href=href,error=error,title="Monitor List")
            return
        except Exception as e:
            self.render("Monitor/list.html",error=f"system error: {e}",title="Monitor List")
            return

class StartMonitorHandler(BaseHandler):
    @tornado.web.authenticated
    async def get(self) -> None:
        try:
            id=self.get_argument("id","")
            if not id:
                self.redirect("/monitor")

            proc=subprocess.Popen([f'docker','compose','-f',f'./monitors/{id}/docker-compose.yml','up'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,shell=True)

            self.redirect(f"/monitor?e={proc.communicate()}")
        except Exception as e:
            self.redirect(f"/monitor?e=system error: {e}")

class StopMonitorHandler(BaseHandler):
    @tornado.web.authenticated
    async def get(self) -> None:
        try:
            id=self.get_argument("id","")
            if not id:
                self.redirect("/monitor")

            docker_client=docker.from_env()
            docker_client.containers.get(id).remove(force=True)

            self.redirect("/monitor")
        except Exception as e:
            self.redirect(f"/monitor?e=system error: {e}")


class ListNginxHandler(BaseHandler):
    @tornado.web.authenticated
    async def get(self) -> None:
        try:
            error=self.get_argument("e","")
            name=self.get_argument("name","")

            nginxs=[]
            
            for i in list(m.name for m in os.scandir("/etc/nginx/sites-enabled") if not m.is_dir()):
                try:
                    c = nginx.Conf()
                    c = nginx.loadf(f'/etc/nginx/sites-enabled/{i}')
                    nginxs.append(i)
                except: continue

            if name and name in nginxs:
                c = nginx.Conf()
                c = nginx.loadf(f'/etc/nginx/sites-enabled/{name}')
                
                self.render("details_json.html",item=c.as_dict,title="Nginx Detail")
                return

            self.render("Nginx/list.html",items=nginxs,error=error,title="Nginx List")
            return
        except Exception as e:
            self.render("Nginx/list.html",error=f"system error: {e}",title="Nginx List")
            return

class CreateNginxHandler(BaseHandler):
    @tornado.web.authenticated
    async def get(self) -> None:
        try:
            self.render("Nginx/create.html",title="Create Nginx")
            return
        except Exception as e:
            self.redirect(f"/nginx?e=system error: {e}")

    @tornado.web.authenticated
    async def post(self) -> None:
        try:
            
            name= self.get_argument("name")
            expose_port= self.get_argument("expose_port","80")
            local_port= self.get_argument("local_port","80")
            domain= self.get_argument("domain","")

            c = nginx.Conf()
            s = nginx.Server()
            for exp in expose_port.split(","):
                s.add(nginx.Key('listen', exp))
            if domain:
                s.add(nginx.Key('server_name',domain))
            s.add(
                nginx.Location('/',
                               nginx.Key('include','proxy_params'),
                               nginx.Key('proxy_pass',f'http://localhost:{local_port}')
                               )
            )
            c.add(s)
            nginx.dumpf(c, f'/etc/nginx/sites-enabled/{name}')

            proc_systemctl=subprocess.Popen(['sudo systemctl','restart','nginx'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,shell=True)
            proc_systemctl.communicate()

            self.redirect("/nginx")
        except Exception as e:
            self.render("Nginx/create.html",error=f"system error: {e}",title="Create Nginx")
            return

class DeleteNginxHandler(BaseHandler):
    @tornado.web.authenticated
    async def get(self) -> None:
        try:
            id=self.get_argument("id","")
            if not id:
                self.redirect("/nginx")

            os.remove(f"/etc/nginx/sites-enabled/{id}")
            proc=subprocess.Popen(['sudo systemctl','restart','nginx'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,shell=True)

            self.redirect(f"/nginx?e=system error: {proc.communicate()}")
        except Exception as e:
            self.redirect(f"/nginx?e=system error: {e}")


REDIS_PORT=6379
REDIS_CONTAINER_NAME="redis_devops"
REDIS_VOLUME_NAME="redis_devops"

CONFIG_PORT=444

NGINX=1

async def tornado_main():
    settings = {
        "cookie_secret": "__TODO:_GENERATE_YOUR_OWN_RANDOM_VALUE_HERE__",
        "login_url": "/login",
        "template_path":os.path.join(os.path.dirname(__file__), "templates"),
        "static_path":os.path.join(os.path.dirname(__file__), "static"),
    }

    app = tornado.web.Application([
        (r'/login', LoginHandler),
        (r'/logout', LogoutHandler),
        (r'/', HomeHandler),

        (r'/user', ListUserHandler),
        (r'/user/create', CreateUserHandler),
        (r'/user/edit', EditUserHandler),
        (r'/user/delete', DeleteUserHandler),

        (r'/gitlab/credential', ListGitlabHandler),
        (r'/gitlab/credential/create', CreateGitlabHandler),
        (r'/gitlab/credential/delete', DeleteGitlabHandler),
        (r'/gitlab/project', ListProjectGitlabHandler),
        (r'/gitlab/branch', ListBranchGitlabHandler),

        (r'/docker/image', ListImageDockerHandler),
        (r'/docker/image/build', BuildImageDockerHandler),
        (r'/docker/image/pull', PullImageDockerHandler),
        (r'/docker/image/run', RunImageDockerHandler),
        (r'/docker/image/delete', DeleteImageDockerHandler),
        (r'/docker/container', ListContainerDockerHandler),
        (r'/docker/container/delete', DeleteContainerDockerHandler),
        (r'/docker/volume', ListVolumeDockerHandler),
        (r'/docker/volume/create', CreateVolumeDockerHandler),
        (r'/docker/volume/delete', DeleteVolumeDockerHandler),

        (r'/monitor', ListMonitorHandler),
        (r'/monitor/start', StartMonitorHandler),
        (r'/monitor/stop', StopMonitorHandler),

        (r'/nginx', ListNginxHandler),
        (r'/nginx/create', CreateNginxHandler),
        (r'/nginx/delete', DeleteNginxHandler),

    ], **settings)

    app.listen(CONFIG_PORT)
    shutdown_event = asyncio.Event()
    await shutdown_event.wait()

if __name__ == '__main__':

    logging.basicConfig(level=logging.DEBUG)

    IPADDRESS=getIP()
    LOCAL_IPADDRESS='127.0.0.1'

    # Check everything is installed and in right version
    should_continue=1
    if sys.version_info[:2] < (3,11):
        should_continue=0
        logging.debug("Python version must be >=3.11")

    try:
        docker_client=docker.from_env()
        if tuple(map(int, ((docker_client.version()['Version']).split("."))))<=(24,0):
            should_continue=0
            logging.debug("Docker version must be >=24.0")
    except:
        should_continue=0
        logging.debug("Docker is not installed")

    nginx_check=subprocess.Popen([f'nginx -v'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,shell=True)
    if "nginx version".casefold() not in f"{nginx_check.communicate()}".casefold():
        logging.debug("Nginx is not installed")

    # If everything is OK run redis and web platform
    if should_continue>0:
        try:
            redis_container=docker_client.containers.get(REDIS_CONTAINER_NAME)
        except:
            admin_set=True
            try:
                docker_client.volumes.get(REDIS_VOLUME_NAME)
            except:
                docker_client.volumes.create(REDIS_VOLUME_NAME,driver='local')
                admin_set=False


            redis_ports: typing.Dict[str, tuple] = {}
            redis_ports[f'{REDIS_PORT}/tcp']=(LOCAL_IPADDRESS,REDIS_PORT)

            redis_container:docker.models.containers.Container = docker_client.containers.run("redis" ,ports=redis_ports,network_mode='bridge'
                                                        , detach=True, remove=True
                                                        , volumes={REDIS_VOLUME_NAME: {'bind': '/data', 'mode': 'rw'}}
                                                        , name=REDIS_CONTAINER_NAME)
            redis_container.reload()
            while redis_container.status != 'running':
                redis_container.reload()
                time.sleep(0.1)
            redis_container.exec_run('redis-cli config set save "10 1"')

            if not admin_set:
                admin=User("admin",hashlib.sha256(b"ASD%^&123").hexdigest(),access_level=1)
                r=redis.Redis(host=LOCAL_IPADDRESS, port=REDIS_PORT)
                r.set("users",json.dumps([admin.json()]))
                r.close()

        logging.info(f"Redis container status: {redis_container.status}")
        logging.info(f'Redis Port: {REDIS_PORT}')

        asyncio.run(tornado_main())        