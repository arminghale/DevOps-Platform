import asyncio
import datetime
import hashlib
from io import BytesIO
import json
import logging
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import typing
import time
import zipfile

import docker.models
import docker.models.containers
import docker

import redis

import tornado.escape
import tornado.ioloop
import tornado.web

from GitlabModel import GitlabInfo
from Repository import CICDHandler, DockerHandler, GitHandler, MonitorHandler, NginxHandler, UserHandler
from UserModel import User
from CICDModel import CICD


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

    def get_token(self):
        return self.get_signed_cookie("credential").decode("utf-8")

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
        _userhandler=UserHandler(LOCAL_IPADDRESS,REDIS_PORT)
        
        if username:
            user_json=_userhandler.get_user_by_username(username)
        elif id:
            user_json=_userhandler.get_user_by_id(id)
        elif token:
            user_json=_userhandler.get_user_by_token(token)
 
        user=_userhandler.decode_user_from_json(user_json)
        _userhandler.close_redis()
        return user

    def get_template_namespace(self):
        namespace = super(BaseHandler, self).get_template_namespace()
        namespace.update({
            'access_level': self.get_user_access(),
            'error': self.get_argument("e",""),
            'title':"Home",
            'items':[],
            'item':'',
            'nginx':NGINX,
        })
        return namespace

    def get_uri_without_error(self):
        uri=self.request.uri
        uri_splitted=uri.split("&e=")
        result=uri_splitted[0]
        if len(uri_splitted)>1:
            result=result+"&"+'&'.join(uri_splitted[1].split("&")[1:])
            
        return result


class HomeHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self) -> None:
        try:
            self.render("home.html")
            return
        except Exception as e:
            self.redirect(f"{self.get_uri_without_error()}&e=system error: {e}")

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
            
            _userhandler=UserHandler(LOCAL_IPADDRESS,REDIS_PORT)
            users=_userhandler.get_users()
            _userhandler.close_redis()

            self.render("User/list.html",items=users,title="Users List")
            return
        except Exception as e:
            self.redirect(f"/&e=system error: {e}")

class DeleteUserHandler(BaseHandler):
    @tornado.web.authenticated
    async def get(self) -> None:
        try:
            if self.get_user_access()<1:
                self.redirect(f"/?e=no access")
            
            id=self.get_argument("id","")
            if not id:
                self.redirect("/user")

            _userhandler=UserHandler(LOCAL_IPADDRESS,REDIS_PORT)
            _userhandler.delete_user(id)
            _userhandler.close_redis()
            
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
                self.redirect(f"{self.get_uri_without_error()}&e=enter username and password")
            if access_level<0:
                self.redirect(f"{self.get_uri_without_error()}&e=enter positive number for access level")
            
            _userhandler=UserHandler(LOCAL_IPADDRESS,REDIS_PORT)

            if _userhandler.get_user_by_username(username=username):
                self.redirect(f"{self.get_uri_without_error()}&e=user with this username exists")


            user=User(username,hashlib.sha256(password.encode("utf-8")).hexdigest(),access_level=access_level)
            _userhandler.add_user(user)
            _userhandler.close_redis()

            self.redirect("/user")
        except Exception as e:
            self.redirect(f"{self.get_uri_without_error()}&e=system error: {e}")

class EditUserHandler(BaseHandler):
    @tornado.web.authenticated
    async def get(self) -> None:
        try:
            if self.get_user_access()<1:
                self.redirect(f"/?e=no access")
            
            id=self.get_argument("id","")
            if not id:
                self.redirect("/user")

            _userhandler=UserHandler(LOCAL_IPADDRESS,REDIS_PORT)

            user=_userhandler.get_user_by_id(id)
            _userhandler.close_redis()
            if not user:
                self.redirect(f"/user?e=system error: user not found")

            self.render("User/edit.html",item=user,title="Edit User")
            return
        except Exception as e:
            self.redirect(f"/user?e=system error: {e}")
    
    @tornado.web.authenticated
    async def post(self) -> None:
        try:
            if self.get_user_access()<1:
                self.redirect(f"/?e=no access")
            
            id= self.get_argument("id")
            username= self.get_argument("username")
            password= self.get_argument("password")
            access_level= self.get_argument("access_level")
           

            if not username:
                self.redirect(f"{self.get_uri_without_error()}&e=enter username")
            if access_level<0:
                self.redirect(f"{self.get_uri_without_error()}&e=enter positive number for access level")
            
            _userhandler=UserHandler(LOCAL_IPADDRESS,REDIS_PORT)

            user=_userhandler.decode_user_from_json(_userhandler.get_user_by_id(id=id))
            if not user:
                self.redirect(f"{self.get_uri_without_error()}&e=user not found")

            if _userhandler.get_user_by_id(username=username)['id']!=id:
                self.redirect(f"{self.get_uri_without_error()}&e=user with this username exists")

            user.username=username
            user.access_level=access_level
            if password:
                user.password=hashlib.sha256(password.encode("utf-8")).hexdigest()

            _userhandler.edit_user(user)
            _userhandler.close_redis()

            self.redirect("/user")
        except Exception as e:
            self.redirect(f"{self.get_uri_without_error()}&e=system error: {e}")


class ListGitlabHandler(BaseHandler):
    @tornado.web.authenticated
    async def get(self) -> None:
        try:
            _githanlder=GitHandler(LOCAL_IPADDRESS,REDIS_PORT,self.get_token())
            gitlabs=_githanlder.get_gits()
            _githanlder.close_redis()

            self.render("Gitlab/list.html",items=gitlabs,title="Gitlabs List")
            return
        except Exception as e:
            self.redirect(f"/&e=system error: {e}")

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
                self.redirect(f"{self.get_uri_without_error()}&e=enter token and domain")
            
            _githanlder=GitHandler(LOCAL_IPADDRESS,REDIS_PORT,self.get_token())
            
            if not _githanlder.check_git(domain,token):
                self.redirect(f"{self.get_uri_without_error()}&e=can't login with this information")
   
            gitlab=GitlabInfo(token,domain,self.get_user_username())
            _githanlder.add_git(gitlab)
            _githanlder.close_redis()

            self.redirect("/gitlab/credential")
        except Exception as e:
            self.redirect(f"{self.get_uri_without_error()}&e=system error: {e}")

class DeleteGitlabHandler(BaseHandler):
    @tornado.web.authenticated
    async def get(self) -> None:
        try:
            id=self.get_argument("id","")
            if not id:
                self.redirect("/gitlab/credential")


            _githanlder=GitHandler(LOCAL_IPADDRESS,REDIS_PORT,self.get_token())
            _githanlder.delete_git(id)
            _githanlder.close_redis()

            self.redirect("/gitlab/credential")
        except Exception as e:
            self.redirect(f"/gitlab/credential?e=system error: {e}")

class ListProjectGitlabHandler(BaseHandler):
    @tornado.web.authenticated
    async def get(self) -> None:
        try:
            selected_gitlab=self.get_argument("gitlab","")
            selected_project=self.get_argument("project","")
            projects=[]

            _githanlder=GitHandler(LOCAL_IPADDRESS,REDIS_PORT,self.get_token())

            if selected_gitlab:
                if selected_project:
                    project=_githanlder.get_project(selected_gitlab,selected_project)
                    self.render("details_json.html",item=project,title="Gitlabs Project")
                    return
                
                projects=_githanlder.get_projects(selected_gitlab)
            _githanlder.close_redis()
            self.render("Gitlab/project_list.html",items=projects,title="Gitlabs Projects List")
            return
        except Exception as e:
            self.redirect(f"/&e=system error: {e}")

class ListBranchGitlabHandler(BaseHandler):
    @tornado.web.authenticated
    async def get(self) -> None:
        try:
            selected_gitlab=self.get_argument("gitlab","")
            selected_project=self.get_argument("project","")
            selected_branch=self.get_argument("branch","")
            
            branches=[]

            _githanlder=GitHandler(LOCAL_IPADDRESS,REDIS_PORT,self.get_token())

            if selected_gitlab:
                if selected_project: 
                    if selected_branch:
                        branch=_githanlder.get_branch(selected_gitlab,selected_project,selected_branch)
                        self.render("details_json.html",item=branch,title="Gitlabs Project Branch")
                        return
                    branches=_githanlder.get_branches(selected_gitlab,selected_project)
            _githanlder.close_redis()
            self.render("Gitlab/branch_list.html",items=branches,title="Gitlabs Project Branches List")
            return
        except Exception as e:
            self.redirect(f"/&e=system error: {e}")

class ListGitlabAPIHandler(BaseHandler):
    @tornado.web.authenticated
    async def get(self) -> None:
        try:
            _githanlder=GitHandler(LOCAL_IPADDRESS,REDIS_PORT,self.get_token())
            gitlabs=_githanlder.get_gits()
            _githanlder.close_redis()

            self.write(json.dumps(gitlabs))
            self.finish()
        except Exception as e:
            self.set_status(500)
            self.write(f"system error: {e}")
            self.finish()

class ListProjectGitlabAPIHandler(BaseHandler):
    @tornado.web.authenticated
    async def get(self) -> None:
        try:
            selected_gitlab=self.get_argument("gitlab")
            projects=[]

            _githanlder=GitHandler(LOCAL_IPADDRESS,REDIS_PORT,self.get_token())
            projects=_githanlder.get_projects(selected_gitlab)
            _githanlder.close_redis()

            self.write(json.dumps(projects))
            self.finish()
        except Exception as e:
            self.set_status(500)
            self.write(f"system error: {e}")
            self.finish()

class ListBranchGitlabAPIHandler(BaseHandler):
    @tornado.web.authenticated
    async def get(self) -> None:
        try:
            selected_gitlab=self.get_argument("gitlab")
            selected_project=self.get_argument("project")

            branches=[]

            _githanlder=GitHandler(LOCAL_IPADDRESS,REDIS_PORT,self.get_token())
            branches=_githanlder.get_branches(selected_gitlab,selected_project)
            _githanlder.close_redis()

            self.write(json.dumps(branches))
            self.finish()
        except Exception as e:
            self.set_status(500)
            self.write(f"system error: {e}")
            self.finish()


class ListImageDockerHandler(BaseHandler):
    @tornado.web.authenticated
    async def get(self) -> None:
        try:
            _dockerhandler=DockerHandler()
            images=_dockerhandler.get_images()
            in_use=_dockerhandler.get_in_use_images()

            self.render("Docker/image_list.html",items=images,in_use=in_use,title="Docker Image List")
            return
        except Exception as e:
            self.redirect(f"/&e=system error: {e}")

class DeleteImageDockerHandler(BaseHandler):
    @tornado.web.authenticated
    async def get(self) -> None:
        try:
            id=self.get_argument("id","")
            if not id:
                self.redirect("/docker/image")

            _dockerhandler=DockerHandler()
            _dockerhandler.delete_image(id)

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
            
            _dockerhandler=DockerHandler()
            image=_dockerhandler.get_image(id)
            _dockerhandler.close_redis()

            self.render("Docker/run.html",image=image,title="Run Docker Image")
            return
        except Exception as e:
            self.redirect(f"/docker/image?e=system error: {e}")

    @tornado.web.authenticated
    async def post(self) -> None:
        try:
            id= self.get_argument("id")
            env=self.get_argument("env")
            port=self.get_argument("port")
            name=self.get_argument("name")
            ip=self.get_argument("ip","127.0.0.1")
            restart_policy=self.get_argument("restart_policy")
            on_failure_retry=int(self.get_argument("on_failure_retry","1"))
            volumes=self.get_argument("volumes","")

            if restart_policy!="always" and restart_policy!="on-failure":
                self.redirect(f"{self.get_uri_without_error()}&e=restart policy is invalid")

            if ip=="expose":
                ip=getIP()
            
            _dockerhandler=DockerHandler(LOCAL_IPADDRESS,REDIS_PORT)
            _dockerhandler.run_container(id,ip,port,name,restart_policy,on_failure_retry,volumes,env)
            _dockerhandler.close_redis()

            self.redirect("/docker/container")
        except Exception as e:
            self.redirect(f"{self.get_uri_without_error()}&e=system error: {e}")

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
                self.redirect(f"{self.get_uri_without_error()}&e=enter repository")
            
            _dockerhandler=DockerHandler()
            _dockerhandler.pull_image(repository,tag,platform,username,password)

            self.redirect("/docker/image")
        except Exception as e:
            self.redirect(f"{self.get_uri_without_error()}&e=system error: {e}")

class BuildImageDockerHandler(BaseHandler):
    @tornado.web.authenticated
    async def get(self) -> None:
        try:
            branch= self.get_argument("branch")
            project=self.get_argument("project")
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
        try:
            branch= self.get_argument("brnach")
            project=self.get_argument("project")
            run=int(self.get_argument("run","0"))
            gitlab=self.get_argument("gitlab")
            spath= self.get_argument("spath")
            bpath= self.get_argument("bpath")
            tag= self.get_argument("tag")
            name= self.get_argument("name")

            if not spath or not bpath or not tag or not branch or not project or not gitlab or not name:
                self.redirect(f"{self.get_uri_without_error()}&e=fill out all entries")

            _githanlder=_githanlder=GitHandler(LOCAL_IPADDRESS,REDIS_PORT,self.get_token())
            if not _githanlder.has_access(gitlab):
                self.redirect(f"{self.get_uri_without_error()}&e=no access to selected gitlab")
            _githanlder.clone(gitlab,project,branch,spath)

            _dockerhandler=DockerHandler()
            image=_dockerhandler.build_image(f"{name}:{tag}",f"{spath}{bpath}")

            shutil.rmtree(os.rmdir(spath), ignore_errors=True)

            if run>0:
                self.redirect(f"/docker/image/run?id={image.id}")

            self.redirect("/docker/image")
        except Exception as e:
            self.redirect(f"{self.get_uri_without_error()}&e=system error: {e}")
            
class ListContainerDockerHandler(BaseHandler):
    @tornado.web.authenticated
    async def get(self) -> None:
        try:
            _dockerhandler=DockerHandler()
            containers=_dockerhandler.get_containers()
            self.render("Docker/container_list.html",items=containers,title="Docker Container List")
            return
        except Exception as e:
            self.redirect(f"/&e=system error: {e}")

class DeleteContainerDockerHandler(BaseHandler):
    @tornado.web.authenticated
    async def get(self) -> None:
        try:
            id=self.get_argument("id","")
            if not id:
                self.redirect("/docker/container")

            _dockerhandler=DockerHandler()
            _dockerhandler.delete_container(id)

            self.redirect("/docker/container")
        except Exception as e:
            self.redirect(f"/docker/container?e=system error: {e}")

class ListVolumeDockerHandler(BaseHandler):
    @tornado.web.authenticated
    async def get(self) -> None:
        try:
            _dockerhandler=DockerHandler(LOCAL_IPADDRESS,REDIS_PORT)
            volumes=_dockerhandler.get_volumes()
            _dockerhandler.close_redis()

            self.render("Docker/volume_list.html",items=volumes,title="Docker Volume List")
            return
        except Exception as e:
            self.redirect(f"/&e=system error: {e}")

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
            local_path= self.get_argument("local_path","")

            if not name:
                self.redirect(f"{self.get_uri_without_error()}&e=enter name")
            
            if driver_opts:
                try:
                    driver_opts=json.loads(driver_opts)
                except:
                    self.redirect(f"{self.get_uri_without_error()}&e=driver options not in write format")

            volume={'name':name,"local_path":local_path,"driver":driver,"driver_opts":driver_opts}

            _dockerhandler=DockerHandler(LOCAL_IPADDRESS,REDIS_PORT)
            _dockerhandler.add_volume(volume)
            _dockerhandler.close_redis()

            self.redirect("/docker/volume")
        except Exception as e:
            self.redirect(f"{self.get_uri_without_error()}&e=system error: {e}")

class DeleteVolumeDockerHandler(BaseHandler):
    @tornado.web.authenticated
    async def get(self) -> None:
        try:
            id=self.get_argument("id","")
            if not id:
                self.redirect("/docker/volume")

            _dockerhandler=DockerHandler(LOCAL_IPADDRESS,REDIS_PORT)
            _dockerhandler.delete_volume(id)
            _dockerhandler.close_redis()

            self.redirect("/docker/volume")
        except Exception as e:
            self.redirect(f"/docker/volume?e=system error: {e}")

class DownloadVolumeDockerHandler(BaseHandler):
    @tornado.web.authenticated
    async def get(self) -> None:
        try:
            id=self.get_argument("id","")
            if not id:
                self.redirect("/docker/volume")

            _dockerhandler=DockerHandler(LOCAL_IPADDRESS,REDIS_PORT)
            volume=_dockerhandler.get_volume(id)
            _dockerhandler.close_redis()

            if not volume["local_path"]:
                docker_client=docker.from_env()
                volume_docker=docker_client.volumes.get(id)
                image=docker_client.images.pull("busybox","latest")

                volumes_config={}
                volumes_config[volume_docker.name]={"bind":"/volume","mode":"rw"}
                volumes_config[f"{os.getcwd()}/volume_data"]={"bind":"/volume_data","mode":"rw"}

                container=docker_client.containers.run(image,volumes=volumes_config,detach=True
                                                    ,command="cp -a /volume/. /volume_data")
                container.remove(force=True)

                dir = Path(f"{os.getcwd()}/volume_data")
            else:
                dir = Path(volume["local_path"])
            f=BytesIO()
            with zipfile.ZipFile(f"{os.getcwd()}/data.zip", "w", zipfile.ZIP_DEFLATED) as zip_file:
                for entry in dir.rglob("*"):
                    zip_file.write(entry, entry.relative_to(dir))
                zip_file.close()
            
            if not volume["local_path"]:
                shutil.rmtree(f"{os.getcwd()}/volume_data", ignore_errors=True)
            
            f=open(f"{os.getcwd()}/data.zip","rb")
            self.set_header('Content-Type', 'application/zip')
            self.set_header("Content-Disposition", "attachment; filename=%s" % "data.zip")
            self.write(f.read())
            f.close()
            
            os.remove(f"{os.getcwd()}/data.zip")
                
            self.finish()
        except Exception as e:
            self.redirect(f"/docker/volume?e=system error: {e}")

class ListVolumeDockerAPIHandler(BaseHandler):
    @tornado.web.authenticated
    async def get(self) -> None:
        try:
            _dockerhandler=DockerHandler(LOCAL_IPADDRESS,REDIS_PORT)
            volumes=_dockerhandler.get_volumes()
            _dockerhandler.close_redis()

            self.write(json.dumps(volumes))
            self.finish()
        except Exception as e:
            self.set_status(500)
            self.write(f"system error: {e}")
            self.finish()


class ListMonitorHandler(BaseHandler):
    @tornado.web.authenticated
    async def get(self) -> None:
        try:
            _monitorhandler=MonitorHandler()
            monitors=_monitorhandler.get_monitors()
            in_use,href=_monitorhandler.get_in_use_href_monitors()

            self.render("Monitor/list.html",items=monitors,in_use=in_use,href=href,title="Monitor List")
            return
        except Exception as e:
            self.redirect(f"/&e=system error: {e}")

class StartMonitorHandler(BaseHandler):
    @tornado.web.authenticated
    async def get(self) -> None:
        try:
            id=self.get_argument("id","")
            if not id:
                self.redirect("/monitor")

            _monitorhandler=MonitorHandler()
            result=_monitorhandler.start_monitor(id)

            self.redirect(f"/monitor?e={result}")
        except Exception as e:
            self.redirect(f"/monitor?e=system error: {e}")

class StopMonitorHandler(BaseHandler):
    @tornado.web.authenticated
    async def get(self) -> None:
        try:
            id=self.get_argument("id","")
            if not id:
                self.redirect("/monitor")

            _monitorhandler=MonitorHandler()
            _monitorhandler.stop_monitor(id)

            self.redirect("/monitor")
        except Exception as e:
            self.redirect(f"/monitor?e=system error: {e}")


class ListNginxHandler(BaseHandler):
    @tornado.web.authenticated
    async def get(self) -> None:
        try:
            name=self.get_argument("name","")

            _nginxhandler=NginxHandler()

            if name:
                self.render("details_json.html",item=_nginxhandler.get_nginx(name),title="Nginx Detail")
                return
            
            nginxs=_nginxhandler.get_nginxs()

            self.render("Nginx/list.html",items=nginxs,title="Nginx List")
            return
        except Exception as e:
            self.redirect(f"/&e=system error: {e}")

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
            policy= self.get_argument("policy","")

            _nginxhandler=NginxHandler()
            result=_nginxhandler.add_nginx(name,expose_port,local_port,domain,policy)

            self.redirect(f"/nginx?e={result}")
        except Exception as e:
            self.redirect(f"{self.get_uri_without_error()}&e=system error: {e}")

class DeleteNginxHandler(BaseHandler):
    @tornado.web.authenticated
    async def get(self) -> None:
        try:
            id=self.get_argument("id","")
            if not id:
                self.redirect("/nginx")

            _nginxhandler=NginxHandler()
            result=_nginxhandler.delete_nginx(id)

            self.redirect(f"/nginx?e={result}")
        except Exception as e:
            self.redirect(f"/nginx?e=system error: {e}")


class ListCICDHandler(BaseHandler):
    @tornado.web.authenticated
    async def get(self) -> None:
        try:
            id=self.get_argument("id","")

            _cicdhandler=CICDHandler(LOCAL_IPADDRESS,REDIS_PORT)

            if id:
                self.render("details_json.html",item=_cicdhandler.get_cicd(id),title="CI/CD Config")
                return
            cicds=_cicdhandler.get_cicds()
            _cicdhandler.close_redis()
            self.render("CICD/list.html",items=cicds,title="CI/CD List")
            return
        except Exception as e:
            self.redirect(f"/?e=system error: {e}")

class DeleteCICDHandler(BaseHandler):
    @tornado.web.authenticated
    async def get(self) -> None:
        try:
            id=self.get_argument("id","")
            if not id:
                self.redirect("/cicd")


            _cicdhandler=CICDHandler(LOCAL_IPADDRESS,REDIS_PORT)
            _cicdhandler.delete_cicd(id)
            _cicdhandler.close_redis()

            self.redirect("/cicd")
        except Exception as e:
            self.redirect(f"/cicd?e=system error: {e}")

class CreateCICDHandler(BaseHandler):
    @tornado.web.authenticated
    async def get(self) -> None:
        try:

            self.render("CICD/create.html",title="Create CICD")
            return
        except Exception as e:
            self.redirect(f"/cicd?e=system error: {e}")
    
    @tornado.web.authenticated
    async def post(self) -> None:
        try:
            gitlab= self.get_argument("gitlab")
            project= self.get_argument("project")
            branch= self.get_argument("branch")
            name= self.get_argument("name")
            image_name= self.get_argument("image_name")
            image_spath= self.get_argument("image_spath")
            image_bpath= self.get_argument("image_bpath")
            image_tag= self.get_argument("image_tag")
            container_env=self.get_argument("container_env")
            container_port=(self.get_argument("container_port"))
            container_name=self.get_argument("container_name")
            container_ip=self.get_argument("container_ip","127.0.0.1")
            container_restart_policy=self.get_argument("container_restart_policy")
            container_on_failure_retry=int(self.get_argument("container_on_failure_retry","1"))
            volumes=self.get_argument("volumes")
            
            _githandler=GitHandler(LOCAL_IPADDRESS,REDIS_PORT,self.get_token())
            selected_gitlab=_githandler.get_git(gitlab)
            selected_project=_githandler.get_project(gitlab,project)
            _githandler.close_redis()

            cicd=CICD(name,f"{selected_gitlab['user']}|{selected_gitlab['domain']}",gitlab,selected_project['name'],project,branch
                      ,image_name,image_spath,image_bpath,image_tag
                      ,container_name,container_port,container_ip,container_env,container_restart_policy,container_on_failure_retry
                      ,volumes)
            
            _cicdhandler=CICDHandler(LOCAL_IPADDRESS,REDIS_PORT)
            _cicdhandler.add_cicd(cicd)
            _cicdhandler.close_redis()

            self.redirect("/cicd")
        except Exception as e:
            self.redirect(f"{self.get_uri_without_error()}&e=system error: {e}")

class EditCICDHandler(BaseHandler):
    @tornado.web.authenticated
    async def get(self) -> None:
        try:
            
            id=self.get_argument("id","")
            if not id:
                self.redirect("/cicd")

            _cicdhandler=CICDHandler(LOCAL_IPADDRESS,REDIS_PORT)
            cicd=_cicdhandler.get_cicd(id)
            if not cicd:
                self.redirect(f"/cicd?e=system error: cicd not found")
            _cicdhandler.close_redis()

            self.render("CICD/edit.html",item=cicd,title="Edit CICD")
            return
        except Exception as e:
            self.redirect(f"/cicd?e=system error: {e}")
    
    @tornado.web.authenticated
    async def post(self) -> None:
        try:
            id= self.get_argument("id")
            gitlab= self.get_argument("gitlab")
            project= self.get_argument("project")
            branch= self.get_argument("branch")
            name= self.get_argument("name")
            image_name= self.get_argument("image_name")
            image_spath= self.get_argument("image_spath")
            image_bpath= self.get_argument("image_bpath")
            image_tag= self.get_argument("image_tag")
            container_env=self.get_argument("container_env")
            container_port=(self.get_argument("container_port"))
            container_name=self.get_argument("container_name")
            container_ip=self.get_argument("container_ip","127.0.0.1")
            container_restart_policy=self.get_argument("container_restart_policy")
            container_on_failure_retry=int(self.get_argument("container_on_failure_retry","1"))
            volumes=self.get_argument("volumes")
            

            _githandler=GitHandler(LOCAL_IPADDRESS,REDIS_PORT,self.get_token())
            selected_gitlab=_githandler.get_git(gitlab)
            selected_project=json.loads(_githandler.get_project(gitlab,project))
            _githandler.close_redis()
            
            _cicdhandler=CICDHandler(LOCAL_IPADDRESS,REDIS_PORT)
            cicd=_cicdhandler.get_cicd(id)

            cicd['gitlab']=f"{selected_gitlab['user']}|{selected_gitlab['domain']}"
            cicd['gitlab_id']=gitlab
            cicd['project']=selected_project['name']
            cicd['project_id']=project
            cicd['branch']=branch
            cicd['name']=name
            cicd['image_name']=image_name
            cicd['image_spath']=image_spath
            cicd['image_bpath']=image_bpath
            cicd['image_tag']=image_tag
            cicd['container_name']=container_name
            cicd['container_port']=container_port
            cicd['container_ip']=container_ip
            cicd['container_env']=container_env
            cicd['container_restart_policy']=container_restart_policy
            cicd['container_on_failure_retry']=container_on_failure_retry
            cicd['volumes']=volumes
            cicd['update_date']=datetime.datetime.now().strftime("%Y-%m-%d, %H:%M:%S")
            
            _cicdhandler.edit_cicd(cicd)
            _cicdhandler.close_redis()

            self.redirect("/cicd")
        except Exception as e:
            self.redirect(f"{self.get_uri_without_error()}&e=system error: {e}")

class RunCICDHandler(BaseHandler):
    @tornado.web.authenticated
    async def get(self) -> None:
        try:
            id=self.get_argument("id","")
            if not id:
                self.redirect("/cicd")

            _cicdhandler=CICDHandler(LOCAL_IPADDRESS,REDIS_PORT)
            cicd=_cicdhandler.get_cicd(id)
            _cicdhandler.close_redis()
            if not cicd:
                self.redirect(f"/cicd?e=cicd not found")

            _githandler=GitHandler(LOCAL_IPADDRESS,REDIS_PORT,self.get_token())
            _githandler.clone(cicd['gitlab_id'],cicd['project_id'],cicd['branch'],cicd['image_spath'])
            _githandler.close_redis()

            _dockerhandler=DockerHandler(LOCAL_IPADDRESS,REDIS_PORT)
            image=_dockerhandler.build_image(f"{cicd['image_name']}:{cicd['image_tag']}",f"{cicd['image_spath']}{cicd['image_bpath']}")

            shutil.rmtree(cicd['image_spath'], ignore_errors=True)

            if cicd['container_ip']=="expose":
                cicd['container_ip']=getIP()

            containers=_dockerhandler.run_container(image.id,cicd['container_ip'],cicd['container_port']
                                                   ,cicd['container_name'],cicd['container_restart_policy']
                                                   ,cicd['container_on_failure_retry'],cicd['volumes']
                                                   ,cicd['container_env'])

            _dockerhandler.close_redis()

            self.redirect(f"/cicd?e=Done!")
        except Exception as e:
            self.redirect(f"/cicd?e=system error: {e}")


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
        (r'/api/gitlab/credential', ListGitlabAPIHandler),
        (r'/api/gitlab/project', ListProjectGitlabAPIHandler),
        (r'/api/gitlab/branch', ListBranchGitlabAPIHandler),

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
        (r'/docker/volume/download', DownloadVolumeDockerHandler),
        (r'/api/docker/volume', ListVolumeDockerAPIHandler),

        (r'/monitor', ListMonitorHandler),
        (r'/monitor/start', StartMonitorHandler),
        (r'/monitor/stop', StopMonitorHandler),

        (r'/nginx', ListNginxHandler),
        (r'/nginx/create', CreateNginxHandler),
        (r'/nginx/delete', DeleteNginxHandler),

        (r'/cicd', ListCICDHandler),
        (r'/cicd/create', CreateCICDHandler),
        (r'/cicd/edit', EditCICDHandler),
        (r'/cicd/delete', DeleteCICDHandler),
        (r'/cicd/run', RunCICDHandler),

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
        NGINX=0
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

        r=redis.Redis(host=LOCAL_IPADDRESS, port=REDIS_PORT)
        users=r.get("users")
        volumes=r.get("volumes")
        cicds=r.get("cicds")
        gitlabs=r.get("gitlabs")
        if not users:
            admin=User("admin",hashlib.sha256(b"ASD%^&123").hexdigest(),access_level=1)
            r.set("users",json.dumps([admin.json()]))
        if not volumes:
            r.set("volumes",json.dumps([]))
        if not cicds:
            r.set("cicds",json.dumps([]))
        if not gitlabs:
            r.set("gitlabs",json.dumps([]))

        r.close()

        logging.info(f"Redis container status: {redis_container.status}")
        logging.info(f'Redis Port: {REDIS_PORT}')

        asyncio.run(tornado_main())        