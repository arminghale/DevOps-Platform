import json
import os
import shutil
import subprocess
import time
import typing
import uuid
import docker
import redis
import nginx

from CICDModel import CICD
from GitlabModel import CheckGitlab, GitlabInfo, GitlabModel
from UserModel import User


class UserHandler:
    def __init__(self,redis_ip:str,redis_port:int):
        self.redis=redis.Redis(host=redis_ip, port=redis_port)

    def close_redis(self):
        self.redis.close()

    def get_users(self):
        users:typing.List[dict]=json.loads(self.redis.get("users"))
        return users
    
    def get_user_by_username(self,username:str):
        users=self.get_users()
        user=next((x for x in users if x['username'] == username), None)
        return user

    def get_user_by_id(self,id:str):
        users=self.get_users()
        user=next((x for x in users if x['id'] == id), None)
        return user

    def get_user_by_token(self,token:str):
        users=self.get_users()
        user=next((x for x in users if x['token'] == token), None)
        return user

    def delete_user(self,id:str):
        users=self.get_users()
        user=next((x for x in users if x['id'] == id), None)
        if user:
            users.remove(user)
            self.redis.set("users",json.dumps(users))

    def add_user(self,user:User):
        users=self.get_users()
        users.append(user.json())
        self.redis.set("users",json.dumps(users))

    def edit_user(self,user:User):
        users=self.get_users()
        index=next((i for i,item in enumerate(users) if item['id'] == id), -1)
        if index>0:
            users[index]=user.json()
            self.redis.set("users",json.dumps(users))

    def decode_user_from_json(self,user_json):
        return User(
            user_json['username'],
            user_json['password'],
            user_json['token'],
            user_json['expired_date'],
            user_json['access_level'],
            user_json['id']
        )

class GitHandler:
    def __init__(self,redis_ip:str,redis_port:int,token:str=''):
        self.redis=redis.Redis(host=redis_ip, port=redis_port)
        _userhandler=UserHandler(redis_ip,redis_port)
        self.user=_userhandler.decode_user_from_json(_userhandler.get_user_by_token(token))
        _userhandler.close_redis()

    def close_redis(self):
        self.redis.close()

    def get_gits(self):
        gits:typing.List[dict]=json.loads(self.redis.get("gitlabs"))
        if self.user.access_level<1:
            gits=list(filter(lambda x: self.user.username==x['user'], gits))
        return gits
    
    def get_git(self,git:str):
        gits=self.get_gits()
        git=next((item for  i,item in enumerate(gits) if item['id']==git), None)  
        return git
    
    def has_access(self,git:str):
        gits=self.get_gits()
        git=next((item for  i,item in enumerate(gits) if item['id']==git), None)
        if git:
            return True
        return False

    def check_git(self,domain:str,token:str):
        return CheckGitlab(token,domain)

    def get_git_model(self,git:str):
        gits=self.get_gits()
        git=next((item for  i,item in enumerate(gits) if item['id']==git), None)  
        gl=GitlabModel(git['token'],git['domain'])  
        return gl

    def add_git(self,git:GitlabInfo):
        gits=self.get_gits()
        gits.append(git.json())
        self.redis.set("gitlabs",json.dumps(gits))

    def delete_git(self,id:str):
        gits=self.get_gits()
        git=next((x for x in gits if x['id'] == id), None)
        if git:
            gits.remove(git)
            self.redis.set("gitlabs",json.dumps(gits))

    def get_projects(self,git:str):
        gl=self.get_git_model(git)
        projects=gl.Projects()
        for i in range(len(projects)): projects[i]=json.loads(projects[i].to_json())
        return projects
                
    def get_project(self,git:str,project:str):
        gl=self.get_git_model(git) 
        return gl.Project(project).to_json()

    def get_branches(self,git:str,project:str):
        gl=self.get_git_model(git)
        branches=gl.Branches(project)
        for i in range(len(branches)): branches[i]=json.loads(branches[i].to_json())
        return branches
    
    def get_branch(self,git:str,project:str,branch:str):
        gl=self.get_git_model(git)
        return gl.Branch(project,branch).to_json()

    def clone(self,git:str,project:str,branch:str,path:str):
        gl=self.get_git_model(git)
        gl.Clone(project,branch,path)

class DockerHandler:
    def __init__(self,redis_ip:str='',redis_port:int=-1):
        self.docker=docker.from_env()
        if redis_ip and redis_port>0:
            self.redis=redis.Redis(host=redis_ip, port=redis_port)

    def close_redis(self):
        self.redis.close()

    def get_images(self):
        return self.docker.images.list()
    
    def get_image(self,id:str):
        return self.docker.images.get(id)
    
    def get_containers(self):
        return self.docker.containers.list(all=True)

    def delete_container(self,id:str):
        self.docker.containers.get(id).remove(force=True)

    def get_in_use_images(self):
        containers=self.get_containers()
        in_use=[]
        for i in self.get_images():
            if next((x for x in containers if x.image.tags[0] == i.tags[0]), None):
                in_use.append("in use")
            else: in_use.append("unused")
        return in_use

    def delete_image(self,id:str):
        self.docker.images.remove(id)

    def pull_image(self,repository:str,tag:str,platform:str="",username:str="",password:str=""):
        auth_config={}
        if username and password:
            auth_config={'username':username,'password':password}

        return self.docker.images.pull(repository=repository, tag=tag
                                      , auth_config=auth_config if auth_config else None
                                      , platform=platform if platform else None)

    def build_image(self,tag:str,path:str):
        image=self.docker.images.build(tag=tag, path=path, rm=True)[0]
        return image

    def get_volumes(self):
        volumes=json.loads(self.redis.get("volumes"))

        not_in_redis=0
        docker_volumes=self.docker.volumes.list()
        for v in docker_volumes:
            v_in_r=next((x for x in volumes if x['id']==v.id),None)
            if not v_in_r:
                not_in_redis=1
                volumes.append({"id":v.id,'name':v.name,"local_path":"","driver":v.attrs['Driver'],"driver_opts":v.attrs['Options']})
        
        if not_in_redis>0:
            self.redis.set("volumes",json.dumps(volumes))
        return volumes

    def get_volume(self,id:str):
        volumes=self.get_volumes()
        volume=next((x for x in volumes if x['id'] == id), None)
        return volume

    def add_volume(self,volume:dict):
        if not volume["local_path"]:
            vol=self.docker.volumes.create(name=volume["name"],driver=volume["driver"]
                                           ,driver_opts=json.loads(volume["driver_opts"]))
            volume['id']=vol.id
        else:
            volume['id']=str(uuid.uuid4())
            
        volumes=self.get_volumes()
        volumes.append(volume)
        self.redis.set("volumes",json.dumps(volumes))

    def delete_volume(self,id:str):
        volume=self.get_volume(id)
        if not volume['local_path']:
            self.docker.volumes.get(id).remove(force=True)
        else:
            shutil.rmtree(volume['local_path'], ignore_errors=True)

        volumes=self.get_volumes()
        volumes.remove(volume)
        self.redis.set("volumes",json.dumps(volumes))

    def run_container(self,image_id:str,ip:str,port:str,name:str,restart_policy:str,on_failure_retry:int,volumes:str="",env:str=""):
        containers=[]
        inside_port=4583
        for i,p in enumerate(port.split(",")):
            container_ports: typing.Dict[str, tuple] = {}
            container_ports[f'{inside_port}/tcp']=(ip,p)

            res_policy={"Name":restart_policy}
            if restart_policy=="on-failure": res_policy['MaximumRetryCount']=on_failure_retry

            volumes_config={}
            if volumes:
                for v in volumes.split(","):
                    vol=self.get_volume(v.split("||")[0])
                    volumes_config[vol['name'] if not vol['local_path'] else vol['local_path']]={"bind":v.split("||")[2],"mode":v.split("||")[3]}

            container=self.docker.containers.run(image_id, environment=env.split(",") if len(env)>0 else None
                                                    , ports=container_ports, network_mode='bridge'
                                                    , name= f"{name}-{i}", detach=True
                                                    , restart_policy=res_policy
                                                    , volumes=volumes_config)
                
            while container.status != 'running':
                container.reload()
                time.sleep(0.1)
            
            containers.append(container)
        return containers

class MonitorHandler:
    def __init__(self):
        pass

    def get_monitors(self):
        return list(m.name for m in os.scandir("./monitors") if m.is_dir())
    
    def get_in_use_href_monitors(self):
        _dockerhandler=DockerHandler()
        containers=_dockerhandler.get_containers()
        in_use=[]
        href=[]
        for m in self.get_monitors():
            if next((x for x in containers if x.name == m), None):
                in_use.append("active")
                with open(f'./monitors/{m}/setting.json','r',encoding="utf-8-sig") as f:
                    href.append(json.loads(f.read())['ip:port'])
            else: 
                in_use.append("deactivate")
                href.append("")
        
        return in_use,href

    def start_monitor(self,id:str):
        proc=subprocess.Popen([f'docker','compose','-f',f'./monitors/{id}/docker-compose.yml','up','-d'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,shell=True)
        return proc.communicate()

    def stop_monitor(self,id:str):
        _dockerhandler=DockerHandler()
        _dockerhandler.delete_container(id)

class NginxHandler:
    def __init__(self):
        self.nginx_conf=nginx.Conf()
        self.nginx_server=nginx.Server()
    
    def get_nginxs(self):
        nginxs=[]
        for i in list(m.name for m in os.scandir("/etc/nginx/sites-enabled") if not m.is_dir()):
            try:
                c = nginx.loadf(f'/etc/nginx/sites-enabled/{i}')
                nginxs.append(i)
            except: continue
        return nginxs

    def get_nginx(self,name:str):
        if name and name in self.get_nginxs():
            c = nginx.loadf(f'/etc/nginx/sites-enabled/{name}')
            return c.as_dict
        return "{}"

    def add_nginx(self,name:str,expose_port:str,local_port:str,domain:str="",policy=""):        
        self.nginx_upstream=nginx.Upstream(name)
        if policy: self.nginx_upstream.add(nginx.Key(policy,""))
        for loc in local_port.split(','):
            self.nginx_upstream.add(nginx.Key('server',f'localhost:{loc}'))
 
        for exp in expose_port.split(","):
            self.nginx_server.add(nginx.Key('listen', exp))
        if domain:
            self.nginx_server.add(nginx.Key('server_name',domain))
        reverse_proxy=nginx.Location('/',nginx.Key('include','proxy_params'))
        reverse_proxy.add(nginx.Key('proxy_pass',f'http://{name}'))
        # reverse_proxy.add(nginx.Key('health_check',""))
        self.nginx_server.add(reverse_proxy)

        self.nginx_conf.add(self.nginx_upstream)
        self.nginx_conf.add(self.nginx_server)

        nginx.dumpf(self.nginx_conf, f'/etc/nginx/sites-enabled/{name}')

        proc_systemctl=subprocess.Popen('sudo systemctl restart nginx', stdout=subprocess.PIPE, stderr=subprocess.STDOUT,shell=True)
        return proc_systemctl.communicate()

    def delete_nginx(self,id:str):
        os.remove(f"/etc/nginx/sites-enabled/{id}")
        proc=subprocess.Popen('sudo systemctl restart nginx', stdout=subprocess.PIPE, stderr=subprocess.STDOUT,shell=True)
        return proc.communicate()

class CICDHandler:
    def __init__(self,redis_ip:str,redis_port:int):
        self.redis=redis.Redis(host=redis_ip, port=redis_port)

    def close_redis(self):
        self.redis.close()

    def get_cicds(self):
        cicds:typing.List[dict]=json.loads(self.redis.get("cicds"))
        return cicds

    def get_cicd(self,id:str):
        cicds=self.get_cicds()
        cicd=next((x for x in cicds if x['id'] == id), None)
        return cicd

    def delete_cicd(self,id:str):
        cicd=self.get_cicd(id)
        cicds=self.get_cicds()
        cicds.remove(cicd)
        self.redis.set("cicds",json.dumps(cicds))

    def add_cicd(self,cicd:CICD):
        cicds=self.get_cicds()
        cicds.append(cicd.json())
        self.redis.set("cicds",json.dumps(cicds))

    def edit_cicd(self,cicd:dict):
        cicds=self.get_cicds()
        index = next((i for i, item in enumerate(cicds) if item['id'] == cicd['id']), -1)
        cicds[index]=cicd
        self.redis.set("cicds",json.dumps(cicds))




