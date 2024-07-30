import datetime
import uuid


class CICD:
    def __init__(self,name:str,gitlab:str,gitlab_id:str,project:str,project_id:str,branch:str
                 ,image_name:str,image_spath:str,image_bpath:str,image_tag:str
                 ,container_name:str,container_port:int,container_ip:str,container_env:str,container_restart_policy:str,container_on_failure_retry:int
                 ,volumes:str):
        self.id=str(uuid.uuid4())
        self.create_date=datetime.datetime.now()
        self.update_date=datetime.datetime.now()
        self.name=name
        self.gitlab=gitlab
        self.gitlab_id=gitlab_id
        self.project=project
        self.project_id=project_id
        self.branch=branch
        self.image_name= image_name
        self.image_spath= image_spath
        self.image_bpath=image_bpath
        self.image_tag= image_tag
        self.container_env=container_env
        self.container_port=container_port
        self.container_name=container_name
        self.container_ip=container_ip
        self.container_restart_policy=container_restart_policy
        self.container_on_failure_retry=container_on_failure_retry
        self.volumes=volumes

    
    def json(self):
        return {
            'id':self.id,
            'name':self.name,
            'create_date':self.create_date.strftime("%Y-%m-%d, %H:%M:%S"),
            'update_date':self.update_date.strftime("%Y-%m-%d, %H:%M:%S"),
            'gitlab':self.gitlab,
            'gitlab_id':self.gitlab_id,
            'project':self.project,
            'project_id':self.project_id,
            'branch':self.branch,
            'image_name':self.image_name,
            'image_spath':self.image_spath,
            'image_bpath':self.image_bpath,
            'image_tag':self.image_tag,
            'container_name':self.container_name,
            'container_env':self.container_env,
            'container_port':self.container_port,
            'container_ip':self.container_ip,
            'container_restart_policy':self.container_restart_policy,
            'container_on_failure_retry':self.container_on_failure_retry,
            'volumes':self.volumes,
        }
