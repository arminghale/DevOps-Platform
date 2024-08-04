import subprocess
import uuid
import gitlab


def CheckGitlab(token:str,gitlab_url:str='https://gitlab.com'):
    try:
        gitlab.Gitlab(url=gitlab_url, private_token=token)
        # gl.auth()
        return True
    except Exception as e:
        return False
        # raise e

class GitlabInfo:
    def __init__(self,token:str,domain:str,user:str,id:str=''):
        self.id=id if id else str(uuid.uuid4())
        self.token=token
        self.domain=domain
        self.user=user # username
    
    def json(self):
        return {
            'id':self.id,
            'token':self.token,
            'domain':self.domain,
            'user':self.user
        }




class GitlabModel:
    def __init__(self,authKey,gitlab_url):
        self.authKey=authKey
        self.gl=gitlab.Gitlab(gitlab_url, private_token=authKey)
    
    def KeyValidation(self):
        try:
            self.gl.auth()
            return self.gl.user
        except Exception as e:
            raise e

    def Projects(self,visibility:str='private'):
        if not self.KeyValidation():
            raise
        return self.gl.projects.list(visibility=visibility,all=True)
    
    def Project(self,id:str):
        if not self.KeyValidation():
            raise
        return self.gl.projects.get(id)

    def Branches(self,projectID:str):
        if not self.KeyValidation():
            raise
        project=self.gl.projects.get(projectID)
        return project.branches.list(all=True)

    def Branch(self,projectID:str,name:str):
        if not self.KeyValidation():
            raise
        project=self.gl.projects.get(projectID)
        return project.branches.get(name)

    def Clone(self,projectName:str,branchName:str,path):
        if not self.KeyValidation():
            raise
        project =  self.gl.projects.get(projectName)
        git_url = project.http_url_to_repo
        git_proc=subprocess.Popen(f'git clone --branch {branchName} --single-branch https://oauth2:{self.authKey}@{git_url.split("https://")[1]} {path}', stdout=subprocess.PIPE, stderr=subprocess.STDOUT,shell=True)
        git_proc.communicate()
        rm_git_folder=subprocess.Popen(['rm','-rf',f'{path}/.git'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,shell=True)
        rm_git_folder.communicate()
