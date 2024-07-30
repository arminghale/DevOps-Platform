# Project Management and Deployment Platform 🚀

## Introduction

Hey there! Welcome to your one-stop platform for managing projects and deployment services on a single server. 🎉

### What Can It Do?
- **GitLab Integration**: Add your GitLab credentials, view projects and branches, and deploy branches with custom configurations.
- **Docker Management**: Connect to your server's Docker, manage images, containers, and volumes. Pull images and run them with custom settings.
- **Nginx Configurations**: If you have Nginx installed, manage configurations directly—add new ones or remove old ones without diving into Nginx files.
- **Monitoring Systems**: Activate default configurations for monitoring systems like Grafana or Prometheus with ease.
- **CI/CD Systems**: Managing configuration, create/edit/delete CI/CD configes and execute them with one click.

### A Little Disclaimer 🐞
This is my first version, and I'm new to this! It has a few bugs and isn't fully complete. I'd love your feedback—there are definitely more stable and high-performance tools out there, but hey, I wanted to give this a shot. (Be kind, okay? 😉)

## Setup

### Tested Environments
- **Windows**: 10 (22H2)
- **Ubuntu**: 20.04
- **Requirements**: Python 3.11+ and Docker 24.0+, Nginx is optional.

### How to Run
1. **Run Main Script**: Just fire up `main.py` (after installing requirements.txt).
   - **Default Port**: 444
   - **Default Authentication**: Located in the setup folder.
   - You can tweak settings in `main.py`.

2. **Ubuntu Setup**: Everything you need is in the setup folder, including how to copy files to a remote server with SSH. 😅

> Remember the classic line: "It works on my machine!" 😅

## Feedback
Hope you test this out and share your thoughts to make it better and more user-friendly. My goal is to help people with minimal DevOps knowledge to deploy and manage their projects in single server easily, without needing costly assistance.

---

Happy Deploying! 🚀
