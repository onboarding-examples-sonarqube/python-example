## Overview

This project is an example of using GitHub Actions pipeline for a python project. It demonstrates how to set up a CI/CD pipeline for a Python application.  
We have multiple CI/CD Pipeline examples, one for running the SonarScanner and sending the results to SonarQube Server and the other for sending the results to SonarQube Cloud.  

PLEASE READ OUR SONARQUBE DOCUMENTATION FOR WORKING WITH GITHUB ACTION PIPELINES  
GitHub - SonarQube Server Integration > https://docs.sonarsource.com/sonarqube-server/latest/devops-platform-integration/github-integration/introduction/  
GitHub Actions Pipelines - SonarQube Cloud > https://docs.sonarsource.com/sonarqube-cloud/getting-started/github/#ci-based-analysis 

## Important Information in Pipelines
- on triggers are set to only execute on changes to specific branches and a specific directory in the project, this can be modified with whatever you would want to specify.
- they have shallow fetch set to 0. this is required for SonarScanner to properly analyze your project.  
- for more information on how to limit your analysis scope and parameters available, please check **SonarScanner Analysis Scope** and **SonarScanner Analysis Parameters** in the Important Links section.
- Please remember that there are different tasks for SonarQube Server and SonarQube Cloud. Examples for both are provided.
    - SonarQube Cloud Example: sonarqube-cloud.yml  
    - SonarQube Server Example: sonarqube-server.yml 

## Important Links
SonarQube Server Scan GitHub Action task > https://github.com/marketplace/actions/official-sonarqube-scan
SonarQube Cloud Scan GitHub Action task >  https://github.com/marketplace/actions/sonarqube-cloud-scan
SonarScanner Analysis Scope > https://docs.sonarsource.com/sonarqube-server/latest/project-administration/analysis-scope/  
SonarScanner Analysis Parameters > https://docs.sonarsource.com/sonarqube-server/latest/analyzing-source-code/analysis-parameters/  

## Example to fail the entire pipeline if Quality Gate fails
There may be situations or branches in which you will like to fail the pipeline if the SonarQube Quality Gate fails in order to stop any other steps in the pipeline.  
This can be done by adding ```sonar.qualitygate.wait=true``` 
to the **with: args: >** section in the **SonarQube Scan** task.  

Example
``` sh
    with:
        args: >
          -Dsonar.verbose=true
          -Dsonar.sources=src/
          -Dsonar.qualitygate.wait=true
```

## PR Decoration Test  (still working on these instructions)
In SonarQube (Server and Cloud), there is functionality to be able to block PR from being merged to SonarQube  
In GitHub Actions, you need to have the following set up in your Project:  
- Setup a Branch Protetction Rule 
- Select a Target branch to apply the rule to

SonarQube Documentation:
https://docs.sonarsource.com/sonarqube-server/latest/devops-platform-integration/github-integration/setting-up-at-project-level/#prevent-pull-request-merge  

In SonarQube Server, you need to make sure the DevOps Integration is correctly configured. Go to the Project, in Project Settings > General Settings > DevOps Platform Integration.
In SonarQube Cloud, you need to make sure the DevOps Integration is correctly configured. Go to the Project, in Administration > General Settings > Repository Binding. 

To test this, follow these steps:
1. Create New Branch
2. In new branch, go to file src/s1940.py
3. Add the following code snippet
``` sh
def fun(a):
  i = 10
  return i + a       # Noncompliant
  i += 1             # this is never executed
```
4. Create PR to merge to the target branch you have set the Branch Protection Rule
5. Wait for the SonarQube Scanner analysis to complete
6. It should Fail and have the PR get blocked from merging