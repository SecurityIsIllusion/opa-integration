
FROM ubuntu:latest
  
ENV TERRAFORM_VERSION=0.12.20

# Proxy variables
#ENV http_proxy http://xxx.xxx.xx.x:xxxx
#ENV https_proxy http://xxx.xxx.xx.x:xxxx
#ENV no_proxy 127.0.0.1,localhost,companyxxx.com,companyxxx.net
#ENV HTTP_PROXY http://xxx.xxx.xx.x:xxxx
#ENV HTTPS_PROXY http://xxx.xxx.xx.x:xxxx
#ENV NO_PROXY 127.0.0.1,localhost,companyxxx.com,companyxxx.net


RUN echo "Hello Ubuntu"

RUN apt-get -y update
RUN apt-get -y install curl
#Install unzip and zip
RUN apt-get -y install unzip zip
#install JSON parser
RUN apt-get -y install jq
#install GIT
RUN apt-get -y install git

#ENTRYPOINT ["/usr/local/bin/opa"]

#Install dependencies and packages - Terraform and OPA
RUN cd /usr/local/bin && \
    curl https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_amd64.zip -o terraform_${TERRAFORM_VERSION}_linux_amd64.zip && \
    unzip terraform_${TERRAFORM_VERSION}_linux_amd64.zip && \
    rm terraform_${TERRAFORM_VERSION}_linux_amd64.zip && \
    ls -ls && \
    terraform version  && \
    #curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64
    curl -L -o opa https://github.com/open-policy-agent/opa/releases/download/v0.17.0/opa_linux_amd64


RUN cd /usr/local/bin && \
    chmod 755 ./opa && \
    ls -l && \
    ./opa version
