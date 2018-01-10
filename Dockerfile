FROM centos:7
MAINTAINER Robert Abram <robert.abram@entpack.com>

RUN yum -y update; yum clean all
RUN yum -y install epel-release
RUN yum -y install python-pip python-setuptools; yum clean all
RUN yum -y install gcc libffi-devel python-devel openssl-devel; yum clean all
RUN pip install SilentDune-Client 

CMD [ "/bin/bash" ]
