FROM ubuntu

RUN apt update
RUN apt-get install -y git

RUN apt install -y curl \
  && curl -fsSL https://deb.nodesource.com/setup_16.x | bash - \
  && apt install -y nodejs