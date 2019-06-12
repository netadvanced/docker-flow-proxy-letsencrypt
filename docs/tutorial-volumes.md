# Automatic LetsEncrypt support for docker-flow-proxy

## Setup

You need a swarm setup with docker 1.12+ (docker 1.13+ for secret support).

```
# create the proxy overlay network
docker network create --driver overlay proxy

# create the le-cert volume to store generated certs.
docker volume create [--driver <your_favorite_volume_driver>] le-certs
```

!!! info
You also need to setup your DNS provider to redirect DNS hostnames to the correct hosts. In this example we will use **.example.com** domain name.

## The stack

### docker-flow-proxy-letsencrypt

Let's start creating the `docker-flow-proxy-letsencrypt` service.

```
docker service create --name proxy_proxy-le \
	--network proxy \
	-e DF_PROXY_SERVICE_NAME=proxy_proxy \
	-e CERTBOT_OPTIONS=--staging \
	--mount "type=volume,source=le-certs,destination=/etc/letsencrypt" \
	--label com.df.notify=true \
	--label com.df.distribute=true \
	--label com.df.servicePath=/.well-known/acme-challenge \
	--label com.df.port=8080 \
	nib0r/docker-flow-proxy-letsencrypt
```

This will create and start the `docker-flow-proxy-letsencrypt` service in the **proxy** network, using the **le-certs** volume.

This service will be registered as a proxied service by `docker-flow-proxy` using labels **com.df.notify**, **com.df.distribute**, **com.df.servicePath**, **com.df.port**. This allows `docker-flow-proxy-letsencrypt` to answer to the ACME challenge performed by letsencrypt.

!!! info
During this tutorial, we recommend you to use the **CERTBOT_OPTION=--staging** environment variable that will use the staging api of letsencrypt. You will not hit rate limits problems in case your something go wrong (DFPLE side or your services). This will generate untrusted certificate. When everything is correctly working, remove the environment variable and real certificates will be generated.

### docker-flow-proxy stack

Create a volume for **/certs** folder which contains all certificates registered by `docker-flow-proxy`. This will enable persistent certificates on DFP side.

```
docker volume create [--driver <your_favorite_volume_driver>] dfp-certs
```

Start `docker-flow-proxy` service.

```
docker service create --name proxy_proxy \
	-p 80:80 \
	-p 443:443 \
	--network proxy \
	-e MODE=swarm \
	-e LISTENER_ADDRESS=proxy_swarm-listener \
	-e SERVICE_NAME=proxy_proxy \
	--mount "type=volume,source=dfp-certs,destination=/certs" \
	vfarcic/docker-flow-proxy
```

Then `docker-flow-swarm-listener` service.

```
docker service create --name proxy_swarm-listener \
	--network proxy \
	-e MODE=swarm \
	-e DF_NOTIFY_CREATE_SERVICE_URL=http://proxy_proxy-le:8080/v1/docker-flow-proxy-letsencrypt/reconfigure \
	--mount "type=bind,source=/var/run/docker.sock,target=/var/run/docker.sock" \
	--constraint 'node.role == manager' \
	vfarcic/docker-flow-swarm-listener
```

The relevant information here are that :

- we plug the **dfp-certs** volume on `docker-flow-proxy` to keep persistent certificates on DFP side (in case the service is recreated),
- we trick the `docker-flow-swarm-listener` environment variable **DF_NOTIFY_CREATE_SERVICE_URL** to notify the `docker-flow-proxy-letsencrypt` when a new service is created. The DFPLE service will generate certificated if needed and then forward the request to `docker-flow-proxy` to get back in the standard flow.

### services

Now you are ready to play with the proxy stack with automatic letsencrypt support !

You need to set deployment labels to enable let's encrypt support for each proxied services:

- com.df.letsencrypt.host
- com.df.letsencrypt.email

**com.df.letsencrypt.host** generally match the **com.df.serviceDomain** label.

Let's start a test service `jwilder/whoami` : web server listening on port 8000 answering GET requests with docker hostname.

```
docker service create --name whoami \
	--network proxy \
	--label com.df.notify=true \
	--label com.df.distribute=true \
	--label com.df.serviceDomain=whoami.example.com \
	--label com.df.servicePath=/ \
	--label com.df.srcPort=443 \
	--label com.df.port=8000 \
	--label com.df.letsencrypt.host=whoami.example.com \
	--label com.df.letsencrypt.email=meATexample.com \
	jwilder/whoami
```

You should now be able to securely access your service

```
curl -k https://whoami.example.com
I'm 49d7577396e7
```
