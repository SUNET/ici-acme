DOCKER_ICI_ACME ?= /var/lib/ici_acme
DOCKER_ICI_ACME_CONFIG ?= /etc/ici_acme/config.yaml
DOCKER_ICI_PORT ?= 127.0.0.1:8000

docker_build:
	docker build . -t 'ici_acme:latest'

docker_run:
	docker run --rm -it \
		-e ICI_ACME_CONFIG=/etc/ici_acme/config.yaml \
		-v $(DOCKER_ICI_ACME_CONFIG):/etc/ici_acme/config.yaml \
		-v $(DOCKER_ICI_ACME):/var/lib/ici_acme \
		-p $(DOCKER_ICI_PORT):8000 \
		'ici_acme:latest'

.PHONY: docker_build docker_run
