DOCKER_ICI_ACME ?= /var/lib/ici_acme

docker_build:
	docker build . -t 'ici_acme:latest'

docker_run:
	docker run --rm -it \
		-v $(DOCKER_ICI_ACME):/var/lib/ici_acme \
		'ici_acme:latest'

.PHONY: docker_build docker_run
