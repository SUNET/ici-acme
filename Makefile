DOCKER_ICI_ACME ?= /var/lib/ici_acme
DOCKER_ICI_ACME_CONFIG ?= /etc/ici_acme/config.yaml
DOCKER_ICI_PORT ?= 127.0.0.1:8000

docker_build:
	docker build . -t 'ici_acme:latest'

docker_run:
	docker run --rm -it --name ici_acme \
		-e ICI_ACME_CONFIG=/etc/ici_acme/config.yaml \
		-v $(DOCKER_ICI_ACME_CONFIG):/etc/ici_acme/config.yaml \
		-v $(DOCKER_ICI_ACME):/var/lib/ici_acme \
		-p $(DOCKER_ICI_PORT):8000 \
		'ici_acme:latest'

# Start interface between ICI and ICI-ACME
docker_interface:
	docker run --rm -it --name ici_interface \
		-v $(DOCKER_ICI_ACME):/var/lib/ici_acme \
		-v /var/lib/ici/example/requests:/var/lib/ici/example/requests \
		-v /var/lib/ici/example/out-certs:/var/lib/ici/example/out-certs \
		'ici_acme:latest' /ici_acme/env/bin/python -- \
			/ici_acme/src/tools/ici-interface.py \
			--store_dir /var/lib/ici_acme/data/certificate \
			--debug

compose_up:
	./bin/docker-compose -p ici -f ici-compose.yaml up -d

compose_down: compose_stop

compose_stop:
	./bin/docker-compose -p ici -f ici-compose.yaml stop

compose_logs:
	./bin/docker-compose -p ici -f ici-compose.yaml logs -f

.PHONY: docker_build docker_run compose_up compose_down compose_stop compose_logs
