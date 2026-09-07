DC := docker compose -f docker-compose.dev.yml

.PHONY: help build dev test bench lint fmt shell prod-build clean

help:                
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

build:              
	$(DC) build --build-arg UID=$$(id -u) --build-arg GID=$$(id -g)

dev shell:          
	$(DC) run --rm dev

test:           
	$(DC) run --rm test

bench:               
	$(DC) run --rm bench

prod-build:          
	docker build -t loglensai/loglens:latest .

clean:               
	$(DC) down -v --rmi local 2>/dev/null || true