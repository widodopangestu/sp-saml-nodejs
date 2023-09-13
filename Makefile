.PHONY: up clean

up:
	docker-compose up -d --build

clean:
	docker-compose stop
	docker-compose rm -f