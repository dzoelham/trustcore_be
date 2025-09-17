run:
	go run ./cmd/api

migrate-up:
	migrate -path internal/db/migrate -database "$(DATABASE_URL)" up

migrate-new:
	migrate create -ext sql -dir internal/db/migrate -seq $(name)

test:
	go test ./...
