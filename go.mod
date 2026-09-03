module github.com/example/autostream-observability

go 1.26.5

require (
	github.com/example/autostream-contracts v0.0.0
	github.com/go-sql-driver/mysql v1.10.0
)

replace github.com/example/autostream-contracts => github.com/Kome-Lab/Autostream-Contracts v1.2.12-0.20260903202917-82716abd84f2

require filippo.io/edwards25519 v1.2.0 // indirect
