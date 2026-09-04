module github.com/example/autostream-observability

go 1.26.5

require (
	github.com/example/autostream-contracts v0.0.0
	github.com/go-sql-driver/mysql v1.10.0
)

replace github.com/example/autostream-contracts => github.com/Kome-Lab/Autostream-Contracts v1.2.12-0.20260904044030-e96ac056e73e

require (
	filippo.io/edwards25519 v1.2.0 // indirect
	github.com/santhosh-tekuri/jsonschema/v6 v6.0.3 // indirect
	golang.org/x/text v0.41.0 // indirect
)
