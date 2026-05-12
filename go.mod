module github.com/ContinuumApp/continuum-plugin-oidc-login

go 1.26.0

replace github.com/ContinuumApp/continuum-plugin-sdk => /opt/worktrees/continuum-plugin-sdk-rh

require (
	github.com/ContinuumApp/continuum-plugin-sdk v0.3.7
	github.com/coreos/go-oidc/v3 v3.10.0
	github.com/go-chi/chi/v5 v5.2.5
	github.com/hashicorp/go-hclog v1.6.3
	golang.org/x/oauth2 v0.20.0
	google.golang.org/grpc v1.75.1
	google.golang.org/protobuf v1.36.11
)
