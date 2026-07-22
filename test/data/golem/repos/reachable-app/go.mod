module github.com/example/reachable-app

go 1.21

require github.com/example/vuln-lib v0.0.0

replace github.com/example/vuln-lib => ../vuln-lib
