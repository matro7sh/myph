TARGET 		= myph
SRC 		= main.go

.PHONY: all
all: compile

.PHONY: help
help:
	@echo "\033[34mgork targets:\033[0m"
	@perl -nle'print $& if m{^[a-zA-Z_-\d]+:.*?## .*$$}' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-22s\033[0m %s\n", $$1, $$2}'

.PHONY: compile
compile: ## compile the project
	@go build -o $(TARGET) $(SRC)
	.
.PHONY: clean
clean: ## clean up the project directory
	@rm -f $(TARGET)

.PHONY: docker
docker: ## build a local docker image
	@docker build . -t gork:latest
