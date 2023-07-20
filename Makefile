# Build configuration
# -------------------

APP_NAME = myph
APP_VERSION = 2.0.0
GIT_REVISION = `git rev-parse HEAD`
DOCKER_IMAGE_TAG ?= $(APP_VERSION)
DOCKER_LOCAL_IMAGE = $(APP_NAME):$(DOCKER_IMAGE_TAG)

# Introspection targets
# ---------------------

.PHONY: all
all: compile


.PHONY: help
help: header targets

.PHONY: header
header:
	@echo "\033[34mEnvironment\033[0m"
	@echo "\033[34m---------------------------------------------------------------\033[0m"
	@printf "\033[33m%-23s\033[0m" "APP_NAME"
	@printf "\033[35m%s\033[0m" $(APP_NAME)
	@echo ""
	@printf "\033[33m%-23s\033[0m" "APP_VERSION"
	@printf "\033[35m%s\033[0m" $(APP_VERSION)
	@echo ""
	@printf "\033[33m%-23s\033[0m" "GIT_REVISION"
	@printf "\033[35m%s\033[0m" $(GIT_REVISION)
	@echo ""
	@printf "\033[33m%-23s\033[0m" "DOCKER_IMAGE_TAG"
	@printf "\033[35m%s\033[0m" $(DOCKER_IMAGE_TAG)
	@echo ""
	@printf "\033[33m%-23s\033[0m" "DOCKER_LOCAL_IMAGE"
	@printf "\033[35m%s\033[0m" $(DOCKER_LOCAL_IMAGE)
	@echo "\n"


.PHONY: targets
targets:
	@echo "\033[34mmyph targets:\033[0m"
	@perl -nle'print $& if m{^[a-zA-Z_-\d]+:.*?## .*$$}' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-22s\033[0m %s\n", $$1, $$2}'


.PHONY: compile
compile: ## compile the project
	@go build -o $(TARGET) .
	@echo "[ *** build successful *** ]"

.PHONY: clean
clean: ## clean up the project directory
	@rm -f $(TARGET)

.PHONY: docker
docker: ## build a local docker image
	@docker build . -t $(TARGET):latest
