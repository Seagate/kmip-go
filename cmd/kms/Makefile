# Copyright (c) 2022 Seagate Technology LLC and/or its Affiliates

APP_NAME := kms

help:
	@echo ""
	@echo "-----------------------------------------------------------------------------------"
	@echo "make clean        - remove all"
	@echo "make local        - build a local executable"
	@echo "make install      - install the executable"
	@echo "make run          - build a local executable and run it"
	@echo ""

clean:
	@echo "Clean up..."
	go clean
	rm -f $(APP_NAME)

local: clean
	@echo "Build local executable..."
	go build -o $(APP_NAME) -ldflags "-X main.buildTime=`date -u '+%Y-%m-%dT%H:%M:%S'`"
	ls -lh $(APP_NAME)

install:
	@echo "Installing local executable..."
	install ./kms /usr/local/bin

run: local
	@echo "Running $(APP_NAME)..."
	./$(APP_NAME) -v=0
