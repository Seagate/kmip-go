# Copyright (c) 2022 Seagate Technology LLC and/or its Affiliates

APP_NAME := kms

help:
	@echo ""
	@echo "-----------------------------------------------------------------------------------"
	@echo "make local        - build a local executable"
	@echo "make clean        - remove all"
	@echo "make run          - build a local executable and run it"
	@echo "make debug        - build a local executable and run it with verbose logging"
	@echo ""

clean:
	@echo "Clean up..."
	go clean
	rm -f $(APP_NAME)

local: clean
	@echo "Build local executable..."
	go build -o $(APP_NAME) -ldflags "-X main.buildTime=`date -u '+%Y-%m-%dT%H:%M:%S'`"
	ls -lh $(APP_NAME)

run: local
	@echo "Running $(APP_NAME)..."
	./$(APP_NAME) -v=0

debug: local
	@echo "Running $(APP_NAME) with pykmip..."
	./$(APP_NAME) -v=5
