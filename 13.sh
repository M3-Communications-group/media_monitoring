#!/bin/bash

echo "Starting process..."
docker-compose down
docker-compose up --build -d
docker ps
echo "Process completed."
