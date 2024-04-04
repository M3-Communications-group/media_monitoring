#!/bin/bash

echo "Starting process..."
docker-compose down
git pull origin main
docker-compose up --build -d
echo "Process completed."
