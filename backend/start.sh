#!/bin/bash

echo "Starting Ollama server..."
ollama serve &

# Wait for Ollama to initialize
echo "Waiting for Ollama to start..."
sleep 10

# Pull the model if not already available
echo "Pulling Qwen model..."
ollama pull qwen2.5-coder:3b

# Start Flask backend with Gunicorn
echo "Starting Flask backend..."
gunicorn -b 0.0.0.0:7860 app:app --timeout 300