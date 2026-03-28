#!/bin/bash
# DataShield AI - Start Script
# Backend: FastAPI on port 8007
# Frontend: React+Vite on port 5179

DIR="$(cd "$(dirname "$0")" && pwd)"

echo "🛡️  Starting DataShield AI..."
echo ""

# Start backend
echo "Starting backend on port 8007..."
cd "$DIR/backend"
PYTHONPATH=src .venv/bin/uvicorn datashield.main:app --reload --port 8007 &
BACKEND_PID=$!

# Start frontend
echo "Starting frontend on port 5179..."
cd "$DIR/frontend"
npm run dev &
FRONTEND_PID=$!

echo ""
echo "DataShield AI is running!"
echo "  Backend:  http://localhost:8007"
echo "  Frontend: http://localhost:5179"
echo ""
echo "Press Ctrl+C to stop both servers."

trap "kill $BACKEND_PID $FRONTEND_PID 2>/dev/null; exit" INT TERM
wait
