#!/bin/bash

# Veriscope Cleanup Utility
# Ensures no zombie processes remain after app termination

echo "🧹 Veriscope Cleanup Utility"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Find and kill all Veriscope-related processes
PROCESSES=$(ps aux | grep -E "veriscope.*web.py|flask.*veriscope" | grep -v grep | awk '{print $2}')

if [ -z "$PROCESSES" ]; then
    echo "✓ No Veriscope processes found"
else
    echo "Found Veriscope processes:"
    ps aux | grep -E "veriscope.*web.py|flask.*veriscope" | grep -v grep
    echo ""
    echo "Terminating processes..."

    # Try graceful shutdown first
    echo "$PROCESSES" | xargs -r kill -TERM 2>/dev/null
    sleep 2

    # Force kill any remaining
    REMAINING=$(ps aux | grep -E "veriscope.*web.py|flask.*veriscope" | grep -v grep | awk '{print $2}')
    if [ ! -z "$REMAINING" ]; then
        echo "Force killing remaining processes..."
        echo "$REMAINING" | xargs -r kill -9 2>/dev/null
    fi

    echo "✓ All processes terminated"
fi

# Clean up temporary files
echo ""
echo "Cleaning temporary files..."

TEMP_FILES=$(find /tmp -name "tmp*veriscope*" -o -name "tmp*.txt" -o -name "tmp*.bin" 2>/dev/null | wc -l)

if [ "$TEMP_FILES" -gt 0 ]; then
    find /tmp -name "tmp*veriscope*" -mmin +5 -delete 2>/dev/null
    echo "✓ Cleaned up temporary files"
else
    echo "✓ No temporary files to clean"
fi

# Check for orphaned port usage
echo ""
echo "Checking port 5000..."

PORT_CHECK=$(ss -tuln 2>/dev/null | grep ":5000" || lsof -ti:5000 2>/dev/null)

if [ ! -z "$PORT_CHECK" ]; then
    echo "⚠  Port 5000 still in use"
    PID=$(lsof -ti:5000 2>/dev/null)
    if [ ! -z "$PID" ]; then
        echo "Killing process $PID on port 5000..."
        kill -9 $PID 2>/dev/null
        echo "✓ Port 5000 freed"
    fi
else
    echo "✓ Port 5000 is free"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✓ Cleanup complete!"
