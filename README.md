# CloudWatch Logs Grep Tool (cwgrep)

A fast, interactive tool for searching AWS CloudWatch logs with grep-like syntax. Perfect for incident response when you need reliable access to logs, especially when other log aggregators like New Relic drop logs.

## Demo
[![Watch the demo](https://img.youtube.com/vi/CrjnFnXXM0Q/hqdefault.jpg)](https://www.youtube.com/watch?v=CrjnFnXXM0Q)


## Installation

```bash
# Clone the repository
git clone <repository-url>
cd cwgrep

# Install dependencies
pip install -r requirements.txt

# Make executable (optional)
chmod +x cwgrep.py
```

## Prerequisites

- Python 3.7+
- AWS credentials configured (via `aws configure` or environment variables)
- Appropriate CloudWatch Logs permissions

## Usage

### Interactive Mode

```bash
# Start the interactive tool
python cwgrep.py

# Enable detailed AWS API debugging
python cwgrep.py --debug

# Or make it executable and run directly
./cwgrep.py
./cwgrep.py --debug
```

### Direct Search Mode (Command Line)

```bash
# Basic search - last hour
python cwgrep.py -g /aws/lambda/api-service -p "ERROR.*timeout"

# Search last 4 hours
python cwgrep.py -g /aws/lambda/api-service -p "ERROR" -h 4

# Custom time range
python cwgrep.py -g /aws/lambda/api-service -p "ERROR" \
  -s "2024-01-15 14:00" -e "2024-01-15 16:00"

# Limit results and enable debug mode
python cwgrep.py --debug -g /aws/ecs/web-app -p "HTTP.*5[0-9][0-9]" \
  -h 2 --limit 50

# Natural language time parsing
python cwgrep.py -g /aws/apigateway/logs -p "timeout" \
  -s "yesterday 2pm" -e "now"
```

### Command Line Options

- `-g, --log-group`: Log group name to search (required for direct mode)
- `-p, --pattern`: Search pattern - regex or literal string (required for direct mode)
- `-h, --hours`: Search last N hours (default: 1)
- `-s, --start-time`: Custom start time (e.g., "2024-01-15 14:30", "yesterday 2pm")
- `-e, --end-time`: Custom end time (e.g., "2024-01-15 16:00", "now")
- `-l, --limit`: Maximum matches to return (default: 100)
- `--debug`: Enable detailed AWS API call debugging

### Interactive Workflow

1. **Select Log Group** Tool shows 5 most active log groups or enter custom name
2. **Choose Time Range** Select from preset ranges or enter absolute dates/times
3. **Enter Pattern** Natural grep syntax, supports regex and literal searches
4. **View Results** Streaming results with pattern highlighting and pagination

### Example Usage

```
📋 Available CloudWatch Log Groups
┏━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━━━┓
┃ #   ┃ Log Group Name              ┃ Retention    ┃ Size       ┃
┡━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━━━┩
│ 1   │ /aws/lambda/api-service     │ 14 days      │ 100.0 MB   │
│ 2   │ /aws/ecs/web-app            │ 30 days      │ 500.0 MB   │
│ 3   │ /aws/apigateway/access-logs │ 7 days       │ 50.0 MB    │
└─────┴─────────────────────────────┴──────────────┴────────────┘

Select log group: 1
Time Range: 1 (Last 1 hour)
Pattern: ERROR.*timeout

🔧 AWS API: filter_log_events(logGroupName='/aws/lambda/api-service', ...)
✅ AWS API: filter_log_events (1.23s)

🔍 Search Results
2024-01-15 14:30:15 [ERROR] Connection timeout after 30s
2024-01-15 14:32:41 [ERROR] Database timeout: query exceeded limit

✅ Search Complete
Found 2 matches in 1,247 log events
⏱️ Total search time: 2.34s
📊 Processing rate: 533 events/second
```

## AWS Permissions Required

Your AWS credentials need the following CloudWatch Logs permissions:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "logs:DescribeLogGroups",
                "logs:DescribeLogStreams", 
                "logs:FilterLogEvents",
                "logs:GetLogEvents"
            ],
            "Resource": "*"
        }
    ]
}
```

## Why Use cwgrep?

**Incident Response**
- Fast log access when every second counts
- Real-time AWS API monitoring shows exactly what's happening
- No waiting for web interfaces to load

**Reliability** 
- Direct CloudWatch access bypasses log aggregator failures
- Works when New Relic, Splunk, or other tools drop logs
- Always has access to the source of truth

**Developer Experience**
- Natural grep syntax without complex escaping
- Interactive interface guides you through the process
- Pattern highlighting makes matches easy to spot
- Pagination lets you control result flow

**Performance**
- Optimized for speed with parallel processing
- Shows timing metrics for all operations
- Memory efficient streaming of large log volumes
- Smart retention policy enforcement

## Debug Mode

Enable debug mode with `--debug` for detailed AWS API tracing:

```bash
python cwgrep.py --debug
```

Debug mode shows:
- Full AWS API parameters for each call
- Response structure and data summaries
- Detailed timing information
- Request/response debugging information

## Advanced Features

**Time Range Options**
- Preset ranges: 1h, 4h, 24h, 7d
- Absolute dates: "2024-01-15 14:30" to "2024-01-15 16:00"
- Natural language: "yesterday 2pm" to "now"

**Search Patterns**
- Literal strings: `ERROR Connection failed`
- Regular expressions: `ERROR.*timeout|ERROR.*database`
- Case insensitive by default
- Automatic pattern type detection

**Result Control**
- Interactive pagination every 20 matches
- User controlled continuation
- Safety limits with override options
- Pattern highlighting in results