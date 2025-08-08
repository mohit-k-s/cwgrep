#!/usr/bin/env python3
"""
CloudWatch Logs Grep Tool (cwgrep)
A fast, interactive tool for searching AWS CloudWatch logs with grep-like syntax.
"""

import boto3
import click
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.text import Text
from datetime import datetime, timedelta
import sys
import re
import time
import json
import functools
from typing import List, Dict, Optional, Tuple
from botocore.exceptions import ClientError, NoCredentialsError

console = Console()

default_region='ap-southeast-2'

class AWSMethodRouter:
    """Router/Spy system for AWS API calls that intercepts and logs all method calls."""
    
    def __init__(self, client, logger):
        self.client = client
        self.logger = logger
        self.debug_mode = False
        
    def enable_debug_mode(self):
        """Enable detailed debug logging with request/response data."""
        self.debug_mode = True
        console.print("[dim]🔍 AWS API debug mode enabled[/dim]")
    
    def _sanitize_params(self, params: Dict) -> Dict:
        """Sanitize parameters for logging (remove sensitive data)."""
        if not params:
            return {}
        
        sanitized = {}
        for key, value in params.items():
            if key.lower() in ['password', 'secret', 'token', 'key']:
                sanitized[key] = "***REDACTED***"
            elif isinstance(value, dict):
                sanitized[key] = self._sanitize_params(value)
            elif isinstance(value, list) and len(value) > 10:
                # Truncate long lists for readability
                sanitized[key] = f"[{len(value)} items]"
            else:
                sanitized[key] = value
        return sanitized
    
    def _format_params(self, params: Dict) -> str:
        """Format parameters for compact display."""
        if not params:
            return ""
        
        sanitized = self._sanitize_params(params)
        
        # Create compact representation
        compact_params = []
        for key, value in sanitized.items():
            if isinstance(value, str) and len(value) > 50:
                compact_params.append(f"{key}='{value[:47]}...'")
            elif isinstance(value, dict):
                compact_params.append(f"{key}={{...}}")
            elif isinstance(value, list):
                compact_params.append(f"{key}=[{len(value)} items]")
            else:
                compact_params.append(f"{key}={value}")
        
        return ", ".join(compact_params)
    
    def __getattr__(self, method_name: str):
        """Intercept all method calls to the AWS client."""
        if not hasattr(self.client, method_name):
            raise AttributeError(f"'{type(self.client).__name__}' object has no attribute '{method_name}'")
        
        original_method = getattr(self.client, method_name)
        
        @functools.wraps(original_method)
        def wrapper(*args, **kwargs):
            # Log the method call with parameters
            params_str = self._format_params(kwargs)
            if params_str:
                console.print(f"[dim blue]🔧 AWS API: {method_name}({params_str})[/dim blue]")
            else:
                console.print(f"[dim blue]🔧 AWS API: {method_name}()[/dim blue]")
            
            # If debug mode, show full parameters
            if self.debug_mode and kwargs:
                sanitized_params = self._sanitize_params(kwargs)
                console.print(f"[dim]   Full params: {json.dumps(sanitized_params, indent=2, default=str)}[/dim]")
            
            # Execute the actual method with timing
            start_time = time.time()
            try:
                result = original_method(*args, **kwargs)
                duration = time.time() - start_time
                
                # Log success
                self.logger.log_call(method_name, duration, success=True)
                
                # If debug mode, show response summary
                if self.debug_mode:
                    if isinstance(result, dict):
                        response_keys = list(result.keys())
                        console.print(f"[dim green]   Response keys: {response_keys}[/dim green]")
                        
                        # Show interesting response data
                        if 'logGroups' in result:
                            console.print(f"[dim green]   Found {len(result['logGroups'])} log groups[/dim green]")
                        elif 'events' in result:
                            console.print(f"[dim green]   Found {len(result['events'])} log events[/dim green]")
                        elif 'nextToken' in result:
                            console.print(f"[dim green]   Has pagination token[/dim green]")
                
                return result
                
            except Exception as e:
                duration = time.time() - start_time
                error_msg = str(e)
                
                # Log failure
                self.logger.log_call(method_name, duration, success=False, error=error_msg)
                
                # Re-raise the exception
                raise
        
        return wrapper

class AWSCallLogger:
    """Logger for AWS API calls with timing information."""
    
    def __init__(self):
        self.calls = []
        self.total_time = 0
        
    def log_call(self, operation: str, duration: float, success: bool = True, error: str = None):
        """Log an AWS API call with timing information."""
        call_info = {
            'operation': operation,
            'duration': duration,
            'success': success,
            'error': error,
            'timestamp': datetime.now()
        }
        self.calls.append(call_info)
        self.total_time += duration
        
        # Display the call in real-time
        status = "✅" if success else "❌"
        console.print(f"[dim]{status} AWS API: {operation} ({duration:.2f}s)[/dim]")
        if error:
            console.print(f"[dim red]   Error: {error}[/dim red]")
    
    def get_stats(self) -> Dict:
        """Get statistics about AWS API calls."""
        if not self.calls:
            return {'total_calls': 0, 'total_time': 0, 'success_rate': 0}
        
        successful_calls = sum(1 for call in self.calls if call['success'])
        return {
            'total_calls': len(self.calls),
            'successful_calls': successful_calls,
            'failed_calls': len(self.calls) - successful_calls,
            'total_time': self.total_time,
            'average_time': self.total_time / len(self.calls),
            'success_rate': (successful_calls / len(self.calls)) * 100
        }
    
    def display_summary(self):
        """Display a summary of AWS API calls."""
        stats = self.get_stats()
        if stats['total_calls'] == 0:
            return
            
        console.print(f"\n[bold cyan]📊 AWS API Call Summary[/bold cyan]")
        console.print(f"Total calls: [bold]{stats['total_calls']}[/bold]")
        console.print(f"Successful: [green]{stats['successful_calls']}[/green]")
        if stats['failed_calls'] > 0:
            console.print(f"Failed: [red]{stats['failed_calls']}[/red]")
        console.print(f"Total time: [bold]{stats['total_time']:.2f}s[/bold]")
        console.print(f"Average time: [bold]{stats['average_time']:.2f}s[/bold]")
        console.print(f"Success rate: [bold]{stats['success_rate']:.1f}%[/bold]")

class CloudWatchGrep:
    def __init__(self, debug_mode: bool = False):
        try:
            # Initialize AWS call logger
            self.aws_logger = AWSCallLogger()
            
            # Use local credentials strategy - check multiple sources
            self.session = self._create_session()
            raw_client = self.session.client('logs' , region_name= default_region)
            
            # Create the AWS method router/spy
            self.logs_client = AWSMethodRouter(raw_client, self.aws_logger)
            
            # Enable debug mode if requested
            if debug_mode:
                self.logs_client.enable_debug_mode()
            
            self.log_groups_cache = []
            self.retention_cache = {}
            
            # Test credentials by making a simple API call
            self._test_credentials()
            
        except NoCredentialsError:
            console.print("[red]❌ AWS credentials not found.[/red]")
            console.print("Please configure AWS credentials using one of these methods:")
            console.print("• [cyan]aws configure[/cyan] (AWS CLI)")
            console.print("• Set [cyan]AWS_PROFILE[/cyan] environment variable")
            console.print("• Set [cyan]AWS_ACCESS_KEY_ID[/cyan] and [cyan]AWS_SECRET_ACCESS_KEY[/cyan] environment variables")
            console.print("• Use IAM roles if running on EC2")
            sys.exit(1)
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code in ['UnauthorizedOperation', 'AccessDenied']:
                console.print("[red]❌ AWS credentials found but insufficient permissions.[/red]")
                console.print("Required permissions: logs:DescribeLogGroups, logs:FilterLogEvents")
            else:
                console.print(f"[red]❌ AWS API error: {e}[/red]")
            sys.exit(1)
        except Exception as e:
            console.print(f"[red]❌ Error initializing AWS client: {e}[/red]")
            sys.exit(1)
    
    def _create_session(self):
        """Create boto3 session using local credentials strategy."""
        import os
        
        # Try different credential sources in order of preference
        session = boto3.Session()
        
        # Check if we have explicit profile
        aws_profile = os.environ.get('AWS_PROFILE')
        if aws_profile:
            console.print(f"[dim]Using AWS profile: {aws_profile}[/dim]")
            session = boto3.Session(profile_name=aws_profile)
        
        return session
    
    def _test_credentials(self):
        """Test AWS credentials with a simple API call."""
        try:
            # Make a lightweight call to test credentials
            self.logs_client.describe_log_groups(limit=1)
        except ClientError as e:
            if e.response['Error']['Code'] == 'UnauthorizedOperation':
                raise ClientError(
                    error_response={'Error': {'Code': 'AccessDenied', 'Message': 'Insufficient permissions'}},
                    operation_name='DescribeLogGroups'
                )
            raise

    def fetch_log_groups(self, limit: int = 50) -> List[Dict]:
        """Fetch available log groups from CloudWatch."""
        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task("Fetching log groups...", total=None)
                
                fetch_start_time = time.time()
                log_groups = []
                
                paginator = self.logs_client.get_paginator('describe_log_groups')
                pages = paginator.paginate()
                
                for page in pages:
                    for group in page['logGroups']:
                        log_groups.append({
                            'name': group['logGroupName'],
                            'creation_time': group.get('creationTime', 0),
                            'retention_days': group.get('retentionInDays'),
                            'stored_bytes': group.get('storedBytes', 0),
                            'metric_filter_count': group.get('metricFilterCount', 0)
                        })
                        
                        if len(log_groups) >= limit:
                            break
                    if len(log_groups) >= limit:
                        break
                
                # Sort by most recent activity (stored bytes as proxy)
                log_groups.sort(key=lambda x: x['stored_bytes'], reverse=True)
                
                fetch_duration = time.time() - fetch_start_time
                progress.update(task, completed=True)
                
                console.print(f"[dim]📊 Fetched {len(log_groups)} log groups in {fetch_duration:.2f}s[/dim]")
                
            return log_groups
            
        except ClientError as e:
            console.print(f"[red]❌ Error fetching log groups: {e}[/red]")
            return []

    def get_retention_info(self, log_group_name: str) -> Tuple[Optional[int], datetime]:
        """Get retention period and calculate earliest searchable date."""
        if log_group_name in self.retention_cache:
            return self.retention_cache[log_group_name]
        
        try:
            response = self.logs_client.describe_log_groups(
                logGroupNamePrefix=log_group_name,
                limit=1
            )
            
            if response['logGroups']:
                group = response['logGroups'][0]
                retention_days = group.get('retentionInDays')
                
                if retention_days:
                    earliest_date = datetime.now() - timedelta(days=retention_days)
                else:
                    # No retention set - logs never expire
                    earliest_date = datetime.min
                
                self.retention_cache[log_group_name] = (retention_days, earliest_date)
                return retention_days, earliest_date
            
        except ClientError as e:
            console.print(f"[yellow]⚠️ Warning: Could not fetch retention info for {log_group_name}: {e}[/yellow]")
        
        # Default: assume 30 days retention if we can't determine
        earliest_date = datetime.now() - timedelta(days=30)
        self.retention_cache[log_group_name] = (30, earliest_date)
        return 30, earliest_date

    def display_log_groups(self, log_groups: List[Dict], show_count: int = 5) -> None:
        """Display log groups in a nice table format."""
        if not log_groups:
            console.print("[red]❌ No log groups found or accessible.[/red]")
            return

        table = Table(title="📋 Available CloudWatch Log Groups", show_header=True, header_style="bold cyan")
        table.add_column("#", style="dim", width=3)
        table.add_column("Log Group Name", style="green")
        table.add_column("Retention", style="yellow", width=12)
        table.add_column("Size", style="blue", width=10)
        table.add_column("Last Activity", style="magenta", width=15)

        displayed_groups = log_groups[:show_count]
        
        for idx, group in enumerate(displayed_groups, 1):
            # Format retention
            if group['retention_days']:
                retention = f"{group['retention_days']} days"
            else:
                retention = "Never expires"
            
            # Format size
            size_bytes = group['stored_bytes']
            if size_bytes > 1024**3:
                size = f"{size_bytes / (1024**3):.1f} GB"
            elif size_bytes > 1024**2:
                size = f"{size_bytes / (1024**2):.1f} MB"
            elif size_bytes > 1024:
                size = f"{size_bytes / 1024:.1f} KB"
            else:
                size = f"{size_bytes} B"
            
            # Format creation time
            if group['creation_time']:
                created = datetime.fromtimestamp(group['creation_time'] / 1000)
                time_ago = datetime.now() - created
                if time_ago.days > 0:
                    last_activity = f"{time_ago.days}d ago"
                else:
                    last_activity = f"{time_ago.seconds // 3600}h ago"
            else:
                last_activity = "Unknown"
            
            table.add_row(
                str(idx),
                group['name'],
                retention,
                size,
                last_activity
            )
        
        console.print(table)
        
        if len(log_groups) > show_count:
            console.print(f"\n[dim]... and {len(log_groups) - show_count} more log groups available[/dim]")

    def select_log_group(self, log_groups: List[Dict]) -> Optional[Dict]:
        """Interactive log group selection."""
        if not log_groups:
            return None
        
        while True:
            try:
                console.print("\n[bold]Select a log group to search:[/bold]")
                console.print("[dim]Enter number (1-5), 'more' to see more groups, 'custom' to enter log group name, or 'back' to return to main menu[/dim]")
                
                choice = Prompt.ask("Your choice", default="1")
                
                if choice.lower() in ['back', 'quit', 'q', 'exit']:
                    console.print("[yellow]🔙 Returning to main menu...[/yellow]")
                    return None
                
                if choice.lower() == 'more':
                    # Show more log groups
                    self.display_log_groups(log_groups, show_count=20)
                    continue
                
                if choice.lower() in ['custom', 'c']:
                    # Allow custom log group input
                    return self._handle_custom_log_group()
                
                # Try to parse as number
                try:
                    idx = int(choice) - 1
                    if 0 <= idx < min(len(log_groups), 5):
                        selected_group = log_groups[idx]
                        console.print(f"\n[green]✓ Selected: {selected_group['name']}[/green]")
                        return selected_group
                    else:
                        console.print("[red]❌ Invalid selection. Please choose 1-5.[/red]")
                except ValueError:
                    console.print("[red]❌ Please enter a number, 'more', 'custom', or 'back'.[/red]")
                    
            except KeyboardInterrupt:
                console.print("\n[yellow]⚠️  Interrupted by user[/yellow]")
                if Confirm.ask("[yellow]Return to main menu?[/yellow]"):
                    return None
                # If they don't want to return to main menu, continue the loop

    def _handle_custom_log_group(self) -> Optional[Dict]:
        """Handle custom log group name input from user."""
        console.print("\n[bold cyan]📝 Enter Custom Log Group[/bold cyan]")
        console.print("[dim]You can enter any CloudWatch log group name (e.g., /aws/lambda/my-function)[/dim]")
        
        while True:
            try:
                log_group_name = Prompt.ask("Log group name", default="").strip()
                
                if not log_group_name:
                    console.print("[red]❌ Please enter a log group name[/red]")
                    continue
                
                if log_group_name.lower() in ['quit', 'q', 'back', 'cancel']:
                    return None
                
                # Validate log group name format (basic validation)
                if not log_group_name.startswith('/') and not log_group_name.startswith('aws/'):
                    console.print("[yellow]⚠️ Log group names typically start with '/' (e.g., /aws/lambda/function-name)[/yellow]")
                    if not Confirm.ask("Continue with this name anyway?", default=True):
                        continue
                
                # Try to verify the log group exists
                console.print(f"[dim]Verifying log group: {log_group_name}[/dim]")
                
                try:
                    with Progress(
                        SpinnerColumn(),
                        TextColumn("[progress.description]{task.description}"),
                        console=console
                    ) as progress:
                        task = progress.add_task("Checking log group...", total=None)
                        
                        # Check if log group exists
                        response = self.logs_client.describe_log_groups(
                            logGroupNamePrefix=log_group_name,
                            limit=1
                        )
                        
                        progress.update(task, completed=True)
                        
                        # Check if we found the exact log group
                        found_groups = [g for g in response.get('logGroups', []) 
                                      if g['logGroupName'] == log_group_name]
                        
                        if found_groups:
                            # Log group exists, create a mock group object
                            group = found_groups[0]
                            custom_group = {
                                'name': group['logGroupName'],
                                'creation_time': group.get('creationTime', 0),
                                'retention_days': group.get('retentionInDays'),
                                'stored_bytes': group.get('storedBytes', 0),
                                'metric_filter_count': group.get('metricFilterCount', 0)
                            }
                            
                            console.print(f"[green]✅ Found log group: {log_group_name}[/green]")
                            
                            # Show some info about the log group
                            if custom_group['retention_days']:
                                console.print(f"[dim]Retention: {custom_group['retention_days']} days[/dim]")
                            else:
                                console.print("[dim]Retention: Never expires[/dim]")
                            
                            return custom_group
                        else:
                            console.print(f"[red]❌ Log group '{log_group_name}' not found[/red]")
                            console.print("[yellow]💡 Make sure the log group name is correct and you have permissions to access it[/yellow]")
                            
                            if Confirm.ask("Try a different log group name?", default=True):
                                continue
                            else:
                                return None
                
                except ClientError as e:
                    error_code = e.response['Error']['Code']
                    if error_code == 'AccessDenied':
                        console.print(f"[red]❌ Access denied to log group '{log_group_name}'[/red]")
                        console.print("[yellow]💡 Check your AWS permissions for CloudWatch Logs[/yellow]")
                    else:
                        console.print(f"[red]❌ Error checking log group: {e}[/red]")
                    
                    # Ask if they want to proceed anyway (maybe permissions issue but group exists)
                    if Confirm.ask("Proceed with this log group anyway? (search might fail)", default=False):
                        # Create a minimal group object for unknown log group
                        unknown_group = {
                            'name': log_group_name,
                            'creation_time': 0,
                            'retention_days': None,  # Unknown
                            'stored_bytes': 0,
                            'metric_filter_count': 0
                        }
                        console.print(f"[yellow]⚠️ Proceeding with unverified log group: {log_group_name}[/yellow]")
                        return unknown_group
                    else:
                        continue
                
            except KeyboardInterrupt:
                console.print("\n[yellow]👋 Returning to main menu...[/yellow]")
                return None

    def _get_custom_time_range(self, earliest_date: datetime) -> Optional[Tuple[datetime, datetime, str]]:
        """Get custom absolute time range from user input."""
        from dateutil import parser
        
        console.print("\n[bold cyan]📅 Custom Time Range[/bold cyan]")
        console.print("[dim]Enter absolute dates and times. Examples:[/dim]")
        console.print("[dim]• 2024-01-15 14:30[/dim]")
        console.print("[dim]• 2024-01-15 14:30:00[/dim]")
        console.print("[dim]• Jan 15 2024 2:30 PM[/dim]")
        console.print("[dim]• yesterday 2pm[/dim]")
        console.print("[dim]• 2 hours ago[/dim]")
        
        try:
            # Get start time
            while True:
                start_input = Prompt.ask("\n[bold]Start time[/bold]", default="").strip()
                if not start_input or start_input.lower() in ['quit', 'q', 'cancel', 'back']:
                    return None
                
                try:
                    start_time = parser.parse(start_input)
                    console.print(f"[green]✓ Start time: {start_time.strftime('%Y-%m-%d %H:%M:%S')}[/green]")
                    break
                except (ValueError, parser.ParserError) as e:
                    console.print(f"[red]❌ Invalid date format: {e}[/red]")
                    console.print("[yellow]💡 Try formats like '2024-01-15 14:30' or 'Jan 15 2024 2:30 PM'[/yellow]")
            
            # Get end time
            while True:
                end_input = Prompt.ask("[bold]End time[/bold]", default="now").strip()
                if end_input.lower() in ['quit', 'q', 'cancel', 'back']:
                    return None
                
                try:
                    if end_input.lower() == 'now':
                        end_time = datetime.now()
                    else:
                        end_time = parser.parse(end_input)
                    
                    console.print(f"[green]✓ End time: {end_time.strftime('%Y-%m-%d %H:%M:%S')}[/green]")
                    break
                except (ValueError, parser.ParserError) as e:
                    console.print(f"[red]❌ Invalid date format: {e}[/red]")
                    console.print("[yellow]💡 Try formats like '2024-01-15 16:30' or 'now'[/yellow]")
            
            # Validate time range
            if start_time >= end_time:
                console.print("[red]❌ Start time must be before end time[/red]")
                return None
            
            # Check against retention policy
            if start_time < earliest_date:
                console.print(f"[red]❌ Start time is before log retention period[/red]")
                console.print(f"[yellow]Earliest available: {earliest_date.strftime('%Y-%m-%d %H:%M:%S')}[/yellow]")
                return None
            
            # Calculate duration for description
            duration = end_time - start_time
            if duration.days > 0:
                time_desc = f"{start_time.strftime('%Y-%m-%d %H:%M')} to {end_time.strftime('%Y-%m-%d %H:%M')} ({duration.days}d {duration.seconds//3600}h)"
            else:
                hours = duration.seconds // 3600
                minutes = (duration.seconds % 3600) // 60
                time_desc = f"{start_time.strftime('%Y-%m-%d %H:%M')} to {end_time.strftime('%Y-%m-%d %H:%M')} ({hours}h {minutes}m)"
            
            return start_time, end_time, time_desc
            
        except KeyboardInterrupt:
            console.print("\n[yellow]👋 Cancelled[/yellow]")
            return None

    def search_interface(self, log_group: Dict) -> None:
        """Interactive search interface for the selected log group."""
        log_group_name = log_group['name']
        
        # Get retention information
        retention_days, earliest_date = self.get_retention_info(log_group_name)
        
        # Display log group info
        info_panel = Panel(
            f"[bold green]{log_group_name}[/bold green]\n"
            f"Retention: {retention_days if retention_days else 'Never expires'} days\n"
            f"Earliest searchable: {earliest_date.strftime('%Y-%m-%d %H:%M:%S') if earliest_date != datetime.min else 'No limit'}",
            title="📁 Selected Log Group",
            border_style="green"
        )
        console.print(info_panel)
        
        while True:
            try:
                console.print("\n[bold cyan]🔍 Search Configuration[/bold cyan]")
                
                # Get search pattern
                pattern = Prompt.ask("Enter search pattern (or 'back' to return to main menu)", default="ERROR")
                if not pattern or pattern.lower() == 'back':
                    console.print("[yellow]🔙 Returning to main menu...[/yellow]")
                    return
                
                # Get time range
                console.print("\n[bold]Time Range Options:[/bold]")
                console.print("1. Last 1 hour")
                console.print("2. Last 4 hours") 
                console.print("3. Last 24 hours")
                console.print("4. Last 7 days")
                console.print("5. Custom absolute range")
                console.print("6. Back to main menu")
                
                time_choice = Prompt.ask("Select time range", choices=["1", "2", "3", "4", "5", "6"], default="1")
                
                if time_choice == "6":
                    console.print("[yellow]🔙 Returning to main menu...[/yellow]")
                    return
                
                # Calculate time range
                now = datetime.now()
                if time_choice == "1":
                    start_time = now - timedelta(hours=1)
                    time_desc = "last 1 hour"
                elif time_choice == "2":
                    start_time = now - timedelta(hours=4)
                    time_desc = "last 4 hours"
                elif time_choice == "3":
                    start_time = now - timedelta(days=1)
                    time_desc = "last 24 hours"
                elif time_choice == "4":
                    start_time = now - timedelta(days=7)
                    time_desc = "last 7 days"
                else:
                    # Custom absolute range
                    custom_range = self._get_custom_time_range(earliest_date)
                    if custom_range is None:
                        continue  # User cancelled or error
                    start_time, end_time_custom, time_desc = custom_range
                    now = end_time_custom  # Use custom end time
                
                # Check against retention policy
                if start_time < earliest_date:
                    console.print(f"[red]❌ Requested time range goes beyond log retention period.[/red]")
                    console.print(f"[yellow]Earliest available: {earliest_date.strftime('%Y-%m-%d %H:%M:%S')}[/yellow]")
                    
                    if Confirm.ask("Adjust to earliest available time?"):
                        start_time = earliest_date
                        time_desc = f"from {earliest_date.strftime('%Y-%m-%d %H:%M:%S')}"
                    else:
                        continue
                
                # Show search summary
                search_panel = Panel(
                    f"[bold]Pattern:[/bold] {pattern}\n"
                    f"[bold]Time Range:[/bold] {time_desc}\n"
                    f"[bold]Log Group:[/bold] {log_group_name}",
                    title="🎯 Search Summary",
                    border_style="yellow"
                )
                console.print(search_panel)
                
                if Confirm.ask("Start search?", default=True):
                    self.perform_search(log_group_name, pattern, start_time, now)
                    
                    # After search completion, ask what to do next
                    console.print("\n[bold cyan]What would you like to do next?[/bold cyan]")
                    console.print("1. Search this log group again")
                    console.print("2. Return to main menu")
                    
                    next_choice = Prompt.ask("Choose option", choices=["1", "2"], default="2")
                    if next_choice == "2":
                        console.print("[yellow]🔙 Returning to main menu...[/yellow]")
                        return
                    # If choice is "1", continue the loop to search again
                
            except KeyboardInterrupt:
                console.print("\n[yellow]👋 Returning to main menu...[/yellow]")
                return

    def perform_search(self, log_group_name: str, pattern: str, start_time: datetime, end_time: datetime) -> None:
        """Perform the actual log search with the given parameters."""
        try:
            # Convert datetime to milliseconds timestamp for CloudWatch API
            start_timestamp = int(start_time.timestamp() * 1000)
            end_timestamp = int(end_time.timestamp() * 1000)
            
            # Determine if pattern is regex or literal
            is_regex = self._is_regex_pattern(pattern)
            compiled_pattern = None
            
            if is_regex:
                try:
                    compiled_pattern = re.compile(pattern, re.IGNORECASE)
                    console.print(f"[dim]Using regex pattern: {pattern}[/dim]")
                except re.error as e:
                    console.print(f"[red]❌ Invalid regex pattern: {e}[/red]")
                    return
            else:
                console.print(f"[dim]Using literal search: {pattern}[/dim]")
            
            # Start search with progress indicator
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                search_task = progress.add_task("Searching logs...", total=None)
                
                matches_found = 0
                total_events = 0
                
                # Use CloudWatch filter_log_events API for efficient searching
                search_start_time = time.time()
                
                # Build filter pattern for CloudWatch (if possible)
                cw_filter_pattern = self._build_cloudwatch_filter(pattern, is_regex)
                
                paginator = self.logs_client.get_paginator('filter_log_events')
                page_iterator = paginator.paginate(
                    logGroupName=log_group_name,
                    startTime=start_timestamp,
                    endTime=end_timestamp,
                    filterPattern=cw_filter_pattern if cw_filter_pattern else None
                )
                
                console.print(f"\n[bold cyan]🔍 Search Results[/bold cyan]")
                console.print(f"[dim]Log Group: {log_group_name}[/dim]")
                console.print(f"[dim]Pattern: {pattern}[/dim]")
                console.print(f"[dim]Time Range: {start_time.strftime('%Y-%m-%d %H:%M:%S')} to {end_time.strftime('%Y-%m-%d %H:%M:%S')}[/dim]\n")
                
                for page in page_iterator:
                    events = page.get('events', [])
                    total_events += len(events)
                    
                    for event in events:
                        message = event['message']
                        timestamp = event['timestamp']
                        
                        # Apply our own pattern matching if needed
                        match_found = False
                        if cw_filter_pattern:
                            # CloudWatch already filtered, so this is a match
                            match_found = True
                        else:
                            # Apply our own filtering
                            if is_regex and compiled_pattern:
                                match_found = compiled_pattern.search(message) is not None
                            else:
                                match_found = pattern.lower() in message.lower()
                        
                        if match_found:
                            matches_found += 1
                            
                            # Format timestamp
                            dt = datetime.fromtimestamp(timestamp / 1000)
                            time_str = dt.strftime('%Y-%m-%d %H:%M:%S')
                            
                            # Highlight the pattern in the message
                            highlighted_message = self._highlight_pattern(message, pattern, is_regex, compiled_pattern)
                            
                            # Display the match
                            console.print(f"[blue]{time_str}[/blue] {highlighted_message}")
                    
                    # Update progress
                    progress.update(search_task, description=f"Searching... ({matches_found} matches found)")
                    
                    # Check if we should pause for user input (every 20 matches)
                    if matches_found > 0 and matches_found % 20 == 0:
                        progress.update(search_task, description=f"Found {matches_found} matches - pausing for user input...")
                        progress.stop()
                        
                        console.print(f"\n[yellow]📄 Showing {matches_found} matches so far...[/yellow]")
                        
                        if not Confirm.ask("Continue searching for more results?", default=True):
                            console.print("[yellow]🛑 Search stopped by user[/yellow]")
                            break
                        
                        # Resume progress
                        progress.start()
                        progress.update(search_task, description=f"Continuing search... ({matches_found} matches found)")
                    
                    # Safety limit to prevent runaway searches
                    if matches_found >= 500:
                        progress.update(search_task, description=f"Reached safety limit of 500 matches")
                        progress.stop()
                        console.print(f"\n[yellow]⚠️ Reached safety limit of 500 matches[/yellow]")
                        if not Confirm.ask("Continue searching anyway? (may take a long time)", default=False):
                            break
                        progress.start()
            
            progress.update(search_task, completed=True)
            
            # Calculate total search time
            total_search_time = time.time() - search_start_time
            
            # Display summary with timing information
            console.print(f"\n[bold green]✅ Search Complete[/bold green]")
            console.print(f"Found [bold]{matches_found}[/bold] matches in [bold]{total_events}[/bold] log events")
            console.print(f"⏱️ Total search time: [bold]{total_search_time:.2f}s[/bold]")
            
            if matches_found > 0:
                events_per_second = total_events / total_search_time if total_search_time > 0 else 0
                console.print(f"📊 Processing rate: [bold]{events_per_second:.0f}[/bold] events/second")
            
            if matches_found == 0:
                console.print("[yellow]💡 Try adjusting your search pattern or time range[/yellow]")
            
            # Display AWS API call summary
            self.aws_logger.display_summary()
                
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'ResourceNotFoundException':
                console.print(f"[red]❌ Log group '{log_group_name}' not found[/red]")
            elif error_code == 'InvalidParameterException':
                console.print(f"[red]❌ Invalid search parameters: {e.response['Error']['Message']}[/red]")
            else:
                console.print(f"[red]❌ AWS API error: {e}[/red]")
        except Exception as e:
            console.print(f"[red]❌ Search error: {e}[/red]")

    def _is_regex_pattern(self, pattern: str) -> bool:
        """Detect if a pattern contains regex special characters."""
        regex_chars = set('.*+?^${}[]|()')
        return any(char in pattern for char in regex_chars)

    def _build_cloudwatch_filter(self, pattern: str, is_regex: bool) -> Optional[str]:
        """Build CloudWatch filter pattern if possible (for server-side filtering)."""
        if is_regex:
            # CloudWatch doesn't support full regex, so we'll filter client-side
            return None
        
        # For literal strings, we can use CloudWatch's simple pattern matching
        if ' ' in pattern or any(char in pattern for char in '"[]{}'):
            # Complex patterns - let client handle it
            return None
        
        # Simple literal pattern - CloudWatch can handle this
        return f'"{pattern}"'

    def _parse_natural_time(self, time_str: str) -> datetime:
        """Parse natural language time expressions with enhanced support."""
        from dateutil import parser
        import re
        
        time_str = time_str.strip().lower()
        now = datetime.now()
        
        # Handle special cases first
        if time_str == 'now':
            return now
        
        # Handle relative expressions like "2 hours ago", "30 minutes ago"
        ago_match = re.match(r'(\d+)\s+(hour|hours|minute|minutes|day|days)\s+ago', time_str)
        if ago_match:
            amount = int(ago_match.group(1))
            unit = ago_match.group(2)
            
            if unit.startswith('hour'):
                return now - timedelta(hours=amount)
            elif unit.startswith('minute'):
                return now - timedelta(minutes=amount)
            elif unit.startswith('day'):
                return now - timedelta(days=amount)
        
        # Handle "yesterday" with time
        if time_str.startswith('yesterday'):
            yesterday = now - timedelta(days=1)
            time_part = time_str.replace('yesterday', '').strip()
            
            if time_part:
                # Parse the time part (e.g., "6pm", "14:30")
                try:
                    parsed_time = self._parse_time_part(time_part)
                    return yesterday.replace(hour=parsed_time.hour, minute=parsed_time.minute, second=0, microsecond=0)
                except:
                    # If time parsing fails, use yesterday at same time as now
                    return yesterday.replace(second=0, microsecond=0)
            else:
                # Just "yesterday" - use yesterday at current time
                return yesterday.replace(second=0, microsecond=0)
        
        # Handle "today" with time
        if time_str.startswith('today'):
            today = now.replace(second=0, microsecond=0)
            time_part = time_str.replace('today', '').strip()
            
            if time_part:
                try:
                    parsed_time = self._parse_time_part(time_part)
                    return today.replace(hour=parsed_time.hour, minute=parsed_time.minute)
                except:
                    return today
            else:
                return today
        
        # Handle "tomorrow" with time
        if time_str.startswith('tomorrow'):
            tomorrow = now + timedelta(days=1)
            time_part = time_str.replace('tomorrow', '').strip()
            
            if time_part:
                try:
                    parsed_time = self._parse_time_part(time_part)
                    return tomorrow.replace(hour=parsed_time.hour, minute=parsed_time.minute, second=0, microsecond=0)
                except:
                    return tomorrow.replace(second=0, microsecond=0)
            else:
                return tomorrow.replace(second=0, microsecond=0)
        
        # Fall back to dateutil parser for other formats
        try:
            return parser.parse(time_str)
        except Exception as e:
            raise ValueError(f"Unable to parse time '{time_str}'. {str(e)}")
    
    def _parse_time_part(self, time_str: str) -> datetime:
        """Parse just the time part (e.g., '6pm', '14:30', '2:30pm')."""
        from dateutil import parser
        
        time_str = time_str.strip()
        
        # Handle common formats like "6pm", "2pm", "14:30"
        if re.match(r'^\d{1,2}(am|pm)$', time_str):
            # Format like "6pm"
            return parser.parse(time_str)
        elif re.match(r'^\d{1,2}:\d{2}(am|pm)?$', time_str):
            # Format like "2:30pm" or "14:30"
            return parser.parse(time_str)
        elif re.match(r'^\d{1,2}$', time_str):
            # Just a number like "6" - assume it's an hour
            hour = int(time_str)
            if hour > 12:
                # 24-hour format
                return datetime.now().replace(hour=hour, minute=0, second=0, microsecond=0)
            else:
                # Assume PM for single digits in afternoon/evening context
                return parser.parse(f"{time_str}pm")
        else:
            # Let dateutil handle it
            return parser.parse(time_str)

    def _highlight_pattern(self, message: str, pattern: str, is_regex: bool, compiled_pattern: Optional[re.Pattern]) -> str:
        """Highlight matching patterns in the message."""
        try:
            if is_regex and compiled_pattern:
                # Highlight regex matches
                def replace_match(match):
                    return f"[bold red]{match.group()}[/bold red]"
                return compiled_pattern.sub(replace_match, message)
            else:
                # Highlight literal matches (case-insensitive)
                import re as re_module
                escaped_pattern = re_module.escape(pattern)
                pattern_re = re_module.compile(escaped_pattern, re_module.IGNORECASE)
                def replace_match(match):
                    return f"[bold red]{match.group()}[/bold red]"
                return pattern_re.sub(replace_match, message)
        except Exception:
            # If highlighting fails, return original message
            return message

    def run(self):
        """Main application entry point with continuous workflow."""
        console.print(Panel(
            "Fast, interactive CloudWatch log searching with grep-like syntax",
            title="🔍 cwgrep",
            border_style="cyan"
        ))
        
        while True:
            try:
                # Fetch log groups
                log_groups = self.fetch_log_groups(limit=50)
                if not log_groups:
                    console.print("[red]❌ No log groups found.[/red]")
                    if not Confirm.ask("\n[yellow]Would you like to try again?[/yellow]"):
                        break
                    continue
                
                # Display and select log group
                self.display_log_groups(log_groups)
                selected_group = self.select_log_group(log_groups)
                
                if selected_group:
                    self.search_interface(selected_group)
                
                # Ask if user wants to continue
                console.print("\n" + "="*50)
                if not Confirm.ask("[bold cyan]🔄 Would you like to search another log group?[/bold cyan]"):
                    break
                    
            except KeyboardInterrupt:
                console.print("\n[yellow]⚠️  Interrupted by user[/yellow]")
                if not Confirm.ask("[yellow]Return to main menu?[/yellow]"):
                    break
        
        console.print("\n[green]👋 Thanks for using cwgrep![/green]")

    def run_direct_search(self, log_group_name: str, pattern: str, hours: Optional[int], 
                         start_time_str: Optional[str], end_time_str: Optional[str], limit: int) -> None:
        """Run direct search from command-line arguments with validation."""
        try:
            console.print(Panel(
                f"Direct search mode: {log_group_name}",
                title="🔍 cwgrep",
                border_style="cyan"
            ))
            
            # Validate and verify log group exists
            console.print(f"[dim]Validating log group: {log_group_name}[/dim]")
            
            # Check if log group exists
            try:
                response = self.logs_client.describe_log_groups(
                    logGroupNamePrefix=log_group_name,
                    limit=1
                )
                
                # Check if we found the exact log group
                found_groups = [g for g in response.get('logGroups', []) 
                              if g['logGroupName'] == log_group_name]
                
                if not found_groups:
                    console.print(f"[red]❌ Log group '{log_group_name}' not found[/red]")
                    console.print("[yellow]💡 Use interactive mode to browse available log groups[/yellow]")
                    sys.exit(1)
                
                log_group_info = found_groups[0]
                console.print(f"[green]✅ Found log group: {log_group_name}[/green]")
                
            except ClientError as e:
                console.print(f"[red]❌ Error validating log group: {e}[/red]")
                sys.exit(1)
            
            # Get retention information for validation
            retention_days, earliest_date = self.get_retention_info(log_group_name)
            
            # Calculate time range
            now = datetime.now()
            
            if start_time_str and end_time_str:
                # Custom time range provided
                try:
                    # Parse start time
                    if start_time_str.lower() == 'now':
                        start_time = now
                    else:
                        start_time = self._parse_natural_time(start_time_str)
                    
                    # Parse end time  
                    if end_time_str.lower() == 'now':
                        end_time = now
                    else:
                        end_time = self._parse_natural_time(end_time_str)
                    
                    if start_time >= end_time:
                        console.print("[red]❌ Start time must be before end time[/red]")
                        sys.exit(1)
                        
                    time_desc = f"{start_time.strftime('%Y-%m-%d %H:%M')} to {end_time.strftime('%Y-%m-%d %H:%M')}"
                    
                except Exception as e:
                    console.print(f"[red]❌ Error parsing time range: {e}[/red]")
                    console.print("[yellow]💡 Supported formats:[/yellow]")
                    console.print("[yellow]  - Absolute: '2024-01-15 14:30', '2024-01-15 2:30pm'[/yellow]")
                    console.print("[yellow]  - Relative: 'yesterday 6pm', 'today 9am', '2 hours ago'[/yellow]")
                    console.print("[yellow]  - Special: 'now'[/yellow]")
                    sys.exit(1)
                    
            elif hours:
                # Hours-based time range
                start_time = now - timedelta(hours=hours)
                end_time = now
                time_desc = f"last {hours} hour{'s' if hours != 1 else ''}"
                
            else:
                # Default to last 1 hour
                start_time = now - timedelta(hours=1)
                end_time = now
                time_desc = "last 1 hour"
            
            # Validate against retention policy
            if start_time < earliest_date:
                console.print(f"[red]❌ Requested time range goes beyond log retention period[/red]")
                console.print(f"[yellow]Earliest available: {earliest_date.strftime('%Y-%m-%d %H:%M:%S')}[/yellow]")
                console.print(f"[yellow]Requested start: {start_time.strftime('%Y-%m-%d %H:%M:%S')}[/yellow]")
                sys.exit(1)
            
            # Show search summary
            search_panel = Panel(
                f"[bold]Pattern:[/bold] {pattern}\n"
                f"[bold]Time Range:[/bold] {time_desc}\n"
                f"[bold]Log Group:[/bold] {log_group_name}\n"
                f"[bold]Match Limit:[/bold] {limit}",
                title="🎯 Direct Search",
                border_style="yellow"
            )
            console.print(search_panel)
            
            # Perform the search with limit
            self.perform_search_with_limit(log_group_name, pattern, start_time, end_time, limit)
            
        except Exception as e:
            console.print(f"[red]❌ Direct search error: {e}[/red]")
            sys.exit(1)

    def perform_search_with_limit(self, log_group_name: str, pattern: str, start_time: datetime, 
                                 end_time: datetime, limit: int) -> None:
        """Perform search with a specific match limit for command-line mode."""
        try:
            # Convert datetime to milliseconds timestamp for CloudWatch API
            start_timestamp = int(start_time.timestamp() * 1000)
            end_timestamp = int(end_time.timestamp() * 1000)
            
            # Detect if pattern is regex
            is_regex = self._is_regex_pattern(pattern)
            compiled_pattern = None
            
            if is_regex:
                try:
                    compiled_pattern = re.compile(pattern, re.IGNORECASE)
                except re.error as e:
                    console.print(f"[red]❌ Invalid regex pattern: {e}[/red]")
                    return
            
            # Build filter pattern for CloudWatch (if possible)
            cw_filter_pattern = self._build_cloudwatch_filter(pattern, is_regex)
            
            console.print(f"\n[bold cyan]🔍 Search Results[/bold cyan]")
            console.print(f"[dim]Log Group: {log_group_name}[/dim]")
            console.print(f"[dim]Pattern: {pattern} ({'regex' if is_regex else 'literal'})[/dim]")
            console.print(f"[dim]Limit: {limit} matches[/dim]")
            
            # Start timing
            search_start_time = time.time()
            matches_found = 0
            total_events = 0
            
            # Create paginator for log events
            paginator = self.logs_client.get_paginator('filter_log_events')
            page_iterator = paginator.paginate(
                logGroupName=log_group_name,
                startTime=start_timestamp,
                endTime=end_timestamp,
                filterPattern=cw_filter_pattern if cw_filter_pattern else None
            )
            
            # Process log events
            for page in page_iterator:
                events = page.get('events', [])
                total_events += len(events)
                
                for event in events:
                    if matches_found >= limit:
                        console.print(f"\n[yellow]⚠️ Reached limit of {limit} matches[/yellow]")
                        break
                        
                    message = event.get('message', '')
                    
                    # Apply client-side filtering if needed
                    if is_regex and compiled_pattern:
                        if not compiled_pattern.search(message):
                            continue
                    elif not is_regex and cw_filter_pattern is None:
                        if pattern.lower() not in message.lower():
                            continue
                    
                    # Format timestamp
                    timestamp = event.get('timestamp', 0)
                    dt = datetime.fromtimestamp(timestamp / 1000)
                    time_str = dt.strftime('%Y-%m-%d %H:%M:%S')
                    
                    # Highlight pattern in message
                    highlighted_message = self._highlight_pattern(message, pattern, is_regex, compiled_pattern)
                    
                    # Display the match
                    console.print(f"[dim]{time_str}[/dim] {highlighted_message}")
                    matches_found += 1
                
                if matches_found >= limit:
                    break
            
            # Calculate total search time
            total_search_time = time.time() - search_start_time
            
            # Display summary
            console.print(f"\n[bold green]✅ Search Complete[/bold green]")
            console.print(f"Found [bold]{matches_found}[/bold] matches in [bold]{total_events}[/bold] log events")
            console.print(f"⏱️ Total search time: [bold]{total_search_time:.2f}s[/bold]")
            
            if matches_found > 0:
                events_per_second = total_events / total_search_time if total_search_time > 0 else 0
                console.print(f"📊 Processing rate: [bold]{events_per_second:.0f}[/bold] events/second")
            
            if matches_found == 0:
                console.print("[yellow]💡 No matches found. Try adjusting your search pattern or time range[/yellow]")
            elif matches_found == limit:
                console.print(f"[yellow]💡 Results limited to {limit} matches. Use --limit to increase[/yellow]")
            
            # Display AWS API call summary
            self.aws_logger.display_summary()
                
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'ResourceNotFoundException':
                console.print(f"[red]❌ Log group '{log_group_name}' not found[/red]")
            elif error_code == 'InvalidParameterException':
                console.print(f"[red]❌ Invalid search parameters: {e.response['Error']['Message']}[/red]")
            else:
                console.print(f"[red]❌ AWS API error: {e}[/red]")
        except Exception as e:
            console.print(f"[red]❌ Search error: {e}[/red]")

@click.command()
@click.option('--region' ,type=str, help="The region where your logs should be looked at, default ap-southeast-2" )
@click.option('--debug', is_flag=True, help='Enable detailed AWS API call debugging')
@click.option('--log-group', '-g', help='Log group name to search (e.g., /aws/lambda/my-function)')
@click.option('--pattern', '-p', help='Search pattern (regex or literal string)')
@click.option('--hours', '-h', type=int, help='Search last N hours (default: 1)')
@click.option('--start-time', '-s', help='Start time (e.g., "2024-01-15 14:30" or "yesterday 2pm")')
@click.option('--end-time', '-e', help='End time (e.g., "2024-01-15 16:00" or "now")')
@click.option('--limit', '-l', type=int, default=100, help='Maximum number of matches to return (default: 100)')
def main(region, debug, log_group, pattern, hours, start_time, end_time, limit):
    """CloudWatch Logs Grep Tool - Interactive log searching for AWS CloudWatch.
    
    Examples:
      # Interactive mode
      cwgrep.py
      
      # Direct search - last hour
      cwgrep.py -g /aws/lambda/api -p "ERROR.*timeout"
      
      # Direct search - last 4 hours  
      cwgrep.py -g /aws/lambda/api -p "ERROR" -h 4
      
      # Direct search - custom time range
      cwgrep.py -g /aws/lambda/api -p "ERROR" -s "2024-01-15 14:00" -e "2024-01-15 16:00"
    """
    if region :
        global default_region
        console.print("Selected region ", region)
        default_region = region
    try:
        app = CloudWatchGrep(debug_mode=debug)
        
        # Check if we have command-line arguments for direct search
        if log_group and pattern:
            app.run_direct_search(log_group, pattern, hours, start_time, end_time, limit)
        else:
            # Run interactive mode
            app.run()
    except KeyboardInterrupt:
        console.print("\n[yellow]👋 Goodbye![/yellow]")
    except Exception as e:
        console.print(f"[red]❌ Unexpected error: {e}[/red]")
        sys.exit(1)

if __name__ == "__main__":
    main()
