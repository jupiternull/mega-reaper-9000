"""
Command Executor Service
Executes terminal commands with security restrictions
"""

import subprocess
import shlex
import re

class CommandExecutor:
    def __init__(self):
        # Whitelist of allowed commands
        self.allowed_commands = [
            'nmap', 'masscan', 'ping', 'traceroute', 'dig', 'nslookup',
            'netstat', 'ss', 'ifconfig', 'ip', 'route', 'arp',
            'ls', 'pwd', 'whoami', 'uname', 'hostname', 'uptime',
            'ps', 'top', 'df', 'du', 'free', 'cat', 'head', 'tail',
            'grep', 'awk', 'sed', 'curl', 'wget', 'whois',
            'nikto', 'hydra', 'sqlmap', 'help', 'clear'
        ]
        
        # Commands that return help/info
        self.info_commands = {
            'help': self._get_help,
            'clear': lambda: {'output': '', 'clear': True}
        }
    
    def execute(self, command):
        """
        Execute command with security checks
        
        Args:
            command: Command string to execute
            
        Returns:
            dict: Command output and metadata
        """
        
        command = command.strip()
        
        if not command:
            return {'output': '', 'error': False}
        
        # Handle info commands
        if command in self.info_commands:
            result = self.info_commands[command]()
            return {'output': result.get('output', ''), 'error': False, 'clear': result.get('clear', False)}
        
        # Parse command
        try:
            parts = shlex.split(command)
        except ValueError as e:
            return {'output': f'[!] Invalid command syntax: {e}', 'error': True}
        
        if not parts:
            return {'output': '', 'error': False}
        
        cmd = parts[0]
        
        # Security check: command must be whitelisted
        if cmd not in self.allowed_commands:
            return {
                'output': f'[!] Command not allowed: {cmd}\n[*] Type "help" for available commands',
                'error': True
            }
        
        # Security check: prevent dangerous flags
        dangerous_patterns = [
            r'rm\s+-rf',
            r'--exec',
            r'sudo',
            r'su\s',
            r'chmod',
            r'chown',
            r'>/dev/',
            r'\|.*sh',
            r';\s*rm',
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, command):
                return {
                    'output': '[!] Potentially dangerous command blocked',
                    'error': True
                }
        
        # Execute command
        try:
            result = subprocess.run(
                parts,
                capture_output=True,
                text=True,
                timeout=30,  # 30 second timeout
                shell=False
            )
            
            output = result.stdout if result.stdout else result.stderr
            
            # Format output
            if not output:
                output = '[*] Command executed successfully (no output)'
            
            return {
                'output': output,
                'error': result.returncode != 0,
                'returncode': result.returncode
            }
            
        except subprocess.TimeoutExpired:
            return {
                'output': '[!] Command timed out after 30 seconds',
                'error': True
            }
        except FileNotFoundError:
            return {
                'output': f'[!] Command not found: {cmd}\n[*] Make sure the tool is installed',
                'error': True
            }
        except Exception as e:
            return {
                'output': f'[!] Error executing command: {str(e)}',
                'error': True
            }
    
    def _get_help(self):
        """Return help text"""
        help_text = """
[*] Available commands:

NETWORK SCANNING:
  nmap [options] [target]    - Network scanner
  masscan [options] [target] - Fast port scanner
  ping [host]                - Send ICMP echo requests
  traceroute [host]          - Trace network route
  dig [domain]               - DNS lookup
  nslookup [domain]          - Query DNS servers

NETWORK INFO:
  netstat                    - Network connections
  ss                         - Socket statistics
  ifconfig / ip              - Network interfaces
  route                      - Routing table
  arp                        - ARP cache

SECURITY TOOLS:
  nikto -h [url]             - Web server scanner
  hydra [options]            - Password cracker
  sqlmap [options]           - SQL injection tool

SYSTEM INFO:
  ls, pwd, whoami            - Basic navigation
  ps, top                    - Process info
  df, du, free               - Disk/memory usage
  
OTHER:
  help                       - Show this help
  clear                      - Clear terminal
        """
        return {'output': help_text}
