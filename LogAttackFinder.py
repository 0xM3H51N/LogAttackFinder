import sys
import re
import urllib.parse

# Define the regular expression patterns for different types of attacks
command_injection_pattern = r'\b(?:cat|rm|mv|cp|wget|curl|ls|dir|echo|tee|sed|awk|bash|sh|python|perl|ruby|php|java|node|powershell|nc|netcat|telnet|ssh|scp|ftp|tftp|sftp|sudo)\b'
sql_injection_pattern = r'(?:\bselect\b|\bunion\b|\binsert\b|\bupdate\b|\bdelete\b|\bdrop\b|\btruncate\b|\bcreate\b)'
xss_pattern = r'<\s*script\b[^>]*>[^<]*<\s*/\s*script\s*>'

# Check for a help argument
if len(sys.argv) == 2 and sys.argv[1] in ['-h', '--help']:
    print('Usage: python3 script_name.py log_file_name')
    print('Searches a log file for command injection, SQL injection, and XSS attacks, even if they are URL-encoded.')
    sys.exit()

# Check that a log file name was provided as an argument
if len(sys.argv) != 2:
    print('Error: log file name not provided.')
    print('Usage: python3 script_name.py log_file_name')
    sys.exit()

# Get the log file name from the command line argument
log_file_name = sys.argv[1]

# Open the log file for reading
try:
    with open(log_file_name, 'r') as f:
        # Read the entire file contents into a string
        file_contents = f.read()

        # URL-decode the file contents
        file_contents = urllib.parse.unquote(file_contents)

        # Split the file contents into lines
        lines = file_contents.split('\n')

        # Search for the different types of attacks in the file contents using regular expressions
        command_injection_matches = []
        sql_injection_matches = []
        xss_matches = []
        for i, line in enumerate(lines):
            line = urllib.parse.unquote(line)
            command_injection_matches += [(i+1, match) for match in re.findall(command_injection_pattern, line)]
            sql_injection_matches += [(i+1, match) for match in re.findall(sql_injection_pattern, line, re.IGNORECASE)]
            xss_matches += [(i+1, match) for match in re.findall(xss_pattern, line, re.IGNORECASE)]

        # Print any matches that were found
        if command_injection_matches or sql_injection_matches or xss_matches:
            if command_injection_matches:
                print('Command injection attack detected in log file:')
                for line_num, match in command_injection_matches:
                    print(f'Line {line_num}: {match}')
            if sql_injection_matches:
                print('SQL injection attack detected in log file:')
                for line_num, match in sql_injection_matches:
                    print(f'Line {line_num}: {match}')
            if xss_matches:
                print('XSS attack detected in log file:')
                for line_num, match in xss_matches:
                    print(f'Line {line_num}: {match}')
        else:
            print('No attacks detected in log file.')
except IOError:
    print('Error: could not open log file.')
    sys.exit()
