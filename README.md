# LogAttackFinder.py
ThThis Python script is designed to search for potential security vulnerabilities in a log file, including command injection, SQL injection, and cross-site scripting (XSS) attacks, even if they are URL-encoded.

The script takes a single argument from the command line, which should be the name of the log file to search. If no file name is provided, or if the user requests help by passing the "-h" or "--help" argument, the script will print a usage message.

Once the log file is opened and read into memory, the script uses regular expressions to search for patterns that match different types of attacks. For command injection attacks, the script searches for patterns that match common commands used by attackers, such as "cat", "rm", "mv", "curl", and so on. For SQL injection attacks, the script looks for patterns that match common SQL commands, such as "SELECT", "UNION", "INSERT", and so on. For XSS attacks, the script searches for patterns that match HTML script tags.

The script also takes into account the possibility that attack payloads may be URL-encoded, so it first decodes the file contents before searching for matches.

When the script finds a match for a potential attack, it prints the line number and the matched string. If no attacks are found, the script prints a message indicating that no vulnerabilities were detected.
