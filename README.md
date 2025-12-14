A python based tool to search for email breaches, checks to see if the email is connected to socials and leaks.


Installation Dependencies 

pip install requests dnspython pandas reportlab beautifulsoup4



Functions:

Email Validation: Checks for syntax, disposable status, and MX records.

Profile Enumeration: Searches for Gravatar and GitHub profiles.

Social Media Search Links: Generates direct search URLs for platforms like Twitter/X, LinkedIn, Instagram, and Facebook.

Breach & Reputation Checks: Integrates with HaveIBeenPwned for breach detection and provides a simple email reputation assessment.

Google Dorking: Generates advanced Google search queries for deeper web reconnaissance.

Reporting: Outputs results to the console, and generates structured CSV and human-readable PDF reports.

Performance: Utilizes multi-threading for faster checks across various sources.

Logging: Maintains a detailed log of all operations for traceability and debugging (osint_tool.log).
