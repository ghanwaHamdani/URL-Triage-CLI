This is a python command line tool for inspecting links for any kind of phishing or suspicious activity.

HOW IT WORKS...
	triage_analyzer.py - this contains all the inspection logic. It takes raw URL string, breaks it down to its individual parts (scheme, domain, path, TLD), and runs 4 safety checks.
	triage_cli.py - this contains the code foe the command line interface. It uses click to handle the arguments in the command line. I also used colorama to make the report color coded according to the risk level.
	test_analyzer.py - this file just contains some tests that I ran to make sure the URLAnalyzer behaves as needed.
	setup.py - this is the configuration file used to turn the whole project into an installable python package.

In simple terms, you enter a link into the command line and it runs 4 safety check...
	1. it checks whether it contains numbers or a real domain name (+40 points)
	2. it checks if it uses common spam domains (+20 points)
	3. it check for suspicious keywords in weird spots (+15 points)
	4. it checks how new the domain is (+30 points)
After running all these test it will print out a summary showcasing the risk score, risk level, and list of red flags in the URL.
