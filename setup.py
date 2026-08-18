from setuptools import setup, find_packages         # handles package building and console script distribution

setup(
    name = "url-triage-cli",
    version = "0.1.0",
    packages = find_packages(),
    # python dependencies
    install_requires = [
        "click",
        "requests",
        "python-whois",
        "tldextract",
        "colorama",
    ],

    # executable binary command in virtual environment's bin folder
    entry_points = {
        "console_scripts": [
            "url-triage=triage_cli:main"
        ]
    }
)