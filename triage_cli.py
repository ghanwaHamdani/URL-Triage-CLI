import click                                # for parsing terminal command line options and args
from colorama import Fore, Style, init      # for terminal output formatting (make it lok pretty!!)
from triage_analyzer import URLAnalyzer     # the analyzer class we made in the analyzer file

# resets text styling after each print line
init(autoreset = True)

@click.command()            # decorator, converts main() into CLI entry point
@click.argument("url")   

# analyze URL for phishing indicators
def main(url):
    click.echo(f"\n{Style.BRIGHT}Analyzing URL: {url}...\n" + "-" * 50)

    # instantiate the analyzer
    analyzer = URLAnalyzer(url) 
    report = analyzer.analyze()

    color = Fore.GREEN
    if report["risk_level"] == "MEDIUM":
        color = Fore.YELLOW
    elif "HIGH" in report["risk_level"]:
        color = Fore.RED

    # print all the metadata and risk score
    click.echo(f"Domain:        {report['domain']}")
    click.echo(f"Risk Score:    {report['score']}/100")
    click.echo(f"Risk Level:    {color}{Style.BRIGHT}{report['risk_level']}{Style.RESET_ALL}\n")

    click.echo("Warnings:")
    if not report["findings"]:
        click.echo("    [+] No obvious automated heuristics flagged.")
    else:
        for warning in report["warnings"]:
            click.echo(f"   {warning}")
    click.echo("-" * 50 + "\n")   

    if __name__ == "__main__":
        main()                