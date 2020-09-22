# Nessus Scripts

Scripts to manipulate output from Nessus single instances for pentesting engagements.

## List of scripts and usage

1. parse_html_dns.py

Extract FQDN and IPs from HTML report. Useful to cross check duplicate resources. Written for python3, requires bs4.

```bash
pip install bs4
python parse_nessus.py -i <html report> -o <csv output file>
```


2. nessus_scraper.py

Scrape all nessus plugins in range and save output to a csv file. Written in python3 requires requests library.

```bash
pip install requests
python nessus_scraper.py -b <nessusPluginStartNum> -e <nessusPluginEndNum> -o <csv output file>
```


3. parse_html_to_csv.py
Parse a Nessus html report and save the output to a csv file. Written in python3 requires requests library and bs4.

```bash
pip install requests, bs4
python parse_html_to_csv.py -i <html report> -o <csv output file>
```
