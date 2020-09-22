# Nessus Scripts

Scripts to manipulate output from Nessus single instances for pentesting engagements.

## List of scripts and usage

1. Parse_nessus.py

Extract FQDN and IPs from HTML report. Useful to cross check duplicate resources. Written for python3, requires bs4

```bash
pip install bs4
python parse_nessus.py -i <html report> -o <csv output file>
```
