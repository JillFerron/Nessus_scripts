#!/usr/bin/python
import sys, getopt, os
from bs4 import BeautifulSoup

def main(argv):
	inputfile = ''
	outputfile = ''
	counter = 0
	try:
		opts, args = getopt.getopt(argv,"hi:o:",["ifile=","ofile="])
	except getopt.GetoptError:
		print "[+] Usage: python parse_html_dns.py -i <Nessus html report> -o <outputfile>"
		sys.exit(2)

	for opt, arg in opts:
		if opt == '-h':
			print "[+] Usage: python parse_html_dns.py -i <Nessus html report> -o <csv outputfile>"
			sys.exit()
		elif opt in ('-i', '--ifile'):
			inputfile = arg
		elif opt in ('-o', '--ofile'):
			outputfile = arg

	with open(inputfile, 'r') as f:
		print "[+] Exporting FQDNs and IP table to "+str(outputfile)
		contents = f.read()
		soup = BeautifulSoup(contents, 'lxml')
		divs = soup.find_all("div", class_="table-wrapper details")
		for div in divs:
			children = div.find_all("td")
			if len(children) > 3:
				if "Start time" not in children[0].text:
					ip = children[1].text
					fqdn = children[3].text

					out = open(outputfile,"a")
					out.write(str(ip)+','+str(fqdn)+'\n')
					out.close()
					counter += 1

		print "[+] Done. "+str(counter)+" rows added to file "+outputfile


if __name__ == "__main__":
   main(sys.argv[1:])