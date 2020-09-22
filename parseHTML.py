from bs4 import BeautifulSoup
from urllib.request import urlopen
import csv
import sys, getopt

def main(argv):
	inputfile = ''
	outputfile = ''
	try:
	  opts, args = getopt.getopt(argv,"hi:o:",["ifile=","ofile="])
	  if len(opts) < 2:
	  	print ('test.py -i <inputfile> -o <outputfile>')
	  	sys.exit(2)
	except getopt.GetoptError:
	  print ('test.py -i <inputfile> -o <outputfile>')
	  sys.exit(2)
	for opt, arg in opts:
	  if opt == '-h':
	     print ('test.py -i <inputfile> -o <outputfile>')
	     sys.exit()
	  elif opt in ("-i", "--ifile"):
	     inputfile = arg
	  elif opt in ("-o", "--ofile"):
	     outputfile = arg
	print ('Input file is "', inputfile)
	print ('Output file is "', outputfile)

	html = urlopen("file://"+inputfile)

	soup = BeautifulSoup(html, 'html.parser')
	container_ids = []
	for div in soup.findAll("div", {"xmlns" : ""}):
		div_id = div.get('id')
		if isinstance(div_id, str) and div_id.find("-container")>-1:
			container_ids.append(div_id)

	ids = {x.replace('-container', '') for x in container_ids}
	print(ids)
	rows = [["title","unique ID", "unique title","cvss3.0 score", "AV","AC","PR","UI","S","C","I","A"]]

	def get_score(text):
		score = text.split("/")[0]
		return score

	for value in ids:
		div = soup.find("div", {"id" : value})
		div_title = div.text.replace('\n','').replace('  ','')
		div_title_split = div_title.split("-")
		div_title_unique_id = div_title_split[0].split('(')[0].replace(' ','')
		div_title_unique_title = div_title_split[1][1:]
		container_id = value+'-container'
		div_content_divs = soup.find("div", {"id" : container_id}).find_all("div",{"style" : "line-height: 20px; padding: 0 0 20px 0;"})
		cvss_div = ""
		cvss_score = ""
		cvss_detail = ""
		cvss_detail_split = ""
		cvss_av = ""
		cvss_ac = ""
		cvss_pr = ""
		cvss_ui = ""
		cvss_s = ""
		cvss_c = ""
		cvss_i = ""
		cvss_a = ""
		for i in range(0, len(div_content_divs)):
			div_text = div_content_divs[i].text
			if (isinstance(div_text, str)  and div_text.find("CVSS:3.0")>-1):
				cvss_div = div_text
				cvss_score = cvss_div.split()[0]
				cvss_detail = cvss_div.split()[1]
				cvss_detail_split = cvss_detail.split('/')
				cvss_grade = cvss_detail_split[0].split(":")[1]
				cvss_av = cvss_detail_split[1].split(":")[1]
				cvss_ac = cvss_detail_split[2].split(":")[1]
				cvss_pr = cvss_detail_split[3].split(":")[1]
				cvss_ui = cvss_detail_split[4].split(":")[1]
				cvss_s = cvss_detail_split[5].split(":")[1]
				cvss_c = cvss_detail_split[6].split(":")[1]
				cvss_i = cvss_detail_split[7].split(":")[1]
				cvss_a = cvss_detail_split[8].split(":")[1].replace(')','')

				break
			
			
		rows.append([div_title, div_title_unique_id, div_title_unique_title, cvss_score, cvss_av,cvss_ac,cvss_pr,cvss_ui,cvss_s,cvss_c,cvss_i,cvss_a])

	print(rows)

	with open(outputfile, 'w+') as csvFile:
		for row in rows:
			writer= csv.writer(csvFile)
			writer.writerow(row)

	csvFile.close()


if __name__ == "__main__":
   main(sys.argv[1:])