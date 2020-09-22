from bs4 import BeautifulSoup
from urllib import urlopen
import csv, requests, sys, getopt

def main(argv):
	outputfile = ''
	startnum = 0
	stopnum = 0
	try:
	  opts, args = getopt.getopt(argv,"hb:e:o:",["ofile="])
	  if len(opts) < 3:
	  	print ('python nessus_scraper.py -b <nessuspluginstartnum> -e <nessuspluginstopnum> -o <csv outputfile>')
	  	sys.exit(2)
	except getopt.GetoptError:
	  print ('python nessus_scraper.py -b <nessusPluginStartNum> -e <nessusPluginStopNum> -o <csv outputfile>')
	  sys.exit(2)
	for opt, arg in opts:
		if opt == '-h':
			print ('python nessus_scraper.py -b <nessusPluginStartNum> -e <nessusPluginStopNum> -o <csv outputfile>')
			sys.exit()
		elif opt in ("-o", "--ofile"):
			outputfile = arg
		elif opt == '-b':
			startnum = int(arg)
		elif opt == '-e':
			stopnum = int(arg)
	print ('[+] Parsing Nessus plugins in range '+str(startnum)+' to '+str(stopnum)+' and saving to '+ outputfile)

	rows = [["plugin ID","title","synopsys", "description", "solution", "links","CVE", "cvss2.0","AV","AC","Au","C","I","A","cvss3.0", "AV","AC","PR","UI","S","C","I","A","E","RL","RC"]]

	for i in range(startnum, stopnum):
		vuln_synopsis = ""
		vuln_description = ""
		vuln_solution = ""
		vuln_links = []
		vuln_risk_factor = ""
		vuln_cve = ""
		cvss_version = ""
		cvss_2_av	 = ""
		cvss_2_ac	 = ""
		cvss_2_au	 = ""
		cvss_2_v	 = ""
		cvss_2_i	 = ""
		cvss_2_a	 = ""
		cvss_2_score = ""
		cvss_3_av	 = ""
		cvss_3_ac	 = ""
		cvss_3_pr	 = ""
		cvss_3_ui	 = ""
		cvss_3_s	 = ""
		cvss_3_c	 = ""
		cvss_3_i	 = ""
		cvss_3_a	 = ""
		cvss_3_e	 = ""
		cvss_3_rl	 = ""
		cvss_3_rc	 = ""
		cvss_3_score = ""


		headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.3'}
		url_current = "https://www.tenable.com/plugins/nessus/"+str(i)
		response = requests.get(url_current, headers=headers) 
		
		try:
			soup = BeautifulSoup(response.text, 'html.parser')
			vuln_description_sections = soup.find("div", {"class", "col-md-8"}).find_all("section")
			vuln_sidebar_ps = soup.find("div", {"class", "plugin-single__sidebar"}).find_all("p")
			vuln_sidebar_children = soup.find("div", {"class", "plugin-single__sidebar"}).findChildren()
			vuln_title = soup.find("div", {"class" : "plugin-single"}).select("h1")[0].text.strip()
			vuln_synopsis = vuln_description_sections[0].find("span").text.strip()
			vuln_description = vuln_description_sections[1].find("span").text.strip()
			vuln_solution = vuln_description_sections[2].find("span").text.strip()
			vuln_link_elements = vuln_description_sections[3].find_all("a")
			
			for link in vuln_link_elements:
				vuln_links.append(link.get("href"))

			vuln_link_string = ", ".join(str(x) for x in vuln_links)

			for index,child in enumerate(vuln_sidebar_children,start=1):
				try:
					bold_text = child.find("strong").text.strip()
				except:
					bold_text = ""
				if (child.name == "div" and bold_text.find("Risk Factor") > -1):
					vuln_risk_factor = child.find("span").text.strip()
				elif child.name == "h5":
					link = child.find("a").get("href")
					link_split = link.split("/")
					cvss_version = link_split[5].split("?")[0]
					if cvss_version == "v2-calculator":
						cvss_2_av	 = link_split[5].split("(")[1].split(":")[1]
						cvss_2_ac	 = link_split[6].split(":")[1]
						cvss_2_au	 = link_split[7].split(":")[1]
						cvss_2_v	 = link_split[8].split(":")[1]
						cvss_2_i	 = link_split[9].split(":")[1]
						cvss_2_a	 = link_split[10].split(":")[1]

						score_index = index+1
						cvss_2_score = vuln_sidebar_children[score_index].find("span").text.strip()
						
					elif cvss_version == "v3-calculator":
						cvss_3_av	 = link_split[5].split("(")[1].split(":")[1]
						cvss_3_ac	 = link_split[6].split(":")[1]
						cvss_3_pr	 = link_split[7].split(":")[1]
						cvss_3_ui	 = link_split[8].split(":")[1]
						cvss_3_s	 = link_split[9].split(":")[1]
						cvss_3_c	 = link_split[10].split(":")[1]
						cvss_3_i	 = link_split[11].split(":")[1]
						cvss_3_a	 = link_split[12].split(":")[1]
						cvss_3_e	 = link_split[13].split(":")[1]
						cvss_3_rl	 = link_split[14].split(":")[1]
						cvss_3_rc	 = link_split[15].split(":")[1]

						score_index = index+1
						cvss_3_score = vuln_sidebar_children[score_index].find("span").text.strip()

				elif child.name == "section":
					try: 
						search = child.find("h4").text.strip().find("Reference Information")
						if search > -1:
							vuln_cve = child.find("section").find("a").text.strip()
					except:
						pass



			rows.append([i, vuln_title, vuln_synopsis, vuln_description, vuln_solution, vuln_link_string, vuln_cve, cvss_2_score, cvss_2_av,cvss_2_ac, cvss_2_au,cvss_2_v,cvss_2_i,cvss_2_a,cvss_3_score, cvss_3_av,cvss_3_ac,cvss_3_pr,cvss_3_ui,cvss_3_s,cvss_3_c,cvss_3_i,cvss_3_a,cvss_3_e,cvss_3_rl,cvss_3_rc])
			print "[+] Parsed: "+vuln_title

		except:
			print "[-] Plugin doesn't exist: "+str(i)
			pass

	with open(outputfile, 'w+') as csvFile:
		for row in rows:
			writer= csv.writer(csvFile)
			writer.writerow(row)

	csvFile.close()
	print "[+] Done!"

if __name__ == "__main__":
   main(sys.argv[1:])