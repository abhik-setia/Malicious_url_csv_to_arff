import numpy as np
import pandas as pd

def read_csv():
	benign_url_path="data/benign.csv"
	malicious_url_path="data/malicious.csv"

	b_data=pd.read_csv(benign_url_path)
	m_data=pd.read_csv(malicious_url_path)


	arff_file=open('train.arff',"w")

	RELATION_NAME="Malicious_URLs"
	arff_file.write("@RELATION " + RELATION_NAME + "\n")
	
	feature_columns_to_use=['Malicious_website','Server_Ip_address','Country','server','Malicious_files','Suspicious_files'
	,'Potentially_Suspicious_files','Clean_files','External_links_detected','Iframes_scanned','Blacklisted']
	
	for feature in feature_columns_to_use:
		if feature=="Malicious_website" or feature=="Country" or feature=="server" or feature=="Server_Ip_address":
			arff_file.write("@ATTRIBUTE "+feature +" string \n")
		elif feature=="Blacklisted":
			arff_file.write("@ATTRIBUTE "+feature +" {yes,no} \n")
		else:
			arff_file.write("@ATTRIBUTE "+feature +" real \n")	
	
	###PREDEFINED USER FEATURES#######
	arff_file.write("@ATTRIBUTE Malicious {0,1}\n") 
	arff_file.write("@DATA\n")

	for b_urls in b_data.itertuples():
		buff=""
		for index,x in enumerate(feature_columns_to_use):
			if index!=0:
				buff+=str(b_urls[index])+","
		buff+="0"
		arff_file.write(buff+"\n")

	for m_urls in m_data.itertuples():
		buff=""
		for index,x in enumerate(feature_columns_to_use):
			if index!=0:
				buff+=str(m_urls[index])+","
		buff+="1"
		arff_file.write(buff+"\n")
	

if __name__=="__main__":
	read_csv()