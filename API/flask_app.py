from flask import Flask,render_template,url_for,request
from flask_material import Material

# EDA PKg
import pandas as pd 
import numpy as np 

# ML Pkg
import joblib


app = Flask(__name__,static_url_path='/static',template_folder='./templates')
Material(app)

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/dataset')
def dataset():
    return render_template("practice.html")
@app.route('/Home')
def Home():
    return render_template("index.html")    

@app.route('/MLModels')
def MLModels():
    return render_template("predict.html")

@app.route('/',methods=["POST"])
def analyze():
	if request.method == 'POST':
		protocol_type_1={

            'icmp': 0,
            'tcp': 1,
            'udp': 2
            }

		service_1={
		        'IRC': 0,
			    'X11': 1,
			    'Z39_50': 2,
				'auth': 3,
				'bgp': 4,
				'courier': 5,
				'csnet_ns': 6,
				'ctf': 7,
				'daytime': 8,
				'discard': 9,
				'domain': 10,
				'domain_u': 11,
				'echo': 12,
		    	'eco_i': 13,
		    	'ecr_i': 14,
		    	'efs': 15,
		    	'exec': 16,
		    	'finger': 17,
		    	'ftp': 18,
		    	'ftp_data': 19,
		    	'gopher': 20,
		    	'hostnames': 21,
		    	'http': 22,
		    	'http_443': 23,
		    	'imap4': 24,
		    	'iso_tsap': 25,
		    	'klogin': 26,
		    	'kshell': 27,
		    	'ldap': 28,
		    	'link': 29,
		    	'login': 30,
		    	'mtp': 31,
		    	'name': 32,
		    	'netbios_dgm': 33,
		    	'netbios_ns': 34,
		    	'netbios_ssn': 35,
		    	'netstat': 36,
		    	'nnsp': 37,
		    	'nntp': 38,
		    	'ntp_u': 39,
		        'other': 40,
		        'pm_dump': 41,
		        'pop_2': 42,
		        'pop_3': 43,
		        'printer': 44,
		        'private': 45,
		        'red_i': 46,
		        'remote_job': 47,
		        'rje': 48,
		        'shell': 49,
		        'smtp': 50,
		        'sql_net': 51,
		        'ssh': 52,
		        'sunrpc': 53,
		        'supdup': 54,
		        'systat': 55,
		        'telnet': 56,
		        'tftp_u': 57,
		        'tim_i': 58,
		        'time': 59,
		        'urh_i': 60,
		        'urp_i': 61,
		        'uucp': 62,
		        'uucp_path': 63,
		        'vmnet': 64,
		        'whois': 65
			}

		flag_1={
		    'OTH': 0,
		    'REJ': 1,
		    'RSTO': 2,
		    'RSTOS0': 3,
		    'RSTR': 4,
		    'S0': 5,
		    'S1': 6,
		    'S2': 7,
		    'S3': 8,
		    'SF': 9,
		    'SH': 10
		 }
		target_1={
			0:'Normal',
			1:'Dos',
			2:'Probe',
			3:'Root_to_Local',
			4:'User_to_Root'
		}

		protocol_type = protocol_type_1[request.form['protocol']]
		service = service_1[request.form['service']]
		flag = flag_1[request.form['flag']]

		count = request.form['count']
		srv_count = request.form['serv_count']
		rerror_rate = request.form['error_rate']

		src_bytes = request.form['src_bytes']
		num_root = request.form['num_root']
		is_guest_login = request.form['is_guest_login']

		dst_host_count = request.form['dst_host_count']
		dst_host_srv_count = request.form['dst_host_srv_count']
		dst_bytes = request.form['dest_bytes']

		duration = 0
		#protocol_type = icmp
		#service = ecr_i
		#flag = SF
		#src_bytes = 1032
		#dst_bytes = 0
		land = 0
		wrong_fragment = 0
		urgent = 0
		hot = 0
		num_failed_logins = 0
		logged_in = 0
		num_compromised = 0
		root_shell = 0
		su_attempted = 0
		#num_root = 0
		num_file_creations = 0
		num_shells = 0
		num_access_files = 0
		num_outbound_cmds = 0
		is_host_login = 0
		#is_guest_login = 0
		#count = 511
		#srv_count = 511
		serror_rate = 0.0
		srv_serror_rate = 0.0
		#rerror_rate = 0.0
		srv_rerror_rate = 0.0
		same_srv_rate = 1.0
		diff_srv_rate = 0.0
		srv_diff_host_rate = 0.0
		#dst_host_count = 255
		#dst_host_srv_count = 255
		dst_host_same_srv_rate = 1.0
		dst_host_diff_srv_rate = 0.0
		dst_host_same_src_port_rate = 1.0
		dst_host_srv_diff_host_rate = 0.0
		dst_host_serror_rate = 0.0
		dst_host_srv_serror_rate = 0.0
		dst_host_rerror_rate = 0.0
		dst_host_srv_rerror_rate = 0.0


		# Clean the data by convert from unicode to float 
		sample_data = [duration, protocol_type, service, flag, src_bytes,
       dst_bytes, land, wrong_fragment, urgent, hot,
       num_failed_logins, logged_in, num_compromised, root_shell,
       su_attempted, num_root, num_file_creations, num_shells,
       num_access_files, num_outbound_cmds, is_host_login,
       is_guest_login, count, srv_count, serror_rate,
       srv_serror_rate, rerror_rate, srv_rerror_rate, same_srv_rate,
       diff_srv_rate, srv_diff_host_rate, dst_host_count,
       dst_host_srv_count, dst_host_same_srv_rate,
       dst_host_diff_srv_rate, dst_host_same_src_port_rate,
       dst_host_srv_diff_host_rate, dst_host_serror_rate,
       dst_host_srv_serror_rate, dst_host_rerror_rate,
       dst_host_srv_rerror_rate]


		clean_data = [float(i) for i in sample_data]

		# Reshape the Data as a Sample not Individual Features
		ex1 = np.array(clean_data).reshape(1,-1)
		#print(ex1)

		# ex1 = np.array([6.2,3.4,5.4,2.3]).reshape(1,-1)

		# Reloading the Model
		"""
		if model_choice == 'logitmodel':
		    logit_model = joblib.load('data/logit_model_iris.pkl')
		    result_prediction = logit_model.predict(ex1)
		elif model_choice == 'knnmodel':
			knn_model = joblib.load('data/knn_model_iris.pkl')
			result_prediction = knn_model.predict(ex1)
		elif model_choice == 'svmmodel':
		"""	
		knn_model = joblib.load('data/model_final.pkl')
		result_prediction = target_1[knn_model.predict(ex1)[0]]


	return render_template('predict.html',result_prediction=result_prediction)


if __name__ == '__main__':
	app.run(debug=True,port=12347)