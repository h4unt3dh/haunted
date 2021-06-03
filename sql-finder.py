#!/bin/python3

import argparse
import bs4 as bs
import requests
import pyfiglet
import pprint
import sys
import urllib

script_name = pyfiglet.figlet_format('SQL-Finder')
print(script_name)

parser = argparse.ArgumentParser(add_help=True, description = 'A simple script to find SQL injection in a given web page ')
parser.add_argument('-u','--url', action='store', help='URL to target', required=True)
args = parser.parse_args()

s = requests.Session()

#Returns all forms from URL
def get_forms(url):
	soup = bs(s.get(url).content, 'html.parser')
	return soup.find_all('form')
 
#Extracts useful details from a HTML Form
def form_details(form):
	results = {}
	#Gets form action from target url
	try:
		action = forms.attrs.get('action').lower()
	except:
		action = None
	#Retrieves form method e.g. POST
	method = form.attrs.get('method', 'get').lower
	#Retrieves input details in the form
	inputs= []
	for input_tag in form.find_all('input'):
		input_type = input_tag.attrs.get('type', 'text')
		input_name = input_tag.attrs.get('name')
		input_value = input_tag.attrs.get('value', '')
		inputs.append({'type' : input_type , 'name' : input_name, 'value' : input_value})
	
	#Stories everything in the results dictionary
	results['action'] = action
	results['method'] = method
	results['inputs'] = inputs
	return details
	
def vuln_check(response):
	#Checks if anywhere on the page is vulnerable to SQLi based on response
	#List of errors categorised into their DBMS's
	errors = {
	#MySQL
	'you have an error in your sql syntax;',
	'warning: mysql',
	#SQL Server
	'unclosed quotation mark after the character string',
	#Oracle
	'quoted string not properly terminated',
	}
	
	for error in errors:
		if error in response.content.decode().lower():
			return True
		else:
			return False
			
def sqli_scan(url):
	#Tests URL
	for i in "\"'":
		#Appends quote/double quote to URL
		new_url = f'{url}{i}'
		print(f'[*] Trying: {new_url}')
		#Sends request
		r = s.get(new_url)
		if vuln_check(r): #If SQLi is detected forms aren't extracted
			print(f'[!!!] SQL Injecion detected on: {new_url}')
			return
	#Tests HTML Forms
	forms = get_forms(url)
	print(f'[!!!] Detected {len(forms)} forms on {url} !')
	for form in forms:
		get_form_details = form_details(form)
		for i in "\"'":
			data = {}
			for input_tag in form_details['inputs']:
				if input_tag['type'] == 'hiddem' or input_tag['value']:
					#Any input form with a value or is hidden will be used in the body
					try:
						data[input_tag['name']] = input_tag['value'] + i
					except:
						pass
				elif input_tag['type'] != 'submit':
				#Everything except sub,it will use a special char as data
					data[input_tag['name']] = f'test{i}'
			#Joins url and action, form request URL
			url = urljoin(url, form_details['action'])
			if form_details['method'] == 'post':
				r = s.post(url, data=data)
			elif form_details['method'] == 'get':
				r = s.get(url, params=data)
			#Tests whether the page returned is vulnerable
			if vuln_check(r):
				print(f'[!!!] SQL Injecion detected on: {url}')
				print('[+] Form:')
				pprint(form_details)
				break
				
if __name__ == '__main__':
	url = args.url
	sqli_scan(url)
			
