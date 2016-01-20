# Web application for Adaptive Firewall for Smart Grid Security (3.2.4)

from flask import Flask
from flask import request
import httplib #for Python 2.x
import json
from pprint import pprint


app = Flask(__name__)
page_header = '<h1 style="text-align:center;">SG Firewall application</h1>\n'
css_h2 = 'style="background-color:11557C; color:white; text-align:center; "'
menu = """
<h3 style="background-color:98AFC7; text-align:center;">
  <a href='/' style='color:black; '>Main page</a>
  <a href='/rules' style='color:black; margin-left:10px'>Display active rules</a>
  <a href='/todo' style='color:black; margin-left:10px'>Add a new rule</a>
  <a href='/traffic' style='color:black; margin-left:10px'>Display denied traffic</a>
</h3>

"""

@app.route('/')
def index():
  page = menu + '<h2 ' + css_h2 + '>Main page </h2>'
  page += '<div style="text-align:center">'
  #page += menu
  page += "<h3> Info </h3>"
  page += "<p>Application of SDN in Smart Grid substation.  </p>"
  page += "</div>"
  return page_header + page

@app.route('/rules')
def rules():
  page = menu + '<h2 ' + css_h2 + '>Active rules </h2>'
  page += '<div style="text-align:center">'
  httpRequest = ""
  conn = httplib.HTTPConnection("127.0.0.1",8080)
  #---JSON Switch2---
  conn.request("GET","/fw/rules/2960111173765568",httpRequest)
  response = conn.getresponse()
  page += "<h3>Switch2</h3> \n"
  if response.status == 200:
    data = json.load(response)
    page += printTable(data)
  else:
    page += "<p><b>Cannot connect to the switch... </b></p>"
  conn.close()

  #---JSON Switch4---
  conn.request("GET","/fw/rules/2991443865190400",httpRequest)
  response = conn.getresponse()
  page += "<h3>Switch4</h3>"
  if response.status == 200:
    data = json.load(response)
    page += printTable(data)
  else:
    page += "<p><b>Cannot connect to the switch... </b></p>"
  conn.close()

  page += "</div>"
  return page_header + page

@app.route('/traffic')
def traffic():
  page = menu + '<h2 ' + css_h2 + '>Denied traffic </h2>'
  page += '<div style="text-align:center">'

  httpRequest = ""
  conn = httplib.HTTPConnection("127.0.0.1",8080)

  #---JSON Switch2---
  conn.request("GET","/fw/traffic/2960111173765568",httpRequest)
  response = conn.getresponse()
  page += "<h3>Switch2</h3>"
  if response.status == 200:
    data = json.load(response)
    page += printTraffic(data)
  else:
    page += "<p><b>Cannot connect to the switch... </b></p>"
  conn.close()

  #---JSON Switch4---
  conn.request("GET","/fw/traffic/2991443865190400",httpRequest)
  response = conn.getresponse()
  page += "<h3>Switch4</h3>"
  if response.status == 200:
    data = json.load(response)
    page += printTraffic(data)
  else:
    page += "<p><b>Cannot connect to the switch... </b></p>"
  conn.close()

  page += "</div>"
  return page_header + page

def printTable(data):
  page = """<table border="1" style="width:80%; margin-left:10%">\n
  <tr> <th>Number </th> <th> Table ID </th> <th> Prio </th>
  <th> Duration (s) </th> <th> Idle (s) </th> <th> Packets </th>  </tr>
  \n"""
  #print data
  col = -1
  num = 1
  for d in data:
    sepparated = d.split()
    col += 1
    color = "white"
    if num % 2 == 0:
      color = "#E0FFFF "

    if col == 0:
      page += '<tr style="text-align:center; background-color: ' + color +'"><td rowspan="5">' + str(num) + "</td>"
      page += "<td>" + sepparated[2] + "</td>"
    elif col == 1 or col == 2 or col == 3:
      page += "<td>" + sepparated[2] + "</td>"
    elif col == 4:
      page += "<td>" + sepparated[2] + "</td><tr/>"
    elif col == 5:
      page += '<tr style="text-align:center; background-color: ' + color +'"><td colspan="5">' + d + "</td><tr/>"
    elif col == 6:
      page += '<tr style="text-align:center; background-color: ' + color +'"><td colspan="5">' + d + "</td><tr/>"
      col = -1
      num += 1
    #print d
  page += "</table>"
  return page

def printTraffic(data):
  page = """<table border="1" style="width:80%; margin-left:10%">\n
  <tr> <th>Number </th> <th> Source </th> <th> Destination </th>
  <th> Eth Proto </th> <th> Action </th>  </tr>
  \n"""
  #print data

  num = 1
  for d in data:
    index = 0
    color = "white"
    if num % 2 == 0:
      color = "#E0FFFF "
    for i in d:
      if index == 0:
        page += '<tr style="text-align:center; background-color: ' + color +'"><td>' + str(num) + '</td>'
        num += 1
      sepparated = i.split()
      if index == 2:
        proto = decodeEthProto(sepparated[2]) + " (" +sepparated[2] + ") "
        page += "<td>" + proto + "</td>"
      else:
        page += "<td>" + sepparated[2] + "</td>"
      index += 1
      if index == 3:
        page += "<td><a href='/todo'style='color:black;'>ALLOW</a>  </td></tr>"
        index = 0

  page += "</table>"
  return page

def decodeEthProto(eth_proto):
  if int(eth_proto) == 2048:
    return "IPv4"
  if int(eth_proto) == 2054:
    return "ARP"
  return "uknown"

@app.route('/todo')
def todo():
  page = menu + '<h2 ' + css_h2 + '>Not yet implemented </h2>'
  page += '<div style="text-align:center">'
  #page += menu
  page += "<h3> TODO </h3>"
  page += "<p>This function is not yet implemented.  </p>"
  page += "<a href='/'style='color:black;'>Main page</a> "
  page += "</div>"
  return page_header + page


if __name__ == '__main__':
    app.debug = True
    app.run()
