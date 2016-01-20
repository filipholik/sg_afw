# Web application for Adaptive Firewall for Smart Grid Security (3.2.3)

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
</h3>

"""

@app.route('/')
def index():
  page = '<h2 ' + css_h2 + '>Main page </h2>'
  page += '<div style="text-align:center">'
  page += menu
  page += "</div>"
  return page_header + page

@app.route('/rules')
def rules():
  page = '<h2 ' + css_h2 + '>Active rules </h2>'
  page += '<div style="text-align:center">'
  page += menu
  httpRequest = ""
  conn = httplib.HTTPConnection("127.0.0.1",8080)
   #---JSON Switch2---
  conn.request("GET","/fw/rules/2960111173765568",httpRequest)
  response = conn.getresponse()
  page += "<h3>Switch2</h3> \n"
  data = json.load(response)
  page += printTable(data)
  conn.close()

   #---JSON Switch4---
  conn.request("GET","/fw/rules/2991443865190400",httpRequest)
  response = conn.getresponse()
  page += "<h3>Switch4</h3>"
  data = json.load(response)
  page += printTable(data)
  conn.close()

  page += "</div>"
  return page_header + page


def printTable(data):
  page = """<table border="1" style="width:100%">\n
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


if __name__ == '__main__':
    app.debug = True
    app.run()
