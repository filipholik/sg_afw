# Web application for Adaptive Firewall for Smart Grid Security (3.3.4)

from flask import Flask, url_for
from flask import request
import httplib #for Python 2.x
import json
from pprint import pprint

from flask import make_response


app = Flask(__name__)
page_header = '<h1 style="text-align:center;">SG Firewall application</h1>\n'
css_h2 = 'style="background-color:11557C; color:white; text-align:center; "'
menu = """
<h3 style="background-color:98AFC7; text-align:center;">
  <a href='/' style='color:black; '>Main page</a>
  <a href='/rules' style='color:black; margin-left:10px'>Flow tables</a>
  <a href='/newrule' style='color:black; margin-left:10px'>Add a new rule</a>
  <a href='/trafficAllowed' style='color:black; margin-left:10px'>Allowed traffic</a>
  <a href='/trafficDenied' style='color:black; margin-left:10px'>Denied traffic</a>
  <a href='/vis' style='color:black; margin-left:10px'>Traffic visualization</a>
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
  page = menu + '<h2 ' + css_h2 + '>Flow tables </h2>'
  page += '<div style="text-align:center">'
  httpRequest = ""
  try:
    conn = httplib.HTTPConnection("127.0.0.1",8080)
  #---JSON Switch2---
    conn.request("GET","/fw/rules/2960111173765568",httpRequest)
    response = conn.getresponse()
  except:
    return error()
  page += "<h3>Switch2</h3> \n"
  if response.status == 200:
    data = json.load(response)
    page += printTable(data)
  else:
    page += "<p><b>Cannot connect to the switch... </b></p>"
  conn.close()

  #---JSON Switch4---
  try:
    conn.request("GET","/fw/rules/2991443865190400",httpRequest)
    response = conn.getresponse()
  except:
    return error()
  page += "<h3>Switch4</h3>"
  if response.status == 200:
    data = json.load(response)
    page += printTable(data)
  else:
    page += "<p><b>Cannot connect to the switch... </b></p>"
  conn.close()

  page += "</div>"
  return page_header + page

@app.route('/trafficAllowed')
def trafficAllowed():
  page = menu + '<h2 ' + css_h2 + '>Allowed traffic  </h2>'
  page += '<div style="text-align:center">'

  httpRequest = ""
  conn = httplib.HTTPConnection("127.0.0.1",8080)

  #---JSON Switch2---
  try:
    conn.request("GET","/fw/traffic_allowed/2960111173765568",httpRequest)
    response = conn.getresponse()
  except:
    return error()
  page += "<h3>Switch2</h3>"
  if response.status == 200:
    data = json.load(response)
    page += printAllowedTraffic(data)
  else:
    page += "<p><b>Cannot connect to the switch... </b></p>"
  conn.close()

  #---JSON Switch4---
  conn.request("GET","/fw/traffic_allowed/2991443865190400",httpRequest)
  response = conn.getresponse()
  page += "<h3>Switch4</h3>"
  if response.status == 200:
    data = json.load(response)
    page += printAllowedTraffic(data)
  else:
    page += "<p><b>Cannot connect to the switch... </b></p>"
  conn.close()

  page += "</div>"
  return page_header + page

@app.route('/trafficDenied')
def trafficDenied():
  page = menu + '<h2 ' + css_h2 + '>Denied traffic  </h2>'
  page += '<div style="text-align:center">'

  httpRequest = ""
  conn = httplib.HTTPConnection("127.0.0.1",8080)

  #---JSON Switch2---
  try:
    conn.request("GET","/fw/traffic_denied/2960111173765568",httpRequest)
    response = conn.getresponse()
  except:
    return error()
  page += "<h3>Switch2</h3>"
  if response.status == 200:
    data = json.load(response)
    page += printTraffic(data)
  else:
    page += "<p><b>Cannot connect to the switch... </b></p>"
  conn.close()

  #---JSON Switch4---
  conn.request("GET","/fw/traffic_denied/2991443865190400",httpRequest)
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

  #TODO auto refresh
  '''
  r = make_response()
  r.headers.set('<META HTTP-EQUIV="refresh" CONTENT="5">', "default-src 'self'")
  return r
  '''

def printTable(data):
  page = """<table border="1" style="width:80%; margin-left:10%">\n
  <tr> <th>Number </th> <th> Table ID </th> <th> Prio </th>
  <th> Duration (s) </th> <th> Idle (s) </th> <th> Packets </th>  </tr>
  \n"""
  #print data
  col = -1
  num = 1
  '''for d in data:
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
      num += 1'''

  for datadict in data:
    color = "white"
    if num % 2 == 0:
      color = "#E0FFFF "
    page += '<tr style="text-align:center; background-color: ' + color +'"><td rowspan="4">' + str(num) + "</td>"
    page += "<td>" + str(datadict['table_id']) + "</td>"
    page += "<td>" + str(datadict['priority']) + "</td>"
    page += "<td>" + str(datadict['duration_sec']) + "</td>"
    page += "<td>" + str(datadict['idle_timeout']) + "</td>"
    page += "<td>" + str(datadict['packet_count']) + "</td></tr>"
    page += "<tr style='text-align:center; background-color: " + color +"'><td colspan='5'>" + str(datadict['match']) + "</td></tr>"



    if 'matchdict' in datadict:
      flowdict = datadict['matchdict']
      matchstring = "Match: "
      if 'eth_src' in flowdict:
        matchstring += "src: " + str(flowdict['eth_src']) + " "
      if 'eth_dst' in flowdict:
        matchstring += "dst: " + str(flowdict['eth_dst']) + " "
      if 'eth_type' in flowdict:
        matchstring += "eth: " + str(flowdict['eth_type']) + " "
      if matchstring == "Match: ":
        matchstring = "Match everything"
      page += "<tr style='text-align:center; background-color: " + color +"'><td colspan='5'>" + matchstring + "</td></tr>"
    else:
      page += "<tr style='text-align:center; background-color: " + color +"'><td colspan='5'>Match not included in JSON. </td></tr>"

    page += "<tr style='text-align:center; background-color: " + color +"'><td colspan='5'>" + str(datadict['instructions']) + "</td></tr>"
    num+=1

  page += "</table>"
  return page

def printAllowedTraffic(data):
  page = """<table border="1" style="width:80%; margin-left:10%">\n
  <tr> <th>Number </th> <th> Source </th> <th> Destination </th>
  <th> Eth Proto </th> <th> Action </th>  </tr> \n"""
  if len(data) == 0:
    page += "<tr> <td colspan='5' style='text-align:center; '>No allowed traffic</td></tr>"
  num = 1
  for rule in data:
    color = "white"
    if num % 2 == 0:
      color = "#E0FFFF"
    page += '<tr style="text-align:center; background-color: ' + color +'"><td>' + str(num) + '</td>'
    if 'eth_src' in rule:
      page += "<td>" + rule['eth_src'] + "</td>"
    else:
      page += "<td>Any source</td>"
    if 'eth_dst' in rule:
      page += "<td>" + rule['eth_dst'] + "</td>"
    else:
      page += "<td>Any destination</td>"
    if 'eth_type' in rule:
      page += "<td>" + decodeEthProto(rule['eth_type']) + ": " + rule['eth_type'] + "</td>"
    else:
      page += "<td>Any protocol</td>"
    page += "<td><a href='/todo'style='color:black;'>DENY</a>  </td></tr>"
    num += 1

  page += "</table>"
  return page


def printTraffic(data):
  page = """<table border="1" style="width:80%; margin-left:10%">\n
  <tr> <th>Number </th> <th> Source </th> <th> Destination </th>
  <th> Eth Proto </th> <th> Action </th>  </tr>
  \n"""
  #print data

  if len(data) % 3 != 0:
    return data
    return "Unknown data format"

  if len(data) == 0:
    page += "<tr> <td colspan='5' style='text-align:center; '>No denied traffic</td></tr>"

  num = 1
  '''for d in data:
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
        index = 0'''
  index = 0
  for d in data:
    color = "white"
    if num % 2 == 0:
      color = "#E0FFFF"
    if index == 0:
      page += '<tr style="text-align:center; background-color: ' + color +'"><td>' + str(num) + '</td>'
      page += "<td>" + str(d) + "</td>"
    if index == 1:
      page += "<td>" + str(d) + "</td>"
    if index == 2:
      page += "<td>" + decodeEthProto(str(d)) + ": " + str(d) +   "</td>"
      page += "<td><a href='/todo'style='color:black;'>ALLOW</a>  </td></tr>"
      num += 1
      index = 0
      continue
    index += 1

  page += "</table>"

  return page

def decodeEthProto(eth_proto):
  if int(eth_proto) == 2048:
    return "IPv4"
  if int(eth_proto) == 2054:
    return "ARP"
  if int(eth_proto) == 35020:
    return "LLDP"
  return "unknown"

@app.route('/newrule')
def newRule():
  page = menu + '<h2 ' + css_h2 + '>Add a new rule </h2>'
  page += '<div style="text-align:center">'
  #page += menu
  page += "<h3> Insert a new FW rule into the network </h3>"
  page += "<p>Field marked with * are required.  </p>"

  page += """
  <form action="/sendRule" method="post" accept-charset="UTF-8"
  enctype="application/json" autocomplete="off" novalidate
  style="width:80%; margin-left:10%; " >
  <fieldset>
    <legend>Rule:</legend>
    Source MAC:
    <input type="text" name="src" value="fa:16:3e:30:cc:04"><br>
    Destination MAC:
    <input type="text" name="dst" value="fa:16:3e:5e:c6:ef"><br>
    Ethernet protocol:
    <select name="proto">
      <option value="0x0800">IP</option>
      <option value="0">Anything</option>
    </select>
    <br>
    Rule type:
    <select name="type">
      <option value="2">Two-ways</option>
      <option value="1">One-way</option>
    </select>
    <br>
    <input type="submit" value="Insert rule">
  </fieldset>
</form>

  """

  #page += "<a href='/'style='color:black;'>Main page</a> "
  page += "</div>"
  return page_header + page

@app.route('/sendRule', methods=['POST'])
def processRuleRequest():

  '''if request.method == 'POST': '''
  src = request.form['src']
  dst = request.form['dst']
  proto = request.form['proto']
  ruletype = request.form['type']

  #data = {}
  rule = []
  rule.append(src)
  rule.append(dst)
  rule.append(proto)
  rule.append(ruletype)
  #data['rule'] = rule
  jsonrule = json.dumps(rule)
  responsestatus = sendNewRule(jsonrule)
  if responsestatus == -1:
    return error()
  if responsestatus == 200:
    page = menu + '<h2 ' + css_h2 + '>Rule sent </h2>'
    page += '<div style="text-align:center">'
    #page += menu
    page += "<h3> Rule was applied successfully </h3>"
    page += "<p>Rule: "+ src +" -> "+ dst +" ("+ ruletype +"-way)</p>"
  else:
    page = menu + '<h2 ' + css_h2 + '>Error when applying rule </h2>'
    page += '<div style="text-align:center">'
    #page += menu
    page += "<h3> Rule was not applied. Response status: "+ str(responsestatus) +" </h3>"

  page += "<a href='/'style='color:black;'>Main page</a> "
  page += "</div>"
  return page_header + page


def sendNewRule(rule):
  httpRequest = rule
  try:
    conn = httplib.HTTPConnection("127.0.0.1",8080)
    conn.request("POST","/fw/rules/2960111173765568",httpRequest)
    response = conn.getresponse()
    return response.status
  except:
    return -1

@app.route('/vis')
def visualization():
  page = menu + '<h2 ' + css_h2 + '>Traffic visualization </h2>'
  #url_for('static', filename='js/libs/jquery-1.7.2.min.js')

  page += '<div style="text-align:center">'
  #page += menu
  page += "<h3> Info </h3>"
  page += """
  <div id="main" role="main">
      <div id="vis"></div>
    </div>
  """

  page += """

  <script>window.jQuery || document.write('<script src="""+ url_for('static', filename='js/libs/jquery-1.7.2.min.js') +"""><\/script>')</script>

  <script defer src="""+ url_for('static', filename='js/plugins.js') +"""></script>
  <script defer src="""+ url_for('static', filename='js/script.js') +"""></script>
  <script src="""+ url_for('static', filename='js/libs/coffee-script.js') +"""></script>
  <script src="""+ url_for('static', filename='js/libs/d3.v2.js') + """></script>
  <script src="""+ url_for('static', filename='js/Tooltip.js') +"""></script>
  <script type="""+ url_for('static', filename='text/coffeescript" src="coffee/vis.coffee') +"""></script>

  <script src="""+ url_for('static', filename='js/libs/modernizr-2.0.6.min.js') +"""></script>

  """



  page += "</div>"
  return page_header + page


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

def error():
  page = menu + '<h2 ' + css_h2 + '>Connection error </h2>'
  page += '<div style="text-align:center">'
  #page += menu
  page += "<h3> Connection not established </h3>"
  page += "<p>The application could not connect to the RYU controller... </p>"
  page += "<a href='/'style='color:black;'>Main page</a> "
  page += "</div>"
  return page_header + page



if __name__ == '__main__':
    app.debug = True
    app.run()
