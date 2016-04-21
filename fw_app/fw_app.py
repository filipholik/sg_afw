# Web application for Adaptive Firewall for Smart Grid Security (3.5.0)

from flask import Flask, url_for
from flask import request
import httplib #for Python 2.x
import json
from pprint import pprint

from flask import make_response

switchdpidsdict = {'Switch 1': '2960111173765568',
                   'Switch 2': '2991443865190400'}
urlRules = "/fw/rules/"
urlTrafficAllowed = "/fw/traffic_allowed/"
urlTrafficDenied = "/fw/traffic_denied/"
urlNewRule = "/fw/rules/"
urlDelRule = "/fw/delrule/"
urlTopology = "/fw/topology"
urlTraffic = "/fw/traffic"

app = Flask(__name__)
page_header = '<body><h1 style="text-align:center;">SG Firewall application</h1>\n'
css_h2 = 'style="background-color:11557C; color:white; text-align:center; "'
menu = """
<h3 style="background-color:98AFC7; text-align:center;">
  <a href='/' style='color:black; '>Main page</a>
  <a href='/rules' style='color:black; margin-left:10px'>Flow tables</a>
  <a href='/newrule' style='color:black; margin-left:10px'>Add a new rule</a>
  <a href='/trafficAllowed' style='color:black; margin-left:10px'>Traffic monitoring</a>
  <a href='/vis' style='color:black; margin-left:10px'>Traffic visualization</a>
</h3>

"""
page_footer = "</body>"

#For reading data
def getDataFromConnectionGET(url):
  try:
    httpRequest = ""
    conn = httplib.HTTPConnection("127.0.0.1",8080)
    conn.request("GET",url,httpRequest)
    response = conn.getresponse()
    if response.status == 200:
      data = json.load(response)
      conn.close()
      return data
    else:
      conn.close()
      return -1
  except:
    return -1

#For inserting new rules
def getResponseStatusPOST(url, data):
  try:
    #httpRequest = ""
    conn = httplib.HTTPConnection("127.0.0.1",8080)
    conn.request("POST",url,data)
    response = conn.getresponse()
    return response.status
    #conn.close()
  except:
    return -1

@app.route('/')
def index():
  page = menu + '<h2 ' + css_h2 + '>Main page </h2>'
  #url_for('static', filename='js/libs/jquery-1.7.2.min.js')


  page += '<div style="text-align:center">'
  page += "<h3> Info </h3>"
  page += "<p>Application of SDN in Smart Grid substation.  </p>"
  page += "<h3> Topology </h3>"
  page += '<div id="chart"></div>'

  data = getDataFromConnectionGET(urlTopology)
  if data == -1:
    page += "No connection to the controller app... <br> Could not get topology file... "
  else:
    page += """
<style>

.link {
  stroke: #aaa;
  }

.node text {
stroke:#333;
cursos:pointer;
  }

.node circle{
stroke:#fff;
stroke-width:3px;
fill:#555;
  }

</style>
  <script src="//d3js.org/d3.v3.min.js"></script>

  <script>

var width = 960,
    height = 600

var svg = d3.select("#chart").append("svg")
    .attr("width", width)
    .attr("height", height);

var force = d3.layout.force()
    .gravity(.05)
    .distance(100)
    .charge(-1000)
    .size([width, height]);

d3.json("http://127.0.0.1:5000/topojson", function(json) {
  force
      .nodes(json.nodes)
      .links(json.links)
      .start();

  var link = svg.selectAll(".link")
      .data(json.links)
    .enter().append("line")
      .attr("class", "link")
    .style("stroke-width", function(d) { return Math.sqrt(d.weight); });

  var node = svg.selectAll(".node")
      .data(json.nodes)
    .enter().append("g")
      .attr("class", "node")
      .call(force.drag);

  node.append("circle")
      .attr("r","10");

  node.append("text")
      .attr("dx", 12)
      .attr("dy", ".35em")
      .text(function(d) { return d.name });

  force.on("tick", function() {
    link.attr("x1", function(d) { return d.source.x; })
        .attr("y1", function(d) { return d.source.y; })
        .attr("x2", function(d) { return d.target.x; })
        .attr("y2", function(d) { return d.target.y; });

    node.attr("transform", function(d) { return "translate(" + d.x + "," + d.y + ")"; });
  });
});



</script>


    """

  page += "</div>"
  return page_header + page + page_footer

@app.route('/rules')
def rules():
  page = menu + '<h2 ' + css_h2 + '>Flow tables </h2>'
  page += '<div style="text-align:center">'
  #httpRequest = ""

  for switchname, dpid in switchdpidsdict.iteritems():
    data = getDataFromConnectionGET(urlRules+dpid)
    page += "<h3>" + switchname + "</h3>"
    if data == -1 or data == 0:
      page += "Cannot connect to the device or get data from the device... "
    else:
      page += printTable(data)

  page += "</div>"
  return page_header + page + page_footer

@app.route('/trafficAllowed')
def trafficAllowed():
  page = menu + "<h2 "  + css_h2 + """
  ><a href='/trafficAllowed' style='color:white;'>Allowed traffic</a>
  <a href='/trafficDenied' style='color:white; margin-left:20px'>Denied traffic</a>
  </h2> """
  page += '<div style="text-align:center">'
  page += "<h3 " + css_h2 + "> Allowed traffic </h3>"

  for switchname, dpid in switchdpidsdict.iteritems():
    data = getDataFromConnectionGET(urlTrafficAllowed+dpid)
    page += "<h3>" + switchname + "</h3>"
    if data == -1:
      page += "Cannot connect to the device or get data from the device... "
    else:
      page += printTrafficTable(data, "DENY")

  page += "<p>Note: default traffic to controller is not displayed  </p>"
  page += "</div>"
  return page_header + page + page_footer

@app.route('/trafficDenied')
def trafficDenied():
  page = menu + "<h2 "  + css_h2 + """
  ><a href='/trafficAllowed' style='color:white;'>Allowed traffic</a>
  <a href='/trafficDenied' style='color:white; margin-left:20px'>Denied traffic</a>
  </h2> """
  page += '<div style="text-align:center">'
  page += "<h3 " + css_h2 + "> Denied traffic </h3>"


  for switchname, dpid in switchdpidsdict.iteritems():
    data = getDataFromConnectionGET(urlTrafficDenied+dpid)
    page += "<h3>" + switchname + "</h3>"
    if data == -1:
      page += "Cannot connect to the device or get data from the device... "
    else:
      page += printTrafficTable(data, "ALLOW")

  page += "</div>"
  return page_header + page + page_footer

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

def printTrafficTable(data, action):
    #if isinstance(data, (list)):
  if data == 0:
    return "No traffic found"
    return "Datapath ID entry not found... "


  page = """<table border="1" style="width:80%; margin-left:10%">\n
  <tr> <th>Number </th> <th> Source </th> <th> Destination </th>
  <th> Eth Proto </th> <th> PPS </th><th> Packets </th><th> Priority</th> <th> Action </th>  </tr> \n"""
  if len(data) == 0:
    page += "<tr> <td colspan='8' style='text-align:center; '>No traffic</td></tr>"
  num = 1
  action_page = '/newrule'
  for rule in data:
    if 'priority' in rule and rule['priority'] == 0:
      continue #Default rules pointing to different tables
    color = "white"
    if num % 2 == 0:
      color = "#E0FFFF"
    page += '<tr style="text-align:center; background-color: ' + color +'"><td>' + str(num) + '</td>'
    action_link = "?"
    if 'eth_src' in rule:
      page += "<td>" + rule['eth_src'] + "</td>"
      action_link += "src=" + rule['eth_src'] + "&"
    else:
      page += "<td>Any source</td>"
    if 'eth_dst' in rule:
      page += "<td>" + rule['eth_dst'] + "</td>"
      action_link += "dst=" + rule['eth_dst'] + "&"
    else:
      page += "<td>Any destination</td>"
    if 'eth_type' in rule:
      page += "<td>" + decodeEthProto(rule['eth_type']) + ": " + str(rule['eth_type']) + "</td>"
      action_link += "type=" + str(rule['eth_type']) + "&"
    else:
      page += "<td>Any protocol</td>"
    if 'packet_count_history' in rule and len(rule['packet_count_history']) >= 2:
      history = rule['packet_count_history']
      pps2 = history.pop()
      pps1 = history.pop()
      page += "<td>" + str(pps2-pps1) + "</td>"
      page += "<td>" + str(pps2) + "</td>"
    else:
      page += "<td>?</td>"
      page += "<td>?</td>"
    if 'priority' in rule:
      page += "<td>" + str(rule['priority']) + "</td>"
      if action == 'DENY':
        action_link += "prio=" + str(rule['priority']) #Priority must match deny rules!
      else:
        action_link += "prio=" + str(11) #Priority must be higher than deny rules!

    else:
      page += "<td>?</td>"
    if action == 'DENY':
      action_page = '/delRule'
    page += "<td><a href='"+ action_page +action_link+"'style='color:black;'>"+ action +"</a>  </td></tr>"
    num += 1

  page += "</table>"
  return page

'''
def printDeniedTraffic(data):
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
'''

def decodeEthProto(eth_proto):
  #return "?"
  #eth_proto = int(eth_proto, 16)
  if int(eth_proto) == 2048:
    return "IPv4"
  if int(eth_proto) == 2054:
    return "ARP"
  if int(eth_proto) == 35020:
    return "LLDP"
  if int(eth_proto) == 35000:
    return "GOOSE"
  if int(eth_proto) == 35225:
    return "BDDP"
  return "unknown"

@app.route('/newrule')
def newRule():
  page = menu + '<h2 ' + css_h2 + '>Add a new rule </h2>'
  page += '<div style="text-align:center">'
  #page += menu
  page += "<h3> Insert a new FW rule into the network </h3>"
  page += "<p>Field marked with * are required.  </p>"

  src = request.args.get('src', 'fa:16:3e:30:cc:04')
  dst = request.args.get('dst', 'fa:16:3e:5e:c6:ef')
  proto = request.args.get('type', '2048')
  prio = request.args.get('prio', '11')

  page += """
  <form action="/sendRule" method="post" accept-charset="UTF-8"
  enctype="application/json" autocomplete="off" novalidate
  style="width:80%; margin-left:10%; " >
  <fieldset>
    <legend>Rule:</legend>
    Source MAC:
    <input type="text" name="src" value=""" + src + """><br>
    Destination MAC:
    <input type="text" name="dst" value=""" + dst + """><br>
    Ethernet type:
    <input type="text" name="proto" value="""+ proto +"""><br>
    Priority:
    <input type="text" name="prio" value="""+ prio +"""><br>

    <br>
    Rule type:
    <select name="type">
      <option value="2" selected>Two-ways</option>
      <option value="1">One-way</option>
    </select>
    <br>
    <input type="hidden" name="insert_delete" value="insert">
    <input type="submit" value="Insert rule">
  </fieldset>
</form>

  """

  #page += "<a href='/'style='color:black;'>Main page</a> "
  page += "</div>"
  return page_header + page + page_footer

@app.route('/delRule')
def delRule():
  page = menu + '<h2 ' + css_h2 + '>Delete the existing rule </h2>'
  page += '<div style="text-align:center">'
  #page += menu
  page += "<h3> Delete the existing FW rule in the network </h3>"
  page += "<p>Field marked with * are required. Empty field means ANY. </p>"

  src = request.args.get('src', '')
  dst = request.args.get('dst', '')
  proto = request.args.get('type', '')
  prio = request.args.get('prio', '')

  page += """
  <form action="/sendRule" method="post" accept-charset="UTF-8"
  enctype="application/json" autocomplete="off" novalidate
  style="width:80%; margin-left:10%; " >
  <fieldset>
    <legend>Rule:</legend>
    Source MAC:
    <input type="text" name="src" value=""" + src + """><br>
    Destination MAC:
    <input type="text" name="dst" value=""" + dst + """><br>
    Ethernet type:
    <input type="text" name="proto" value="""+ proto +"""><br>
    Priority:
    <input type="text" name="prio" value="""+ prio +"""><br>

    <br>
    Rule type:
    <select name="type">
      <option value="2" selected>Two-ways</option>
      <option value="1">One-way</option>
    </select>
    <br>
    <input type="hidden" name="insert_delete" value="delete">
    <input type="submit" value="Delete rule">
  </fieldset>
</form>

  """

  #page += "<a href='/'style='color:black;'>Main page</a> "
  page += "</div>"
  return page_header + page + page_footer


@app.route('/sendRule', methods=['POST'])
def processRuleRequest():

  '''if request.method == 'POST': '''
  src = request.form['src']
  dst = request.form['dst']
  proto = int(request.form['proto'])
  prio = request.form['prio']
  ruletype = request.form['type']
  insert_delete = request.form['insert_delete']
  #print hex(proto)

  #data = {}
  rule = {}
  rule['eth_src'] = src
  rule['eth_dst'] = dst
  rule['eth_type'] = hex(proto)
  rule['priority'] = prio
  rule['ruletype'] = ruletype

  '''rule.append(src)
  rule.append(dst)
  rule.append(proto)
  rule.append(ruletype)'''

  jsonrule = json.dumps(rule)
  responsestatus = sendNewRule(jsonrule, insert_delete)
  if responsestatus == -1:
    return error()
  if responsestatus == 200:
    if insert_delete == 'insert':
      page = menu + '<h2 ' + css_h2 + '>Rule sent </h2>'
    else:
      page = menu + '<h2 ' + css_h2 + '>Rule deleted </h2>'
    page += '<div style="text-align:center">'
    #page += menu
    if insert_delete == 'insert':
      page += "<h3> Rule was applied successfully </h3>"
    else:
      page += "<h3> Rule was deleted successfully </h3>"
    page += "<p>Rule: "+ src +" -> "+ dst +" ("+ ruletype +"-way)</p>"
  else:
    page = menu + '<h2 ' + css_h2 + '>Error when applying rule </h2>'
    page += '<div style="text-align:center">'
    #page += menu
    page += "<h3> Rule was not applied. Response status: "+ str(responsestatus) +" </h3>"

  page += "<a href='/trafficAllowed'style='color:black;'>Allowed traffic</a> "
  page += "</div>"
  return page_header + page + page_footer


def sendNewRule(rule, insert_delete):
  status = 0
  if insert_delete == 'insert':
    url = urlRules
  else:
    url = urlDelRule
  for switchname, dpid in switchdpidsdict.iteritems():
    responseStatus = getResponseStatusPOST(url+dpid, rule)
    if responseStatus == -1:
      return -1
    status = responseStatus

  return status

  '''httpRequest = rule

  try:
    conn = httplib.HTTPConnection("127.0.0.1",8080)
    conn.request("POST","/fw/rules/2960111173765568",httpRequest)
    response = conn.getresponse()
    return response.status
  except:
    return -1'''

@app.route('/vis')
def visualization():
  page = menu + '<h2 ' + css_h2 + '>Traffic visualization </h2>'
  #url_for('static', filename='js/libs/jquery-1.7.2.min.js')
  data = getDataFromConnectionGET(urlTopology)

  page += '<div style="text-align:center">'
  #page += "<h3>  </h3>"

  if data == -1:
      page += "No connection to the controller app... <br> Could not get the traffic visualization data... "
  else:
    page += '<p>Following figure shows allowed traffic in the substation network. </p>'
    page += '<div id="vis"></div>'




    page += """
  <style>

.node {
  cursor: pointer;
  }

.node circle {
  fill: #fff;
  stroke: steelblue;
  stroke-width: 1.5px;
  }

.node text {
  font: 10px sans-serif;
  }

.link {
  fill: none;
  stroke: #ccc;
  stroke-width: 1.5px;
  }

</style>

<script src="//d3js.org/d3.v3.min.js"></script>

<script>

var margin = {top: 20, right: 120, bottom: 20, left: 120},
    width = 960 - margin.right - margin.left,
    height = 500 - margin.top - margin.bottom;

var i = 0,
    duration = 750,
    root;

var tree = d3.layout.tree()
    .size([height, width]);

var diagonal = d3.svg.diagonal()
    .projection(function(d) { return [d.y, d.x]; });

var svg = d3.select("#vis").append("svg")
    .attr("width", width + margin.right + margin.left)
    .attr("height", height + margin.top + margin.bottom)
  .append("g")
    .attr("transform", "translate(" + margin.left + "," + margin.top + ")");

d3.json("http://127.0.0.1:5000/trafficjson", function(error, flare) {
  if (error) throw error;

  root = flare;
  root.x0 = height / 2;
  root.y0 = 0;

  function collapse(d) {
    if (d.children) {
      d._children = d.children;
      d._children.forEach(collapse);
      d.children = null;
    }
  }

  root.children.forEach(collapse);
  update(root);
});

d3.select(self.frameElement).style("height", "800px");

function update(source) {

  // Compute the new tree layout.
  var nodes = tree.nodes(root).reverse(),
      links = tree.links(nodes);

  // Normalize for fixed-depth.
  nodes.forEach(function(d) { d.y = d.depth * 180; });

  // Update the nodes
  var node = svg.selectAll("g.node")
      .data(nodes, function(d) { return d.id || (d.id = ++i); });

  // Enter any new nodes at the parent's previous position.
  var nodeEnter = node.enter().append("g")
      .attr("class", "node")
      .attr("transform", function(d) { return "translate(" + source.y0 + "," + source.x0 + ")"; })
      .on("click", click);

  nodeEnter.append("circle")
      .attr("r", 1e-6)
      .style("fill", function(d) { return d._children ? "lightsteelblue" : "#fff"; });

  nodeEnter.append("text")
      .attr("x", function(d) { return d.children || d._children ? -10 : 10; })
      .attr("dy", ".35em")
      .attr("text-anchor", function(d) { return d.children || d._children ? "end" : "start"; })
      .text(function(d) { return d.name; })
      .style("fill-opacity", 1e-6);

  // Transition nodes to their new position.
  var nodeUpdate = node.transition()
      .duration(duration)
      .attr("transform", function(d) { return "translate(" + d.y + "," + d.x + ")"; });

  nodeUpdate.select("circle")
      .attr("r", 4.5)
      .style("fill", function(d) { return d._children ? "lightsteelblue" : "#fff"; });

  nodeUpdate.select("text")
      .style("fill-opacity", 1);

  // Transition exiting nodes to the parent's new position.
  var nodeExit = node.exit().transition()
      .duration(duration)
      .attr("transform", function(d) { return "translate(" + source.y + "," + source.x + ")"; })
      .remove();

  nodeExit.select("circle")
      .attr("r", 1e-6);

  nodeExit.select("text")
      .style("fill-opacity", 1e-6);

  // Update the links
  var link = svg.selectAll("path.link")
      .data(links, function(d) { return d.target.id; });

  // Enter any new links at the parent's previous position.
  link.enter().insert("path", "g")
      .attr("class", "link")
      .attr("d", function(d) {
        var o = {x: source.x0, y: source.y0};
        return diagonal({source: o, target: o});
      });

  // Transition links to their new position.
  link.transition()
      .duration(duration)
      .attr("d", diagonal);

  // Transition exiting nodes to the parent's new position.
  link.exit().transition()
      .duration(duration)
      .attr("d", function(d) {
        var o = {x: source.x, y: source.y};
        return diagonal({source: o, target: o});
      })
      .remove();

  // Stash the old positions for transition.
  nodes.forEach(function(d) {
    d.x0 = d.x;
    d.y0 = d.y;
  });
}

// Toggle children on click.
function click(d) {
  if (d.children) {
    d._children = d.children;
    d.children = null;
  } else {
    d.children = d._children;
    d._children = null;
  }
  update(d);
}

</script>


    """


  page += "</div>"
  return page_header + page + page_footer

@app.route('/topojson')
def topologyjson():
  topology = getDataFromConnectionGET(urlTopology)
  return json.dumps(topology)


@app.route('/trafficjson')
def trafficJson():
  traffic = getDataFromConnectionGET(urlTraffic)
  return json.dumps(traffic)


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
  return page_header + page + page_footer



if __name__ == '__main__':
    app.debug = True
    app.run()
