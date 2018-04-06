from flask import Flask, jsonify, request, render_template
import subprocess
import json
import csv
import config
import re

__author__ = "Patrick Blaas <patrick@kite4fun.nl>"
__license__ = "GPL v3"
__version__ = "0.0.2"
__status__ = "Active"

app = Flask(__name__, static_url_path='/static')


def anchoreCLIGet(command, action, id, type):
    if id:
        if type:
            output = subprocess.check_output(["anchore-cli", "--u", config.user, "--p", config.password, "--url", config.url, command, action, id, type]).splitlines()
        else:
            output = subprocess.check_output(["anchore-cli", "--u", config.user, "--p", config.password, "--url", config.url, command, action, id])
    else:
        output = subprocess.check_output(["anchore-cli", "--u", config.user, "--p", config.password, "--url", config.url, command, action]).splitlines()
    return output


def anchoreCLICheckVuln(id):
    output = subprocess.check_output(["anchore-cli", "--u", config.user, "--p", config.password, "--url", config.url, "image", "vuln", id, "os"])
    if len(str(output)) > 1:
        return "#DE3E4B"
    else:
        return "#40bc32"


@app.route('/', methods=['GET'])
def home():
    return render_template('home.html')


@app.route('/images', methods=['GET'])
def getImages():
    imagelist = anchoreCLIGet("image", "list", "", "")
    returnImages = []
    for i in imagelist:
        if "analyz" in i:
            returnImages.append(i)

    reader = csv.DictReader(returnImages, delimiter=' ', skipinitialspace=True, fieldnames=['name', 'id', 'status', 'color'])
    global imageList
    imageList = []
    for row in reader:
        if "analyzing" not in row['status']:
            row['color'] = anchoreCLICheckVuln(row['id'])
        else:
            row['color'] = "orange"
        imageList.append(row)
    return render_template('images.html', images=imageList)


@app.route('/imagescan/<string:id>/')
def imagescan(id):
    result = anchoreCLIGet("image", "vuln", id, "os")
    reader = csv.DictReader(result, delimiter=' ', skipinitialspace=True, fieldnames=['Id', 'Package', 'Severity', 'Fix', 'Url'])

    global vulnList
    vulnList = []
    for row in reader:
        vulnList.append(row)
    if len(vulnList) > 0:
        vulnList.pop(0)
    return render_template('imagescan.html', results=vulnList)


@app.route('/delimage/<string:id>/')
def delimage(id):
    result = anchoreCLIGet("image", "del", id, "--force")
    return render_template('delimage.html', results=result)


@app.route('/sysstatus')
def sysstatus():
    syslist = anchoreCLIGet("system", "status", "", "")
    returnStatus = []
    for i in syslist:
            returnStatus.append(i)

    global matrix
    w, h = 2, 6
    matrix = [[0 for x in range(w)] for y in range(h)]

    # matrix[0] = analyzer
    # matrix[1] = webhook
    # matrix[2] = catalog
    # matrix[3] = apiext
    # matrix[4] = simplequeue
    # matrix[5] = policyengine

    r = re.compile(".*analyzer.*up")
    match = filter(r.match, returnStatus)
    matrix[0][0] = len(match)
    r = re.compile(".*analyzer.*down")
    match = filter(r.match, returnStatus)
    matrix[0][1] = len(match)

    r = re.compile(".*webhook.*up")
    match = filter(r.match, returnStatus)
    matrix[1][0] = len(match)
    r = re.compile(".*webhook.*down")
    match = filter(r.match, returnStatus)
    matrix[1][1] = len(match)

    r = re.compile(".*catalog.*up")
    match = filter(r.match, returnStatus)
    matrix[2][0] = len(match)
    r = re.compile(".*catalog.*down")
    match = filter(r.match, returnStatus)
    matrix[2][1] = len(match)

    r = re.compile(".*apiext.*up")
    match = filter(r.match, returnStatus)
    matrix[3][0] = len(match)
    r = re.compile(".*apiext.*down")
    match = filter(r.match, returnStatus)
    matrix[3][1] = len(match)

    r = re.compile(".*simplequeue.*up")
    match = filter(r.match, returnStatus)
    matrix[4][0] = len(match)
    r = re.compile(".*simplequeue.*down")
    match = filter(r.match, returnStatus)
    matrix[4][1] = len(match)

    r = re.compile(".*policy_engine.*up")
    match = filter(r.match, returnStatus)
    matrix[5][0] = len(match)
    r = re.compile(".*policy_engine.*down")
    match = filter(r.match, returnStatus)
    matrix[5][1] = len(match)

    return render_template('sysstatus.html', status=returnStatus, matrix=matrix)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
