from flask import Flask, jsonify, request, render_template
import subprocess
import json
import csv
import config

__author__ = "Patrick Blaas <patrick@kite4fun.nl>"
__license__ = "GPL v3"
__version__ = "0.0.1"
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
    return render_template('sysstatus.html', status=returnStatus)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
