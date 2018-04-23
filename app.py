from flask import Flask, jsonify, request, render_template, url_for, flash, redirect
import urllib2
import json
from urllib2 import Request, urlopen, URLError, HTTPError
import sys
import errno
import os

__author__ = "Patrick Blaas <patrick@kite4fun.nl>"
__version__ = "0.0.2"
__status__ = "Active"

if "USERNAME" not in os.environ:
    os.environ["USERNAME"] = "admin"
if "PASSWORD" not in os.environ:
    os.environ["PASSWORD"] = "password"
if "URL" not in os.environ:
    os.environ["URL"] = "https://anchore.YOURIPHERE.nip.io"


app = Flask(__name__)
app.secret_key = 'some_secret'

auth_handler = urllib2.HTTPBasicAuthHandler()
auth_handler.add_password(realm='Authentication required', uri=os.environ["URL"], user=os.environ["USERNAME"], passwd=os.environ["PASSWORD"])
opener = urllib2.build_opener(auth_handler)
urllib2.install_opener(opener)


def vulnCheck(id):
    vuln_result = urllib2.urlopen(os.environ["URL"] + '/images/by_id/' + id + '/vuln/os').read()
    python_data_vuln = json.loads(vuln_result)
    if len(python_data_vuln['vulnerabilities']) > 1:
        return "redbg"
    else:
        return ""


@app.route('/vulnarabilities/<string:id>')
def vulnarabilities(id):
    vuln_result = urllib2.urlopen(os.environ["URL"] + '/images/by_id/' + id + '/vuln/os').read()
    python_data_vuln = json.loads(vuln_result)
    return render_template('vulnarabilities.html', data=python_data_vuln)


@app.route('/delimage/<string:id>')
def delimage(id):
    uri = os.environ["URL"] + '/images/by_id/' + id + '?force=true'
    request = urllib2.Request(uri)
    request.get_method = lambda: 'DELETE'
    response = urllib2.urlopen(request).read()
    flash(u'Image successfully deleted.', 'success')
    return redirect(url_for('images'))


@app.route('/addimage', methods=['GET', 'POST'])
def addimage():
    # if request.method == 'POST':
    data = {}
    data['tag'] = request.form['tag']
    json_data = json.dumps(data)
    clen = len(json_data)
    req = urllib2.Request(os.environ["URL"] + '/images', json_data, {'Content-Type': 'application/json', 'Content-Length': clen})
    try:
        response = urllib2.urlopen(req).read()
    except HTTPError as e:
        print 'The server couldn\'t fulfill the request.'
        print 'Error code: ', e.code
        response = e.code
        flash(u'An error occured. Image not added. Reason: ' + str(e.code), 'danger')
    except URLError as e:
        print 'We failed to reach a server.'
        print 'Reason: ', e.reason
        repsonse = e.reason
        flash(u'An error occured. Image not added. Reason: ' + str(e.reason), 'danger')
    else:
        flash(u'Image successfully added.', 'success')
    return redirect(url_for('home'))


@app.route('/')
def home():
    try:
        service_result = urllib2.urlopen(os.environ["URL"] + '/v1/system/services').read()
        python_data_service = json.loads(service_result)
        return render_template('home.html', dataservice=python_data_service)
    except IOError as e:
        if e.errno == errno.EPIPE:
            return render_template('error.html')


@app.route('/images')
def images():
    try:
        image_result = urllib2.urlopen(os.environ["URL"] + '/v1/images').read()
        python_data_image = json.loads(image_result)

        global imageList
        imageList = []
        for object in python_data_image:
            id = object["image_detail"][0]["imageId"]
            if "analyzed" in object["analysis_status"]:
                object['color'] = vulnCheck(id)
            else:
                object['color'] = "orangebg"
            imageList.append(object)
        return render_template('images.html', dataimage=imageList)
    except IOError as e:
        if e.errno == errno.EPIPE:
            return render_template('error.html')


@app.route('/about')
def about():
    try:
        return render_template('about.html', version=__version__)
    except IOError as e:
        if e.errno == errno.EPIPE:
            return render_template('error.html')


if __name__ == '__main__':
    app.run(debug=False, threaded=True, host='0.0.0.0', port=5000)
