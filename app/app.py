from flask import Flask, jsonify, request, render_template, url_for, flash, redirect
import urllib2
import json
from urllib2 import Request, urlopen, URLError, HTTPError
import sys
import errno
import os

# import the flask extension
from flask_caching import Cache

__author__ = "Patrick Blaas <patrick@kite4fun.nl>"
__version__ = "0.0.6"
__status__ = "Active"

if "USERNAME" not in os.environ:
    os.environ["USERNAME"] = "admin"
if "PASSWORD" not in os.environ:
    os.environ["PASSWORD"] = "password"
if "URL" not in os.environ:
    os.environ["URL"] = "https://anchore.YOURIPHERE.nip.io"


app = Flask(__name__)
app.secret_key = 'some_secret'
cache = Cache(app, config={'CACHE_TYPE': 'simple'})

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


@app.route('/vulnerabilities/<string:id>')
def vulnerabilities(id):
    vuln_result = urllib2.urlopen(os.environ["URL"] + '/images/by_id/' + id + '/vuln/os').read()
    python_data_vuln = json.loads(vuln_result)
    image_result = urllib2.urlopen(os.environ["URL"] + '/images/by_id/' + id).read()
    python_data_image = json.loads(image_result)
    return render_template('vulnerabilities.html', data=python_data_vuln, imagedata=python_data_image[0]["image_detail"])


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


@app.route('/delanalyzer/<string:hostid>', methods=['GET', 'POST'])
def delanalyzer(hostid):
    uri = os.environ["URL"] + '/system/services/analyzer/' + hostid
    request = urllib2.Request(uri)
    request.get_method = lambda: 'DELETE'
    try:
        response = urllib2.urlopen(request).read()
    except HTTPError as e:
        print 'The server couldn\'t fulfill the request.'
        print 'Error code: ', e.code
        response = e.code
        flash(u'An error occured. Analyzer not removed. Reason: ' + str(e.code), 'danger')
    except URLError as e:
        print 'We failed to reach a server.'
        print 'Reason: ', e.reason
        repsonse = e.reason
        flash(u'An error occured. Analyzer not removed. Reason: ' + str(e.reason), 'danger')
    else:
        flash(u'Analyzer service removed.', 'success')
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
# @cache.cached(timeout=50)
def images():
    try:
        image_result = urllib2.urlopen(os.environ["URL"] + '/v1/images').read()
        python_data_image = json.loads(image_result)

        global imageList
        imageList = []
        imageCount = 0
        for object in python_data_image:
            id = object["image_detail"][0]["imageId"]
            if "analyzed" in object["analysis_status"]:
                if imageCount < 10:
                    object['color'] = vulnCheck(id)
                    # object['color'] = ""
                else:
                    object['color'] = "purplebg"
            else:
                object['color'] = "orangebg"
            imageList.append(object)
            imageCount += 1
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
