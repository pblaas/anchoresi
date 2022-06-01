from flask import Flask, jsonify, request, render_template, url_for, flash, redirect
import urllib.request
import json
from urllib.request import Request, urlopen, URLError, HTTPError
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

auth_handler = urllib.request.HTTPBasicAuthHandler()
auth_handler.add_password(realm='Authentication required', uri=os.environ["URL"], user=os.environ["USERNAME"], passwd=os.environ["PASSWORD"])
opener = urllib.request.build_opener(auth_handler)
urllib.request.install_opener(opener)


def vulnCheck(id):
    vuln_result = urllib.request.urlopen(os.environ["URL"] + '/images/by_id/' + id + '/vuln/os').read()
    python_data_vuln = json.loads(vuln_result)
    if len(python_data_vuln['vulnerabilities']) > 1:
        return "redbg"
    else:
        return ""


@app.route('/vulnerabilities/<string:id>')
def vulnerabilities(id):
    vuln_result = urllib.request.urlopen(os.environ["URL"] + '/images/by_id/' + id + '/vuln/os').read()
    python_data_vuln = json.loads(vuln_result)
    image_result = urllib.request.urlopen(os.environ["URL"] + '/images/by_id/' + id).read()
    python_data_image = json.loads(image_result)
    return render_template('vulnerabilities.html', data=python_data_vuln, imagedata=python_data_image[0]["image_detail"])


@app.route('/delimage/<string:id>')
def delimage(id):
    uri = os.environ["URL"] + '/images/by_id/' + id + '?force=true'
    request = urllib.request.Request(uri)
    request.get_method = lambda: 'DELETE'
    response = urllib.request.urlopen(request).read()
    flash(u'Image successfully deleted.', 'success')
    return redirect(url_for('images'))


@app.route('/addimage', methods=['GET', 'POST'])
def addimage():
    # if request.method == 'POST':
    data = {}
    data['tag'] = request.form['tag']
    json_data = json.dumps(data)
    clen = len(json_data)
    print("data: ", json_data)
    req = urllib.request.Request(os.environ["URL"] + '/images', bytes(json_data, 'UTF-8'), {'Content-Type': 'application/json', 'Content-Length': clen})
    try:
        response = urllib.request.urlopen(req).read()
    except HTTPError as e:
        print('The server couldn\'t fulfill the request.')
        print('Error code: ', e.code)
        response = e.code
        flash(u'An error occured. Image not added. Reason: ' + str(e.code), 'danger')
    except URLError as e:
        print ('We failed to reach a server.')
        print ('Reason: ', e.reason)
        repsonse = e.reason
        flash(u'An error occured. Image not added. Reason: ' + str(e.reason), 'danger')
    else:
        flash(u'Image successfully added.', 'success')
    return redirect(url_for('home'))


@app.route('/delanalyzer/<string:hostid>', methods=['GET', 'POST'])
def delanalyzer(hostid):
    uri = os.environ["URL"] + '/system/services/analyzer/' + hostid
    request = urllib.request.Request(uri)
    request.get_method = lambda: 'DELETE'
    try:
        response = urllib.request.urlopen(request).read()
    except HTTPError as e:
        print('The server couldn\'t fulfill the request.')
        print('Error code: ', e.code)
        response = e.code
        flash(u'An error occured. Analyzer not removed. Reason: ' + str(e.code), 'danger')
    except URLError as e:
        print('We failed to reach a server.')
        print('Reason: ', e.reason)
        repsonse = e.reason
        flash(u'An error occured. Analyzer not removed. Reason: ' + str(e.reason), 'danger')
    else:
        flash(u'Analyzer service removed.', 'success')
    return redirect(url_for('home'))


@app.route('/')
def home():
    try:
        service_result = urllib.request.urlopen(os.environ["URL"] + '/v1/system/services').read()
        python_data_service = json.loads(service_result)
        return render_template('home.html', dataservice=python_data_service)
    except IOError as e:
        if e.errno == errno.EPIPE:
            return render_template('error.html')


@app.route('/images')
# @cache.cached(timeout=50)
def images():
    try:
        image_result = urllib.request.urlopen(os.environ["URL"] + '/v1/images').read()
        python_data_image = json.loads(image_result)

        imageList = []
        imageCount = 0
        for image in python_data_image:
            id = image["image_detail"][0]["imageId"]
            if "analyzed" in image["analysis_status"]:
                if imageCount < 10:
                    image['color'] = vulnCheck(id)
                    #image['color'] = "purplebg"
                else:
                    image['color'] = "purplebg"
            else:
                image['color'] = "orangebg"
            imageList.append(image)
            imageCount += 1
        return render_template('images.html', dataimage=imageList)
    except Exception as e:
        print('Error: ', e)
        return render_template('error.html', err=e)


@app.route('/about')
def about():
    try:
        return render_template('about.html', version=__version__)
    except IOError as e:
        if e.errno == errno.EPIPE:
            return render_template('error.html')

if __name__ == '__main__':
    app.run(debug=False, threaded=True, host='0.0.0.0', port=5000)
