from flask import Flask, request
#from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.bootstrap import Bootstrap
from flask import render_template
import MySQLdb
import subprocess
import os
import tempfile
from dateutil.parser import parse as parse_date

OPENSSL_BIN = "/usr/bin/openssl"

app = Flask(__name__)
bs = Bootstrap(app)
app.debug = True

db = MySQLdb.connect(host="sql.mit.edu", # your host, usually localhost
                    user="xiaominw", # your username
                    passwd="ccp", # your password
                    db="xiaominw+858")
db.autocommit(True)

def parse_pem(pem):
    f, path = tempfile.mkstemp()
    os.write(f, pem)
    cert_txt = subprocess.check_output([OPENSSL_BIN, "x509", "-text", "-noout", 
                                    "-in", path])
    issuer_txt = subprocess.check_output([OPENSSL_BIN, "x509", "-issuer", "-noout", 
                                    "-in", path])
    try:
        issuer = issuer_txt.split("=", 1)[1].strip()
        issuer_name = dict(map(lambda x: x.split("=", 1), issuer.strip("/").split("/"))).get("CN")
    except: # YOLO
        issuer_name = ""

    date_txt = subprocess.check_output([OPENSSL_BIN, "x509", "-startdate", "-enddate", "-noout", 
                                    "-in", path]).strip().split("\n")
    dates = dict(map(lambda x: x.split("=", 1), date_txt))
    start_date = parse_date(dates["notBefore"])
    end_date = parse_date(dates["notAfter"])

    subject = subprocess.check_output([OPENSSL_BIN, "x509", "-subject", "-noout", 
                                    "-in", path]).split("=", 1)[1].strip()
    subject_name = dict(map(lambda x: x.split("=", 1), subject.strip("/").split("/"))).get("CN")

    serial = subprocess.check_output([OPENSSL_BIN, "x509", "-serial", "-noout", 
                                    "-in", path]).split("=", 1)[1].strip()

    fingerprint = subprocess.check_output([OPENSSL_BIN, "x509", "-fingerprint", "-noout", 
                                    "-in", path]).split("=", 1)[1].strip()

    return {
        # "output": cert_txt,
        "issuer_name": issuer_name,
        "start_date": start_date,
        "end_date": end_date,
        "subject_name": subject_name,
        "serial": serial,
        "fingerprint": fingerprint,
        "pem": pem
    }

@app.route('/')
def index():
    cur = db.cursor()
    cur.execute("select host, issuer_name, ct.fingerprint, end_date from hits ht inner join certificates ct on ht.fingerprint = ct.fingerprint order by timestamp desc limit 100;")
    items = [x for x in cur]
    return render_template('index.html', records=items)

@app.route('/submit', methods=["POST", ])
def submit():
    form = request.get_json()
    pem = form.get("certificate")  # PEM
    cert = parse_pem(pem)
    ipaddr = request.remote_addr
    host = form.get("host")

    cur = db.cursor()
    cert["start_date"] = int(cert["start_date"].strftime("%s"))
    cert["end_date"] = int(cert["end_date"].strftime("%s"))
    fields = ["subject_name", "issuer_name", "start_date", "end_date",
                "serial", "fingerprint", "pem"]
    values = map(cert.get, fields)
    sql = """INSERT IGNORE INTO certificates
                (""" + ",".join(fields) + """) VALUES
                (%s, %s, FROM_UNIXTIME(%s), FROM_UNIXTIME(%s), %s, %s, %s)"""
    cur.execute(sql, values)

    sql = """INSERT INTO hits (host, fingerprint, address) VALUES (%s, %s, %s)"""
    cur.execute(sql, [host, cert["fingerprint"], ipaddr])
    return ""

if __name__=='__main__':
    app.run()
