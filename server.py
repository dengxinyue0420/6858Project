from flask import Flask
#from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.bootstrap import Bootstrap
from flask import render_template
from sqlalchemy import create_engine, MetaData, Table
from sqlalchemy.orm import sessionmaker

app = Flask(__name__)
bs = Bootstrap(app)
#app.config['SQLALCHEMY_DATABASE_URI'] =
engine = create_engine('mysql://xiaominw:ccp@sql.mit.edu/xiaominw+858')
#app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
#db = SQLAlchemy(app)
metadata = MetaData(bind=engine)
Session = sessionmaker()
Session.configure(bind=engine)
s = Session()
record_table = Table('CertChain', metadata, autoload=True)
records = s.query(record_table).all()

@app.route('/')
def index():
  return render_template('index.html', records=records)

if __name__=='__main__':
  app.run()
