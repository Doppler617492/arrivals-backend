from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from datetime import datetime

app = Flask(__name__)
CORS(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///arrivals.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class Arrival(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    supplier = db.Column(db.String(120), nullable=False)
    carrier = db.Column(db.String(120))
    plate = db.Column(db.String(32))
    type = db.Column(db.String(32), default="truck")
    eta = db.Column(db.String(32))
    status = db.Column(db.String(32), default="announced")
    note = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'supplier': self.supplier,
            'carrier': self.carrier,
            'plate': self.plate,
            'type': self.type,
            'eta': self.eta,
            'status': self.status,
            'note': self.note,
            'created_at': self.created_at.isoformat()
        }

@app.before_first_request
def create_tables():
    db.create_all()

@app.route('/api/arrivals', methods=['GET'])
def list_arrivals():
    return jsonify([a.to_dict() for a in Arrival.query.order_by(Arrival.created_at.desc()).all()])

@app.route('/api/arrivals', methods=['POST'])
def create_arrival():
    data = request.json or {}
    a = Arrival(
        supplier=data.get('supplier'),
        carrier=data.get('carrier'),
        plate=data.get('plate'),
        type=data.get('type', 'truck'),
        eta=data.get('eta'),
        status=data.get('status', 'announced'),
        note=data.get('note')
    )
    db.session.add(a)
    db.session.commit()
    return jsonify(a.to_dict()), 201

@app.route('/api/arrivals/<int:id>', methods=['PATCH'])
def update_arrival(id):
    a = Arrival.query.get_or_404(id)
    data = request.json or {}
    for field in ['supplier','carrier','plate','type','eta','status','note']:
        if field in data:
            setattr(a, field, data[field])
    db.session.commit()
    return jsonify(a.to_dict())

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)