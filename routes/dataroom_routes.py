from flask import Blueprint, request, jsonify
from models import db, DataRoom, Folder, File

dataroom_bp = Blueprint('dataroom', __name__)


@dataroom_bp.route('/datarooms', methods=['POST'])
def create_dataroom():
    """Create a new data room"""
    try:
        data = request.get_json()
        
        if not data or 'name' not in data:
            return jsonify({'error': 'Name is required'}), 400
        
        name = data['name'].strip()
        if not name:
            return jsonify({'error': 'Name cannot be empty'}), 400
        
        dataroom = DataRoom(name=name)
        db.session.add(dataroom)
        db.session.commit()
        
        return jsonify(dataroom.to_dict()), 201
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@dataroom_bp.route('/datarooms', methods=['GET'])
def get_datarooms():
    """Get all data rooms"""
    try:
        datarooms = DataRoom.query.all()
        return jsonify([dr.to_dict() for dr in datarooms]), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@dataroom_bp.route('/datarooms/<int:dataroom_id>', methods=['GET'])
def get_dataroom(dataroom_id):
    """Get a specific data room with its contents"""
    try:
        dataroom = DataRoom.query.get(dataroom_id)
        if not dataroom:
            return jsonify({'error': 'Data room not found'}), 404
        
        # Get root folders (folders with no parent)
        root_folders = Folder.query.filter_by(
            dataroom_id=dataroom_id, 
            parent_id=None
        ).all()
        
        # Get root files (files with no folder)
        root_files = File.query.filter_by(
            dataroom_id=dataroom_id,
            folder_id=None
        ).all()
        
        result = dataroom.to_dict()
        result['folders'] = [f.to_dict(include_children=True) for f in root_folders]
        result['files'] = [f.to_dict() for f in root_files]
        
        return jsonify(result), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@dataroom_bp.route('/datarooms/<int:dataroom_id>', methods=['DELETE'])
def delete_dataroom(dataroom_id):
    """Delete a data room and all its contents"""
    try:
        dataroom = DataRoom.query.get(dataroom_id)
        if not dataroom:
            return jsonify({'error': 'Data room not found'}), 404
        
        # Delete all associated files from disk
        files = File.query.filter_by(dataroom_id=dataroom_id).all()
        for file in files:
            file.delete_file()
        
        db.session.delete(dataroom)
        db.session.commit()
        
        return jsonify({'message': 'Data room deleted successfully'}), 200
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500
