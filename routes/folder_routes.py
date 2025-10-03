from flask import Blueprint, request, jsonify
from models import db, Folder, File, DataRoom

folder_bp = Blueprint('folder', __name__)


@folder_bp.route('/folders', methods=['POST'])
def create_folder():
    """Create a new folder"""
    try:
        data = request.get_json()
        
        if not data or 'name' not in data or 'dataroom_id' not in data:
            return jsonify({'error': 'Name and dataroom_id are required'}), 400
        
        name = data['name'].strip()
        if not name:
            return jsonify({'error': 'Name cannot be empty'}), 400
        
        dataroom_id = data['dataroom_id']
        parent_id = data.get('parent_id')
        
        # Verify dataroom exists
        dataroom = DataRoom.query.get(dataroom_id)
        if not dataroom:
            return jsonify({'error': 'Data room not found'}), 404
        
        # Verify parent folder exists if provided
        if parent_id:
            parent_folder = Folder.query.get(parent_id)
            if not parent_folder:
                return jsonify({'error': 'Parent folder not found'}), 404
            if parent_folder.dataroom_id != dataroom_id:
                return jsonify({'error': 'Parent folder must be in the same data room'}), 400
        
        # Check for duplicate names in the same location
        existing = Folder.query.filter_by(
            name=name,
            parent_id=parent_id,
            dataroom_id=dataroom_id
        ).first()
        
        if existing:
            # Auto-rename with counter
            counter = 1
            new_name = name
            while existing:
                new_name = f"{name} ({counter})"
                existing = Folder.query.filter_by(
                    name=new_name,
                    parent_id=parent_id,
                    dataroom_id=dataroom_id
                ).first()
                counter += 1
            name = new_name
        
        folder = Folder(
            name=name,
            parent_id=parent_id,
            dataroom_id=dataroom_id
        )
        
        db.session.add(folder)
        db.session.commit()
        
        return jsonify(folder.to_dict()), 201
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@folder_bp.route('/folders/<int:folder_id>', methods=['GET'])
def get_folder(folder_id):
    """Get a folder and its contents"""
    try:
        folder = Folder.query.get(folder_id)
        if not folder:
            return jsonify({'error': 'Folder not found'}), 404
        
        return jsonify(folder.to_dict(include_children=True)), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@folder_bp.route('/folders/<int:folder_id>', methods=['PUT'])
def update_folder(folder_id):
    """Update folder name"""
    try:
        folder = Folder.query.get(folder_id)
        if not folder:
            return jsonify({'error': 'Folder not found'}), 404
        
        data = request.get_json()
        if not data or 'name' not in data:
            return jsonify({'error': 'Name is required'}), 400
        
        new_name = data['name'].strip()
        if not new_name:
            return jsonify({'error': 'Name cannot be empty'}), 400
        
        # Check for duplicate names in the same location
        existing = Folder.query.filter_by(
            name=new_name,
            parent_id=folder.parent_id,
            dataroom_id=folder.dataroom_id
        ).filter(Folder.id != folder_id).first()
        
        if existing:
            return jsonify({'error': 'A folder with this name already exists in this location'}), 400
        
        folder.name = new_name
        db.session.commit()
        
        return jsonify(folder.to_dict()), 200
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@folder_bp.route('/folders/<int:folder_id>', methods=['DELETE'])
def delete_folder(folder_id):
    """Delete a folder and all its contents (cascade)"""
    try:
        folder = Folder.query.get(folder_id)
        if not folder:
            return jsonify({'error': 'Folder not found'}), 404
        
        # Recursively delete all files in this folder and subfolders
        def delete_folder_files(folder_obj):
            # Delete files in current folder
            for file in folder_obj.files:
                file.delete_file()
            
            # Recursively delete files in subfolders
            for child in folder_obj.children:
                delete_folder_files(child)
        
        delete_folder_files(folder)
        
        # Delete the folder (cascade will handle children)
        db.session.delete(folder)
        db.session.commit()
        
        return jsonify({'message': 'Folder deleted successfully'}), 200
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500
