# backend/routes/file_routes.py - Enhanced with Token Support
from flask import Blueprint, request, jsonify, send_file, make_response
from werkzeug.utils import secure_filename
from models import db, File, Folder, DataRoom, User
from auth import token_required, decode_token
import os
import uuid

file_bp = Blueprint('file', __name__)

ALLOWED_EXTENSIONS = {'pdf'}
UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', 'uploads')


def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def get_unique_filename(original_filename):
    """Generate a unique filename to avoid conflicts"""
    ext = original_filename.rsplit('.', 1)[1].lower() if '.' in original_filename else ''
    unique_name = f"{uuid.uuid4().hex}.{ext}"
    return unique_name


def verify_user_from_token(token_string):
    """Verify user from token string (for query parameter auth)"""
    if not token_string:
        return None

    payload = decode_token(token_string)
    if not payload or payload.get('type') != 'access':
        return None

    user = User.query.get(payload['user_id'])
    if not user or not user.is_active:
        return None

    return user


@file_bp.route('/files/upload', methods=['POST'])
@token_required
def upload_file():
    """Upload a file to a data room"""
    try:
        # Check if file is in request
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400

        file = request.files['file']

        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400

        if not allowed_file(file.filename):
            return jsonify({'error': 'Only PDF files are allowed'}), 400

        # Get metadata from form data
        dataroom_id = request.form.get('dataroom_id', type=int)
        folder_id = request.form.get('folder_id', type=int)
        custom_name = request.form.get('name', '').strip()

        if not dataroom_id:
            return jsonify({'error': 'dataroom_id is required'}), 400

        # Verify dataroom exists
        dataroom = DataRoom.query.get(dataroom_id)
        if not dataroom:
            return jsonify({'error': 'Data room not found'}), 404

        # Verify folder exists if provided
        if folder_id:
            folder = Folder.query.get(folder_id)
            if not folder:
                return jsonify({'error': 'Folder not found'}), 404
            if folder.dataroom_id != dataroom_id:
                return jsonify({'error': 'Folder must be in the same data room'}), 400

        # Determine file name
        original_filename = secure_filename(file.filename)
        display_name = custom_name if custom_name else original_filename

        # Check for duplicate names and auto-rename if needed
        existing = File.query.filter_by(
            name=display_name,
            folder_id=folder_id,
            dataroom_id=dataroom_id
        ).first()

        if existing:
            name_without_ext = display_name.rsplit('.', 1)[0] if '.' in display_name else display_name
            ext = display_name.rsplit('.', 1)[1] if '.' in display_name else ''
            counter = 1
            new_name = display_name

            while existing:
                if ext:
                    new_name = f"{name_without_ext} ({counter}).{ext}"
                else:
                    new_name = f"{name_without_ext} ({counter})"

                existing = File.query.filter_by(
                    name=new_name,
                    folder_id=folder_id,
                    dataroom_id=dataroom_id
                ).first()
                counter += 1

            display_name = new_name

        # Generate unique filename for storage
        storage_filename = get_unique_filename(original_filename)
        file_path = os.path.join(UPLOAD_FOLDER, storage_filename)

        # Save file to disk
        file.save(file_path)
        file_size = os.path.getsize(file_path)

        # Create database record
        user = request.current_user
        file_record = File(
            name=display_name,
            original_name=original_filename,
            folder_id=folder_id,
            dataroom_id=dataroom_id,
            file_path=file_path,
            size=file_size,
            mime_type='application/pdf',
            uploaded_by=user.id
        )

        db.session.add(file_record)
        db.session.commit()

        return jsonify(file_record.to_dict()), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@file_bp.route('/files/<int:file_id>', methods=['GET'])
@token_required
def get_file(file_id):
    """Get file metadata"""
    try:
        file = File.query.get(file_id)
        if not file:
            return jsonify({'error': 'File not found'}), 404

        return jsonify(file.to_dict()), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@file_bp.route('/files/<int:file_id>/download', methods=['GET'])
def download_file(file_id):
    """
    Download or view a file.
    Supports authentication via:
    1. Authorization header (Bearer token)
    2. Query parameter (?token=xxx)
    """
    try:
        # Check authentication - try header first, then query parameter
        user = None

        # Method 1: Authorization header
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(' ')[1]
                user = verify_user_from_token(token)
            except (IndexError, AttributeError):
                pass

        # Method 2: Query parameter
        if not user:
            token = request.args.get('token')
            if token:
                user = verify_user_from_token(token)

        # Require authentication
        if not user:
            return jsonify({'error': 'Authentication required'}), 401

        # Get file
        file = File.query.get(file_id)
        if not file:
            return jsonify({'error': 'File not found'}), 404

        # Check if file exists on disk
        if not os.path.exists(file.file_path):
            return jsonify({'error': 'File not found on disk'}), 404

        # Create response with proper headers for PDF display
        response = make_response(send_file(
            file.file_path,
            mimetype=file.mime_type,
            as_attachment=False,  # Display inline, not download
            download_name=file.name
        ))

        # IMPORTANT: Set headers for iframe display
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'inline; filename="{file.name}"'

        # Remove any CSP that might block rendering
        if 'Content-Security-Policy' in response.headers:
            del response.headers['Content-Security-Policy']

        return response

    except Exception as e:
        print(f"Error serving file: {str(e)}")
        return jsonify({'error': str(e)}), 500


@file_bp.route('/files/<int:file_id>', methods=['PUT'])
@token_required
def update_file(file_id):
    """Update file name"""
    try:
        file = File.query.get(file_id)
        if not file:
            return jsonify({'error': 'File not found'}), 404

        data = request.get_json()
        if not data or 'name' not in data:
            return jsonify({'error': 'Name is required'}), 400

        new_name = data['name'].strip()
        if not new_name:
            return jsonify({'error': 'Name cannot be empty'}), 400

        # Ensure .pdf extension
        if not new_name.lower().endswith('.pdf'):
            new_name += '.pdf'

        # Check for duplicate names in the same location
        existing = File.query.filter_by(
            name=new_name,
            folder_id=file.folder_id,
            dataroom_id=file.dataroom_id
        ).filter(File.id != file_id).first()

        if existing:
            return jsonify({'error': 'A file with this name already exists in this location'}), 400

        file.name = new_name
        db.session.commit()

        return jsonify(file.to_dict()), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@file_bp.route('/files/<int:file_id>', methods=['DELETE'])
@token_required
def delete_file(file_id):
    """Delete a file"""
    try:
        file = File.query.get(file_id)
        if not file:
            return jsonify({'error': 'File not found'}), 404

        # Delete physical file
        file.delete_file()

        # Delete database record
        db.session.delete(file)
        db.session.commit()

        return jsonify({'message': 'File deleted successfully'}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500
