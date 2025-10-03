from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import os

db = SQLAlchemy()

class DataRoom(db.Model):
    __tablename__ = 'datarooms'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    folders = db.relationship('Folder', backref='dataroom', lazy=True, cascade='all, delete-orphan')
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'created_at': self.created_at.isoformat()
        }


class Folder(db.Model):
    __tablename__ = 'folders'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey('folders.id'), nullable=True)
    dataroom_id = db.Column(db.Integer, db.ForeignKey('datarooms.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Self-referential relationship for nested folders
    children = db.relationship('Folder', 
                              backref=db.backref('parent', remote_side=[id]),
                              lazy=True,
                              cascade='all, delete-orphan')
    
    files = db.relationship('File', backref='folder', lazy=True, cascade='all, delete-orphan')
    
    def to_dict(self, include_children=False):
        result = {
            'id': self.id,
            'name': self.name,
            'parent_id': self.parent_id,
            'dataroom_id': self.dataroom_id,
            'created_at': self.created_at.isoformat(),
            'type': 'folder'
        }
        
        if include_children:
            result['children'] = [child.to_dict(include_children=True) for child in self.children]
            result['files'] = [file.to_dict() for file in self.files]
        
        return result


class File(db.Model):
    __tablename__ = 'files'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    original_name = db.Column(db.String(255), nullable=False)
    folder_id = db.Column(db.Integer, db.ForeignKey('folders.id'), nullable=True)
    dataroom_id = db.Column(db.Integer, db.ForeignKey('datarooms.id'), nullable=False)
    file_path = db.Column(db.String(500), nullable=False)
    size = db.Column(db.Integer, nullable=False)
    mime_type = db.Column(db.String(100), default='application/pdf')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'original_name': self.original_name,
            'folder_id': self.folder_id,
            'dataroom_id': self.dataroom_id,
            'size': self.size,
            'mime_type': self.mime_type,
            'created_at': self.created_at.isoformat(),
            'type': 'file'
        }
    
    def delete_file(self):
        """Delete the physical file from disk"""
        try:
            if os.path.exists(self.file_path):
                os.remove(self.file_path)
        except Exception as e:
            print(f"Error deleting file {self.file_path}: {str(e)}")
