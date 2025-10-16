# backend/models.py - Enhanced with Authentication
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import os

db = SQLAlchemy()


# User Model
class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    full_name = db.Column(db.String(255))
    avatar_url = db.Column(db.String(500))
    is_active = db.Column(db.Boolean, default=True)
    is_verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)

    # Relationships
    owned_datarooms = db.relationship(
        "DataRoom", backref="owner", lazy=True, foreign_keys="DataRoom.owner_id"
    )
    permissions = db.relationship(
        "Permission", backref="user", lazy=True, cascade="all, delete-orphan"
    )

    def set_password(self, password):
        """Hash and set password"""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Verify password"""
        return check_password_hash(self.password_hash, password)

    def to_dict(self):
        return {
            "id": self.id,
            "email": self.email,
            "username": self.username,
            "full_name": self.full_name,
            "avatar_url": self.avatar_url,
            "is_active": self.is_active,
            "is_verified": self.is_verified,
            "created_at": self.created_at.isoformat(),
            "last_login": self.last_login.isoformat() if self.last_login else None,
        }


class DataRoom(db.Model):
    __tablename__ = "datarooms"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    owner_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    is_public = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    folders = db.relationship(
        "Folder", backref="dataroom", lazy=True, cascade="all, delete-orphan"
    )

    # ✅ ADD CASCADE DELETE FOR FILES
    files = db.relationship(
        "File", backref="dataroom", lazy=True, cascade="all, delete-orphan"
    )

    permissions = db.relationship(
        "Permission", backref="dataroom", lazy=True, cascade="all, delete-orphan"
    )

    def to_dict(self, include_owner=False):
        result = {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "owner_id": self.owner_id,
            "is_public": self.is_public,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }

        if include_owner and self.owner:
            result["owner"] = {
                "id": self.owner.id,
                "username": self.owner.username,
                "full_name": self.owner.full_name,
            }

        return result


class Permission(db.Model):
    """User permissions for data rooms"""

    __tablename__ = "permissions"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    dataroom_id = db.Column(db.Integer, db.ForeignKey("datarooms.id"), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'owner', 'editor', 'viewer'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (
        db.UniqueConstraint("user_id", "dataroom_id", name="unique_user_dataroom"),
    )

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "dataroom_id": self.dataroom_id,
            "role": self.role,
            "created_at": self.created_at.isoformat(),
        }


class Folder(db.Model):
    __tablename__ = "folders"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey("folders.id"), nullable=True)
    dataroom_id = db.Column(db.Integer, db.ForeignKey("datarooms.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    children = db.relationship(
        "Folder",
        backref=db.backref("parent", remote_side=[id]),
        lazy=True,
        cascade="all, delete-orphan",
    )

    files = db.relationship(
        "File", backref="folder", lazy=True, cascade="all, delete-orphan"
    )

    def to_dict(self, include_children=False):
        result = {
            "id": self.id,
            "name": self.name,
            "parent_id": self.parent_id,
            "dataroom_id": self.dataroom_id,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "type": "folder",
        }

        if include_children:
            result["children"] = [
                child.to_dict(include_children=True) for child in self.children
            ]
            result["files"] = [file.to_dict() for file in self.files]

        return result


class File(db.Model):
    __tablename__ = "files"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    original_name = db.Column(db.String(255), nullable=False)
    folder_id = db.Column(
        db.Integer, db.ForeignKey("folders.id", ondelete="CASCADE"), nullable=True
    )
    dataroom_id = db.Column(
        db.Integer, db.ForeignKey("datarooms.id", ondelete="CASCADE"), nullable=False
    )
    file_path = db.Column(db.String(500), nullable=False)
    size = db.Column(db.Integer, nullable=False)
    mime_type = db.Column(db.String(100), default="application/pdf")
    uploaded_by = db.Column(db.Integer, db.ForeignKey("users.id"))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "original_name": self.original_name,
            "folder_id": self.folder_id,
            "dataroom_id": self.dataroom_id,
            "size": self.size,
            "mime_type": self.mime_type,
            "uploaded_by": self.uploaded_by,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "type": "file",
        }

    def delete_file(self):
        """Delete the physical file from disk"""
        import os

        try:
            if self.file_path and os.path.exists(self.file_path):
                os.remove(self.file_path)
                print(f"✅ Deleted physical file: {self.file_path}")
                return True
            else:
                if self.file_path:
                    print(f"⚠️  File not found on disk: {self.file_path}")
                else:
                    print(f"⚠️  No file path set for file ID {self.id}")
                return False
        except Exception as e:
            print(f"❌ Error deleting file {self.file_path}: {str(e)}")
            import traceback

            traceback.print_exc()
            return False


class ActivityLog(db.Model):
    """Audit trail for all actions"""

    __tablename__ = "activity_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    dataroom_id = db.Column(db.Integer, db.ForeignKey("datarooms.id"), nullable=True)
    action = db.Column(
        db.String(50), nullable=False
    )  # 'create', 'update', 'delete', 'view', 'download'
    resource_type = db.Column(
        db.String(50), nullable=False
    )  # 'dataroom', 'folder', 'file'
    resource_id = db.Column(db.Integer)
    details = db.Column(db.Text)
    ip_address = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "dataroom_id": self.dataroom_id,
            "action": self.action,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "details": self.details,
            "ip_address": self.ip_address,
            "created_at": self.created_at.isoformat(),
        }


class PublicShareLink(db.Model):
    """Public shareable links for files (anyone with the link)"""

    __tablename__ = "public_share_links"

    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(
        db.Integer, db.ForeignKey("files.id", ondelete="CASCADE"), nullable=False
    )
    token = db.Column(db.String(64), unique=True, nullable=False, index=True)
    created_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=True)
    allow_download = db.Column(db.Boolean, default=True, nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    access_count = db.Column(db.Integer, default=0, nullable=False)
    last_accessed_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "file_id": self.file_id,
            "token": self.token,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "allow_download": self.allow_download,
            "is_active": self.is_active,
            "access_count": self.access_count,
            "created_at": self.created_at.isoformat(),
        }


class FileInvitation(db.Model):
    """Email-based file invitations (private sharing)"""

    __tablename__ = "file_invitations"

    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(
        db.Integer, db.ForeignKey("files.id", ondelete="CASCADE"), nullable=False
    )
    invited_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    invited_email = db.Column(db.String(255), nullable=False, index=True)
    invited_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    token = db.Column(db.String(64), unique=True, nullable=False, index=True)
    permission = db.Column(db.String(20), nullable=False)  # 'viewer', 'editor'
    message = db.Column(db.Text, nullable=True)
    status = db.Column(
        db.String(20), default="pending", nullable=False
    )  # 'pending', 'accepted', 'expired', 'revoked'
    expires_at = db.Column(db.DateTime, nullable=True)
    accepted_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "file_id": self.file_id,
            "invited_email": self.invited_email,
            "permission": self.permission,
            "status": self.status,
            "message": self.message,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "accepted_at": self.accepted_at.isoformat() if self.accepted_at else None,
            "created_at": self.created_at.isoformat(),
        }
