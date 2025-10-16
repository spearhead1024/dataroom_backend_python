# backend/routes/dataroom_routes.py - Complete Rewrite with File Cleanup
from flask import Blueprint, request, jsonify
from models import db, DataRoom, Folder, File, Permission, ActivityLog
from auth import token_required
import os

dataroom_bp = Blueprint("dataroom", __name__)


def log_activity(
    user_id, dataroom_id, action, resource_type, resource_id, details=None
):
    """Helper function to log activities"""
    try:
        log = ActivityLog(
            user_id=user_id,
            dataroom_id=dataroom_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details,
            ip_address=request.remote_addr,
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        print(f"Failed to log activity: {str(e)}")


def check_dataroom_permission(user_id, dataroom_id, required_role="viewer"):
    """Check if user has required permission for dataroom"""
    dataroom = DataRoom.query.get(dataroom_id)
    if not dataroom:
        return False, None

    # Owner has all permissions
    if dataroom.owner_id == user_id:
        return True, dataroom

    # Check explicit permissions
    permission = Permission.query.filter_by(
        user_id=user_id, dataroom_id=dataroom_id
    ).first()

    if not permission:
        return False, dataroom

    # Role hierarchy: owner > editor > viewer
    role_hierarchy = {"viewer": 1, "editor": 2, "owner": 3}
    user_role_level = role_hierarchy.get(permission.role, 0)
    required_role_level = role_hierarchy.get(required_role, 0)

    return user_role_level >= required_role_level, dataroom


@dataroom_bp.route("/datarooms", methods=["POST"])
@token_required
def create_dataroom():
    """Create a new data room"""
    try:
        user = request.current_user
        data = request.get_json()

        if not data or "name" not in data:
            return jsonify({"error": "Name is required"}), 400

        name = data["name"].strip()
        if not name:
            return jsonify({"error": "Name cannot be empty"}), 400

        description = data.get("description", "").strip()
        is_public = data.get("is_public", False)

        dataroom = DataRoom(
            name=name, description=description, owner_id=user.id, is_public=is_public
        )
        db.session.add(dataroom)
        db.session.commit()

        print(
            f"✅ Created data room: ID={dataroom.id}, name={name}, owner={user.username}"
        )

        # Log activity
        log_activity(
            user.id,
            dataroom.id,
            "create",
            "dataroom",
            dataroom.id,
            f"Created data room: {name}",
        )

        return jsonify(dataroom.to_dict(include_owner=True)), 201

    except Exception as e:
        db.session.rollback()
        print(f"❌ Error creating data room: {str(e)}")
        return jsonify({"error": str(e)}), 500


@dataroom_bp.route("/datarooms", methods=["GET"])
@token_required
def get_datarooms():
    """Get all data rooms accessible by current user"""
    try:
        user = request.current_user

        # Get data rooms owned by user
        owned_rooms = DataRoom.query.filter_by(owner_id=user.id).all()

        # Get data rooms shared with user
        permissions = Permission.query.filter_by(user_id=user.id).all()
        shared_room_ids = [p.dataroom_id for p in permissions]
        shared_rooms = (
            DataRoom.query.filter(DataRoom.id.in_(shared_room_ids)).all()
            if shared_room_ids
            else []
        )

        # Combine and remove duplicates
        all_rooms = {room.id: room for room in owned_rooms + shared_rooms}

        result = []
        for room in all_rooms.values():
            room_dict = room.to_dict(include_owner=True)
            # Add user's role
            if room.owner_id == user.id:
                room_dict["user_role"] = "owner"
            else:
                perm = next((p for p in permissions if p.dataroom_id == room.id), None)
                room_dict["user_role"] = perm.role if perm else "viewer"
            result.append(room_dict)

        print(f"📂 Loaded {len(result)} data rooms for user {user.username}")
        return jsonify(result), 200

    except Exception as e:
        print(f"❌ Error getting data rooms: {str(e)}")
        return jsonify({"error": str(e)}), 500


@dataroom_bp.route("/datarooms/<int:dataroom_id>", methods=["GET"])
@token_required
def get_dataroom(dataroom_id):
    """Get a specific data room with its contents"""
    try:
        user = request.current_user

        # Check permissions
        has_permission, dataroom = check_dataroom_permission(
            user.id, dataroom_id, "viewer"
        )
        if not has_permission or not dataroom:
            return jsonify({"error": "Data room not found or access denied"}), 404

        # Get root folders (folders with no parent)
        root_folders = Folder.query.filter_by(
            dataroom_id=dataroom_id, parent_id=None
        ).all()

        # Get root files (files with no folder)
        root_files = File.query.filter_by(dataroom_id=dataroom_id, folder_id=None).all()

        result = dataroom.to_dict(include_owner=True)
        result["folders"] = [f.to_dict(include_children=True) for f in root_folders]
        result["files"] = [f.to_dict() for f in root_files]

        # Add user's role
        if dataroom.owner_id == user.id:
            result["user_role"] = "owner"
        else:
            perm = Permission.query.filter_by(
                user_id=user.id, dataroom_id=dataroom_id
            ).first()
            result["user_role"] = perm.role if perm else "viewer"

        print(
            f"📂 Loaded data room {dataroom_id}: {len(root_folders)} folders, {len(root_files)} files"
        )

        # Log activity
        log_activity(
            user.id,
            dataroom_id,
            "view",
            "dataroom",
            dataroom_id,
            f"Viewed data room: {dataroom.name}",
        )

        return jsonify(result), 200

    except Exception as e:
        print(f"❌ Error getting data room: {str(e)}")
        return jsonify({"error": str(e)}), 500


@dataroom_bp.route("/datarooms/<int:dataroom_id>", methods=["PUT"])
@token_required
def update_dataroom(dataroom_id):
    """Update data room details"""
    try:
        user = request.current_user

        # Check permissions (editor or owner)
        has_permission, dataroom = check_dataroom_permission(
            user.id, dataroom_id, "editor"
        )
        if not has_permission or not dataroom:
            return jsonify({"error": "Data room not found or access denied"}), 404

        data = request.get_json()

        if "name" in data:
            name = data["name"].strip()
            if not name:
                return jsonify({"error": "Name cannot be empty"}), 400
            dataroom.name = name

        if "description" in data:
            dataroom.description = data["description"].strip()

        if "is_public" in data and dataroom.owner_id == user.id:
            dataroom.is_public = data["is_public"]

        db.session.commit()

        print(f"✏️ Updated data room {dataroom_id}: {dataroom.name}")

        # Log activity
        log_activity(
            user.id,
            dataroom_id,
            "update",
            "dataroom",
            dataroom_id,
            f"Updated data room: {dataroom.name}",
        )

        return jsonify(dataroom.to_dict(include_owner=True)), 200

    except Exception as e:
        db.session.rollback()
        print(f"❌ Error updating data room: {str(e)}")
        return jsonify({"error": str(e)}), 500


@dataroom_bp.route("/datarooms/<int:dataroom_id>", methods=["DELETE"])
@token_required
def delete_dataroom(dataroom_id):
    """Delete a data room and all its contents (owner only)"""
    try:
        user = request.current_user
        dataroom = DataRoom.query.get(dataroom_id)

        if not dataroom:
            return jsonify({"error": "Data room not found"}), 404

        # Only owner can delete
        if dataroom.owner_id != user.id:
            return jsonify({"error": "Only the owner can delete this data room"}), 403

        dataroom_name = dataroom.name

        # DELETE ALL PHYSICAL FILES FIRST - before database cascade
        print(
            f"🗑️  Deleting physical files for dataroom {dataroom_id} ({dataroom_name})..."
        )
        files = File.query.filter_by(dataroom_id=dataroom_id).all()
        deleted_count = 0
        failed_count = 0
        failed_files = []

        for file in files:
            try:
                success = file.delete_file()
                if success:
                    deleted_count += 1
                    print(f"  ✅ Deleted: {file.name} (ID: {file.id})")
                else:
                    failed_count += 1
                    failed_files.append(file.name)
                    print(f"  ⚠️  File not found on disk: {file.name} (ID: {file.id})")
            except Exception as e:
                failed_count += 1
                failed_files.append(file.name)
                print(f"  ❌ Failed to delete {file.name}: {str(e)}")

        print(
            f"📊 Physical file cleanup: {deleted_count} deleted, {failed_count} failed"
        )

        # Log activity before deletion
        log_activity(
            user.id,
            dataroom_id,
            "delete",
            "dataroom",
            dataroom_id,
            f"Deleted data room: {dataroom_name} ({deleted_count} files removed, {failed_count} failed)",
        )

        # Now delete the dataroom (cascade will handle database records)
        db.session.delete(dataroom)
        db.session.commit()

        print(f"✅ DataRoom {dataroom_id} ({dataroom_name}) deleted successfully")

        response_data = {
            "message": "Data room deleted successfully",
            "files_deleted": deleted_count,
            "files_failed": failed_count,
        }

        if failed_files:
            response_data["failed_files"] = failed_files

        return jsonify(response_data), 200

    except Exception as e:
        db.session.rollback()
        print(f"❌ Error deleting dataroom: {str(e)}")
        import traceback

        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@dataroom_bp.route("/datarooms/<int:dataroom_id>/share", methods=["POST"])
@token_required
def share_dataroom(dataroom_id):
    """Share data room with another user (owner only)"""
    try:
        user = request.current_user
        dataroom = DataRoom.query.get(dataroom_id)

        if not dataroom:
            return jsonify({"error": "Data room not found"}), 404

        # Only owner can share
        if dataroom.owner_id != user.id:
            return jsonify({"error": "Only the owner can share this data room"}), 403

        data = request.get_json()
        target_user_email = data.get("user_email")
        role = data.get("role", "viewer")

        if not target_user_email:
            return jsonify({"error": "User email is required"}), 400

        if role not in ["viewer", "editor"]:
            return jsonify({"error": "Invalid role. Must be viewer or editor"}), 400

        # Find target user
        from models import User

        target_user = User.query.filter_by(email=target_user_email.lower()).first()
        if not target_user:
            return jsonify({"error": "User not found"}), 404

        # Check if permission already exists
        existing_perm = Permission.query.filter_by(
            user_id=target_user.id, dataroom_id=dataroom_id
        ).first()

        if existing_perm:
            # Update existing permission
            existing_perm.role = role
            print(f"✏️ Updated permission for {target_user_email} to {role}")
        else:
            # Create new permission
            permission = Permission(
                user_id=target_user.id, dataroom_id=dataroom_id, role=role
            )
            db.session.add(permission)
            print(f"➕ Created permission for {target_user_email} as {role}")

        db.session.commit()

        # Log activity
        log_activity(
            user.id,
            dataroom_id,
            "share",
            "dataroom",
            dataroom_id,
            f"Shared data room with {target_user_email} as {role}",
        )

        return jsonify({"message": f"Data room shared with {target_user_email}"}), 200

    except Exception as e:
        db.session.rollback()
        print(f"❌ Error sharing data room: {str(e)}")
        return jsonify({"error": str(e)}), 500


@dataroom_bp.route("/datarooms/<int:dataroom_id>/permissions", methods=["GET"])
@token_required
def get_dataroom_permissions(dataroom_id):
    """Get all permissions for a data room (owner only)"""
    try:
        user = request.current_user
        dataroom = DataRoom.query.get(dataroom_id)

        if not dataroom:
            return jsonify({"error": "Data room not found"}), 404

        # Only owner can view permissions
        if dataroom.owner_id != user.id:
            return jsonify({"error": "Only the owner can view permissions"}), 403

        permissions = Permission.query.filter_by(dataroom_id=dataroom_id).all()

        result = []
        for perm in permissions:
            perm_dict = perm.to_dict()
            # Add user info
            from models import User

            perm_user = User.query.get(perm.user_id)
            if perm_user:
                perm_dict["user"] = {
                    "id": perm_user.id,
                    "email": perm_user.email,
                    "username": perm_user.username,
                    "full_name": perm_user.full_name,
                }
            result.append(perm_dict)

        print(f"🔐 Loaded {len(result)} permissions for data room {dataroom_id}")
        return jsonify(result), 200

    except Exception as e:
        print(f"❌ Error getting permissions: {str(e)}")
        return jsonify({"error": str(e)}), 500


@dataroom_bp.route("/permissions/<int:permission_id>", methods=["DELETE"])
@token_required
def remove_permission(permission_id):
    """Remove a permission (owner only)"""
    try:
        user = request.current_user
        permission = Permission.query.get(permission_id)

        if not permission:
            return jsonify({"error": "Permission not found"}), 404

        dataroom = DataRoom.query.get(permission.dataroom_id)
        if not dataroom or dataroom.owner_id != user.id:
            return jsonify({"error": "Only the owner can remove permissions"}), 403

        db.session.delete(permission)
        db.session.commit()

        print(f"🗑️ Removed permission {permission_id}")

        # Log activity
        log_activity(
            user.id,
            permission.dataroom_id,
            "unshare",
            "dataroom",
            permission.dataroom_id,
            f"Removed permission for user {permission.user_id}",
        )

        return jsonify({"message": "Permission removed successfully"}), 200

    except Exception as e:
        db.session.rollback()
        print(f"❌ Error removing permission: {str(e)}")
        return jsonify({"error": str(e)}), 500


@dataroom_bp.route("/datarooms/<int:dataroom_id>/activity", methods=["GET"])
@token_required
def get_dataroom_activity(dataroom_id):
    """Get activity log for a data room"""
    try:
        user = request.current_user

        # Check permissions
        has_permission, dataroom = check_dataroom_permission(
            user.id, dataroom_id, "viewer"
        )
        if not has_permission or not dataroom:
            return jsonify({"error": "Data room not found or access denied"}), 404

        limit = request.args.get("limit", 50, type=int)

        activities = (
            ActivityLog.query.filter_by(dataroom_id=dataroom_id)
            .order_by(ActivityLog.created_at.desc())
            .limit(limit)
            .all()
        )

        result = []
        for activity in activities:
            activity_dict = activity.to_dict()
            # Add user info
            from models import User

            activity_user = User.query.get(activity.user_id)
            if activity_user:
                activity_dict["user"] = {
                    "id": activity_user.id,
                    "username": activity_user.username,
                    "full_name": activity_user.full_name,
                }
            result.append(activity_dict)

        print(f"📜 Loaded {len(result)} activity logs for data room {dataroom_id}")
        return jsonify(result), 200

    except Exception as e:
        print(f"❌ Error getting activity log: {str(e)}")
        return jsonify({"error": str(e)}), 500


@dataroom_bp.route("/admin/cleanup-files", methods=["POST"])
@token_required
def cleanup_orphaned_files_endpoint():
    """
    Admin endpoint to manually cleanup orphaned file records
    Files that exist in database but not on disk
    """
    try:
        user = request.current_user

        print(f"🧹 Manual cleanup initiated by user {user.username}")

        all_files = File.query.all()
        orphaned = []

        for file in all_files:
            if not os.path.exists(file.file_path):
                orphaned.append(
                    {
                        "id": file.id,
                        "name": file.name,
                        "path": file.file_path,
                        "dataroom_id": file.dataroom_id,
                    }
                )

        if orphaned:
            print(f"🗑️  Found {len(orphaned)} orphaned file records")
            for orphan_info in orphaned:
                file = File.query.get(orphan_info["id"])
                if file:
                    print(f"  🗑️  Removing orphan: {file.name} (ID: {file.id})")
                    db.session.delete(file)

            db.session.commit()
            print(f"✅ Removed {len(orphaned)} orphaned file records")

            # Log activity
            log_activity(
                user.id,
                None,
                "cleanup",
                "file",
                None,
                f"Cleaned up {len(orphaned)} orphaned file records",
            )

            return (
                jsonify(
                    {
                        "message": f"Cleaned up {len(orphaned)} orphaned file records",
                        "orphaned_files": orphaned,
                    }
                ),
                200,
            )
        else:
            print("✅ No orphaned file records found")
            return (
                jsonify(
                    {"message": "No orphaned file records found", "orphaned_files": []}
                ),
                200,
            )

    except Exception as e:
        db.session.rollback()
        print(f"❌ Error during manual cleanup: {str(e)}")
        import traceback

        traceback.print_exc()
        return jsonify({"error": str(e)}), 500
