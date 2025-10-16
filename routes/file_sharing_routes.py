# backend/routes/file_sharing_routes.py - COMPLETE REWRITE
from flask import Blueprint, request, jsonify
from models import db, File, Folder, DataRoom, User, Permission, PublicShareLink, FileInvitation
from auth import token_required, optional_token
import secrets
import string
from datetime import datetime, timedelta

sharing_bp = Blueprint('sharing', __name__)


def generate_share_token(length=32):
    """Generate a secure random token for sharing"""
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def check_user_can_share_file(user_id, file_id):
    """Check if user has permission to share a file"""
    file = File.query.get(file_id)
    if not file:
        return None, "File not found"

    dataroom = DataRoom.query.get(file.dataroom_id)
    if not dataroom:
        return None, "Data room not found"

    # Owner has all permissions
    if dataroom.owner_id == user_id:
        return file, None

    # Check if user has editor or owner permission
    permission = Permission.query.filter_by(
        user_id=user_id,
        dataroom_id=file.dataroom_id
    ).first()

    if not permission or permission.role not in ['editor', 'owner']:
        return None, "You do not have permission to share this file"

    return file, None


# ============ PUBLIC LINK SHARING ============

@sharing_bp.route('/files/<int:file_id>/share/public', methods=['POST'])
@token_required
def create_public_share_link(file_id):
    """
    Create a public shareable link for a file (anyone with the link can access)

    Request Body:
        {
            "expires_in_days": 7 (optional),
            "allow_download": true (optional, default: true)
        }

    Returns:
        {
            "share_url": "http://localhost:5000/share/{token}",
            "token": "{token}",
            "expires_at": "2025-01-01T00:00:00",
            "allow_download": true,
            "created_at": "2024-12-25T00:00:00"
        }
    """
    try:
        user = request.current_user

        # Check permissions
        file, error = check_user_can_share_file(user.id, file_id)
        if error:
            return jsonify({'error': error}), 403 if file is None else 404

        # Get request data
        data = request.get_json() or {}
        expires_in_days = data.get('expires_in_days')
        allow_download = data.get('allow_download', True)

        # Generate unique share token
        share_token = generate_share_token()

        # Calculate expiration date
        expires_at = None
        if expires_in_days:
            expires_at = datetime.utcnow() + timedelta(days=int(expires_in_days))

        # Create share link record
        share_link = PublicShareLink(
            file_id=file_id,
            created_by=user.id,
            token=share_token,
            expires_at=expires_at,
            allow_download=bool(allow_download),
            is_active=True,
            access_count=0
        )

        db.session.add(share_link)
        db.session.commit()

        # Verify it was saved
        db.session.refresh(share_link)
        print(f"✅ Created share link: ID={share_link.id}, file_id={share_link.file_id}, token={share_link.token}")

        # Generate shareable URL (without /api prefix)
        share_url = f"{request.host_url}share/{share_token}"

        return jsonify({
            'share_url': share_url,
            'token': share_token,
            'expires_at': expires_at.isoformat() if expires_at else None,
            'allow_download': allow_download,
            'created_at': share_link.created_at.isoformat()
        }), 201

    except Exception as e:
        db.session.rollback()
        print(f"❌ Error creating share link: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'Failed to create share link: {str(e)}'}), 500


@sharing_bp.route('/files/<int:file_id>/share/public', methods=['GET'])
@token_required
def get_public_share_links(file_id):
    """
    Get all active public share links for a file

    Returns:
        [
            {
                "id": 1,
                "share_url": "http://localhost:5000/share/{token}",
                "token": "{token}",
                "expires_at": "2025-01-01T00:00:00",
                "allow_download": true,
                "access_count": 5,
                "created_at": "2024-12-25T00:00:00"
            }
        ]
    """
    try:
        user = request.current_user

        # Check permissions
        file, error = check_user_can_share_file(user.id, file_id)
        if error:
            # Also allow viewers to see share links
            file = File.query.get(file_id)
            if not file:
                return jsonify({'error': 'File not found'}), 404

            dataroom = DataRoom.query.get(file.dataroom_id)
            permission = Permission.query.filter_by(
                user_id=user.id,
                dataroom_id=file.dataroom_id
            ).first()

            if dataroom.owner_id != user.id and not permission:
                return jsonify({'error': 'Access denied'}), 403

        # Get all active share links
        share_links = PublicShareLink.query.filter_by(
            file_id=file_id,
            is_active=True
        ).order_by(PublicShareLink.created_at.desc()).all()

        result = []
        for link in share_links:
            # Check if expired
            if link.expires_at and link.expires_at < datetime.utcnow():
                continue

            result.append({
                'id': link.id,
                'share_url': f"{request.host_url}share/{link.token}",
                'token': link.token,
                'expires_at': link.expires_at.isoformat() if link.expires_at else None,
                'allow_download': link.allow_download,
                'access_count': link.access_count,
                'created_at': link.created_at.isoformat()
            })

        return jsonify(result), 200

    except Exception as e:
        print(f"❌ Error fetching share links: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@sharing_bp.route('/share-links/<int:link_id>', methods=['DELETE'])
@token_required
def revoke_public_share_link(link_id):
    """
    Revoke a public share link

    Returns:
        {"message": "Share link revoked successfully"}
    """
    try:
        user = request.current_user

        share_link = PublicShareLink.query.get(link_id)
        if not share_link:
            return jsonify({'error': 'Share link not found'}), 404

        # Check permissions
        file = File.query.get(share_link.file_id)
        dataroom = DataRoom.query.get(file.dataroom_id)

        # Only creator or dataroom owner can revoke
        if dataroom.owner_id != user.id and share_link.created_by != user.id:
            return jsonify({'error': 'Only the creator or dataroom owner can revoke this link'}), 403

        # Deactivate the link
        share_link.is_active = False
        db.session.commit()

        print(f"✅ Revoked share link: ID={link_id}")

        return jsonify({'message': 'Share link revoked successfully'}), 200

    except Exception as e:
        db.session.rollback()
        print(f"❌ Error revoking link: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


# ============ PRIVATE SHARING (Email Invitations) ============

@sharing_bp.route('/files/<int:file_id>/share/invite', methods=['POST'])
@token_required
def invite_user_to_file(file_id):
    """
    Invite specific users to access a file via email

    Request Body:
        {
            "emails": ["user1@example.com", "user2@example.com"],
            "permission": "viewer" | "editor",
            "message": "Optional message" (optional),
            "expires_in_days": 30 (optional, default: 30)
        }

    Returns:
        {
            "message": "Invitations sent to 2 recipients",
            "invitations": [
                {
                    "email": "user@example.com",
                    "token": "{token}",
                    "invitation_url": "http://localhost:5000/accept-invitation/{token}",
                    "user_exists": true
                }
            ]
        }
    """
    try:
        user = request.current_user

        # Check permissions
        file, error = check_user_can_share_file(user.id, file_id)
        if error:
            return jsonify({'error': error}), 403 if file is None else 404

        # Get request data
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Request body is required'}), 400

        emails = data.get('emails', [])
        permission_level = data.get('permission', 'viewer')
        message = data.get('message', '')
        expires_in_days = data.get('expires_in_days', 30)

        # Validate input
        if not emails or not isinstance(emails, list):
            return jsonify({'error': 'At least one email is required'}), 400

        if permission_level not in ['viewer', 'editor']:
            return jsonify({'error': 'Permission must be viewer or editor'}), 400

        # Calculate expiration
        expires_at = datetime.utcnow() + timedelta(days=int(expires_in_days))

        invitations = []

        for email in emails:
            email = email.strip().lower()

            if not email:
                continue

            # Check if user exists
            invited_user = User.query.filter_by(email=email).first()

            # Generate invitation token
            invitation_token = generate_share_token()

            # Create invitation
            invitation = FileInvitation(
                file_id=file_id,
                invited_by=user.id,
                invited_email=email,
                invited_user_id=invited_user.id if invited_user else None,
                permission=permission_level,
                token=invitation_token,
                message=message,
                status='pending',
                expires_at=expires_at
            )

            db.session.add(invitation)

            invitations.append({
                'email': email,
                'token': invitation_token,
                'invitation_url': f"{request.host_url}accept-invitation/{invitation_token}",
                'user_exists': invited_user is not None
            })

        db.session.commit()

        print(f"✅ Created {len(invitations)} invitations for file_id={file_id}")

        return jsonify({
            'message': f'Invitations sent to {len(invitations)} recipient(s)',
            'invitations': invitations
        }), 201

    except Exception as e:
        db.session.rollback()
        print(f"❌ Error sending invitations: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'Failed to send invitations: {str(e)}'}), 500


@sharing_bp.route('/files/<int:file_id>/invitations', methods=['GET'])
@token_required
def get_file_invitations(file_id):
    """
    Get all invitations for a file

    Returns:
        [
            {
                "id": 1,
                "email": "user@example.com",
                "permission": "viewer",
                "status": "pending",
                "invited_by": "admin",
                "created_at": "2024-12-25T00:00:00",
                "expires_at": "2025-01-24T00:00:00",
                "accepted_at": null
            }
        ]
    """
    try:
        user = request.current_user

        file = File.query.get(file_id)
        if not file:
            return jsonify({'error': 'File not found'}), 404

        # Check permissions
        dataroom = DataRoom.query.get(file.dataroom_id)
        permission = Permission.query.filter_by(
            user_id=user.id,
            dataroom_id=file.dataroom_id
        ).first()

        if dataroom.owner_id != user.id and not permission:
            return jsonify({'error': 'Access denied'}), 403

        # Get all invitations
        invitations = FileInvitation.query.filter_by(
            file_id=file_id
        ).order_by(FileInvitation.created_at.desc()).all()

        result = []
        for inv in invitations:
            invited_by_user = User.query.get(inv.invited_by)
            result.append({
                'id': inv.id,
                'email': inv.invited_email,
                'permission': inv.permission,
                'status': inv.status,
                'invited_by': invited_by_user.username if invited_by_user else 'Unknown',
                'created_at': inv.created_at.isoformat(),
                'expires_at': inv.expires_at.isoformat() if inv.expires_at else None,
                'accepted_at': inv.accepted_at.isoformat() if inv.accepted_at else None
            })

        return jsonify(result), 200

    except Exception as e:
        print(f"❌ Error fetching invitations: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@sharing_bp.route('/invitations/<int:invitation_id>', methods=['DELETE'])
@token_required
def revoke_invitation(invitation_id):
    """
    Revoke a file invitation

    Returns:
        {"message": "Invitation revoked successfully"}
    """
    try:
        user = request.current_user

        invitation = FileInvitation.query.get(invitation_id)
        if not invitation:
            return jsonify({'error': 'Invitation not found'}), 404

        # Check permissions
        file = File.query.get(invitation.file_id)
        dataroom = DataRoom.query.get(file.dataroom_id)

        # Only creator or dataroom owner can revoke
        if dataroom.owner_id != user.id and invitation.invited_by != user.id:
            return jsonify({'error': 'Only the creator or dataroom owner can revoke this invitation'}), 403

        # Mark as revoked
        invitation.status = 'revoked'
        db.session.commit()

        print(f"✅ Revoked invitation: ID={invitation_id}")

        return jsonify({'message': 'Invitation revoked successfully'}), 200

    except Exception as e:
        db.session.rollback()
        print(f"❌ Error revoking invitation: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


# ============ PUBLIC ACCESS ENDPOINTS (NO AUTH REQUIRED) ============

def access_public_share_logic(token):
    """
    Logic for accessing a public share link
    This function can be called from both the blueprint route and direct app route
    """
    try:
        share_link = PublicShareLink.query.filter_by(
            token=token,
            is_active=True
        ).first()

        if not share_link:
            print(f"❌ Share link not found for token: {token}")
            return jsonify({'error': 'Invalid or expired share link'}), 404

        # Check if expired
        if share_link.expires_at and share_link.expires_at < datetime.utcnow():
            print(f"❌ Share link expired: {token}")
            return jsonify({'error': 'This share link has expired'}), 410

        # Increment access count
        share_link.access_count += 1
        share_link.last_accessed_at = datetime.utcnow()
        db.session.commit()

        # Get file details
        file = File.query.get(share_link.file_id)
        if not file:
            print(f"❌ File not found for share link: {share_link.file_id}")
            return jsonify({'error': 'File not found'}), 404

        print(f"✅ Share link accessed: token={token}, file_id={file.id}, count={share_link.access_count}")

        return jsonify({
            'file': file.to_dict(),
            'allow_download': share_link.allow_download,
            'expires_at': share_link.expires_at.isoformat() if share_link.expires_at else None
        }), 200

    except Exception as e:
        print(f"❌ Error accessing share: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@sharing_bp.route('/share/<token>', methods=['GET'])
@optional_token
def access_public_share(token):
    """
    Access a file via public share link (API route with /api prefix)
    This is the blueprint route, accessible at /api/share/<token>
    """
    return access_public_share_logic(token)


def accept_file_invitation_logic(token):
    """
    Logic for accepting a file invitation
    This function can be called from both the blueprint route and direct app route
    """
    try:
        # Get current user from request context
        user = getattr(request, 'current_user', None)
        if not user:
            print(f"❌ No authenticated user for invitation: {token}")
            return jsonify({
                'error': 'Authentication required',
                'message': 'Please log in to accept this invitation',
                'invitation_token': token
            }), 401

        invitation = FileInvitation.query.filter_by(
            token=token,
            status='pending'
        ).first()

        if not invitation:
            print(f"❌ Invitation not found or already used: {token}")
            return jsonify({'error': 'Invalid or already used invitation'}), 404

        # Check if expired
        if invitation.expires_at and invitation.expires_at < datetime.utcnow():
            invitation.status = 'expired'
            db.session.commit()
            print(f"❌ Invitation expired: {token}")
            return jsonify({'error': 'This invitation has expired'}), 410

        # Verify email matches
        if user.email.lower() != invitation.invited_email.lower():
            print(f"❌ Email mismatch: {user.email} != {invitation.invited_email}")
            return jsonify({'error': 'This invitation was sent to a different email address'}), 403

        # Grant access to the dataroom
        file = File.query.get(invitation.file_id)
        if not file:
            print(f"❌ File not found for invitation: {invitation.file_id}")
            return jsonify({'error': 'File not found'}), 404

        existing_permission = Permission.query.filter_by(
            user_id=user.id,
            dataroom_id=file.dataroom_id
        ).first()

        if not existing_permission:
            permission = Permission(
                user_id=user.id,
                dataroom_id=file.dataroom_id,
                role=invitation.permission
            )
            db.session.add(permission)
            print(f"✅ Created new permission: user={user.id}, dataroom={file.dataroom_id}, role={invitation.permission}")
        else:
            # Upgrade permission if needed
            role_hierarchy = {'viewer': 1, 'editor': 2, 'owner': 3}
            if role_hierarchy[invitation.permission] > role_hierarchy[existing_permission.role]:
                existing_permission.role = invitation.permission
                print(f"✅ Upgraded permission: user={user.id}, new_role={invitation.permission}")

        # Mark invitation as accepted
        invitation.status = 'accepted'
        invitation.accepted_at = datetime.utcnow()

        db.session.commit()

        print(f"✅ Invitation accepted: token={token}, user={user.email}")

        return jsonify({
            'message': 'Invitation accepted successfully',
            'file': file.to_dict(),
            'permission': invitation.permission,
            'dataroom_id': file.dataroom_id
        }), 200

    except Exception as e:
        db.session.rollback()
        print(f"❌ Error accepting invitation: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@sharing_bp.route('/accept-invitation/<token>', methods=['GET', 'POST'])
@token_required
def accept_file_invitation(token):
    """
    Accept a file invitation (API route with /api prefix)
    This is the blueprint route, accessible at /api/accept-invitation/<token>
    """
    return accept_file_invitation_logic(token)

# ============ PUBLIC FILE DOWNLOAD ============

@sharing_bp.route('/share/<token>/download', methods=['GET'])
def download_shared_file(token):
    """
    Download a file via public share link (no authentication required)
    Accessible at /api/share/<token>/download
    """
    try:
        share_link = PublicShareLink.query.filter_by(
            token=token,
            is_active=True
        ).first()

        if not share_link:
            return jsonify({'error': 'Invalid or expired share link'}), 404

        # Check if expired
        if share_link.expires_at and share_link.expires_at < datetime.utcnow():
            return jsonify({'error': 'This share link has expired'}), 410

        # Check if download is allowed
        if not share_link.allow_download:
            return jsonify({'error': 'Download is not allowed for this share link'}), 403

        # Get file
        file = File.query.get(share_link.file_id)
        if not file:
            return jsonify({'error': 'File not found'}), 404

        # Check if file exists on disk
        import os
        if not os.path.exists(file.file_path):
            return jsonify({'error': 'File not found on disk'}), 404

        # Increment access count
        share_link.access_count += 1
        share_link.last_accessed_at = datetime.utcnow()
        db.session.commit()

        print(f"✅ Downloading shared file: token={token}, file={file.name}")

        # Send file
        from flask import send_file, make_response
        response = make_response(send_file(
            file.file_path,
            mimetype=file.mime_type,
            as_attachment=False,
            download_name=file.name
        ))

        # Set headers for PDF display
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'inline; filename="{file.name}"'

        return response

    except Exception as e:
        print(f"❌ Error downloading shared file: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@sharing_bp.route('/share/<token>/view', methods=['GET'])
def view_shared_file(token):
    """
    View a file via public share link (same as download but always inline)
    Accessible at /api/share/<token>/view
    """
    return download_shared_file(token)
# Export logic functions for use in app.py direct routes
__all__ = [
    'sharing_bp',
    'access_public_share_logic',
    'accept_file_invitation_logic'
]
