# backend/app.py - Enhanced with Sharing Routes
from flask import Flask, jsonify
from flask_cors import CORS
from models import db
from routes.dataroom_routes import dataroom_bp
from routes.folder_routes import folder_bp
from routes.file_routes import file_bp
from routes.auth_routes import auth_bp
from routes.file_sharing_routes import sharing_bp  # NEW
from routes.file_sharing_routes import access_public_share

import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Configuration
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL", "sqlite:///dataroom.db"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["MAX_CONTENT_LENGTH"] = int(
    os.environ.get("MAX_CONTENT_LENGTH", 104857600)
)  # 100MB
app.config["UPLOAD_FOLDER"] = os.environ.get("UPLOAD_FOLDER", "uploads")
app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY", "your-secret-key-change-in-production"
)

# Ensure upload folder exists
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

# Initialize extensions
db.init_app(app)

# CORS configuration - more secure in production
CORS(
    app,
    resources={
        r"/api/*": {
            "origins": os.environ.get("CORS_ORIGINS", "*").split(","),
            "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            "allow_headers": ["Content-Type", "Authorization"],
            "expose_headers": ["Content-Range", "X-Content-Range"],
            "supports_credentials": True,
        }
    },
)

# Register blueprints
app.register_blueprint(auth_bp, url_prefix="/api")
app.register_blueprint(dataroom_bp, url_prefix="/api")
app.register_blueprint(folder_bp, url_prefix="/api")
app.register_blueprint(file_bp, url_prefix="/api")
app.register_blueprint(sharing_bp, url_prefix="/api")  # NEW


@app.route("/share/<token>", methods=["GET"])
def public_share(token):
    """Public share link access - no auth required"""
    return access_public_share(token)


@app.route("/share/<token>/download", methods=["GET"])
def download_shared_file_direct(token):
    """Download file via public share - accessible at /share/<token>/download"""
    from routes.file_sharing_routes import download_shared_file

    return download_shared_file(token)


@app.route("/share/<token>/view", methods=["GET"])
def view_shared_file_direct(token):
    """View file via public share - accessible at /share/<token>/view"""
    from routes.file_sharing_routes import download_shared_file

    return download_shared_file(token)


# Health check endpoint
@app.route("/api/health", methods=["GET"])
def health_check():
    return (
        jsonify(
            {
                "status": "healthy",
                "message": "Data Room API is running",
                "version": "2.1.0",
            }
        ),
        200,
    )


# API info endpoint
@app.route("/api", methods=["GET"])
def api_info():
    return (
        jsonify(
            {
                "name": "Data Room API",
                "version": "2.1.0",
                "description": "Professional secure document management system",
                "features": [
                    "JWT Authentication",
                    "Role-based Access Control",
                    "File Upload & Management",
                    "Nested Folder Structure",
                    "Activity Logging",
                    "Public Link Sharing",  # NEW
                    "Email Invitations",  # NEW
                ],
                "endpoints": {
                    "auth": "/api/auth/*",
                    "datarooms": "/api/datarooms",
                    "folders": "/api/folders",
                    "files": "/api/files",
                    "sharing": "/api/files/:id/share/*",  # NEW
                },
            }
        ),
        200,
    )


# Error handlers
@app.errorhandler(400)
def bad_request(error):
    return jsonify({"error": "Bad request", "message": str(error)}), 400


@app.errorhandler(401)
def unauthorized(error):
    return jsonify({"error": "Unauthorized", "message": "Authentication required"}), 401


@app.errorhandler(403)
def forbidden(error):
    return (
        jsonify(
            {
                "error": "Forbidden",
                "message": "You do not have permission to access this resource",
            }
        ),
        403,
    )


@app.errorhandler(404)
def not_found(error):
    return (
        jsonify(
            {"error": "Not found", "message": "The requested resource was not found"}
        ),
        404,
    )


@app.errorhandler(413)
def request_entity_too_large(error):
    return (
        jsonify({"error": "File too large", "message": "Maximum file size is 100MB"}),
        413,
    )


@app.errorhandler(422)
def unprocessable_entity(error):
    return jsonify({"error": "Unprocessable entity", "message": str(error)}), 422


@app.errorhandler(500)
def internal_server_error(error):
    return (
        jsonify(
            {
                "error": "Internal server error",
                "message": "An unexpected error occurred",
            }
        ),
        500,
    )


# Request logging middleware (optional - for debugging)
@app.before_request
def log_request_info():
    if app.debug:
        from flask import request

        print(f"[{request.method}] {request.path}")


# Response time header - MODIFIED for PDF iframe support
@app.after_request
def add_header(response):
    # Security headers for non-PDF responses
    if not response.mimetype or "pdf" not in response.mimetype:
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
    else:
        # For PDF files, allow iframe from same origin
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = (
            "SAMEORIGIN"  # Allow iframe from same origin
        )
        # Remove CSP that might block PDF rendering
        if "Content-Security-Policy" in response.headers:
            del response.headers["Content-Security-Policy"]

    return response



def cleanup_orphaned_files():
    """Remove File records that point to non-existent physical files"""
    try:
        import os
        from models import File

        print("\n" + "="*60)
        print("🧹 Checking for orphaned file records...")
        print("="*60)

        all_files = File.query.all()
        orphaned = []

        for file in all_files:
            if not os.path.exists(file.file_path):
                orphaned.append(file)
                print(f"  ⚠️  Orphaned: {file.name} (ID: {file.id})")
                print(f"      Path: {file.file_path}")

        if orphaned:
            print(f"\n🗑️  Found {len(orphaned)} orphaned file records. Cleaning up...")
            for file in orphaned:
                print(f"  🗑️  Removing: {file.name} (ID: {file.id})")
                db.session.delete(file)
            db.session.commit()
            print(f"✅ Removed {len(orphaned)} orphaned file records\n")
        else:
            print("✅ No orphaned file records found\n")

        print("="*60)

    except Exception as e:
        print(f"❌ Error during cleanup: {str(e)}")
        import traceback
        traceback.print_exc()
        db.session.rollback()


# Initialize database
with app.app_context():
    db.create_all()
    print("✓ Database initialized successfully!")

    # Create default admin user if none exists
    from models import User

    if not User.query.first():
        admin = User(
            email="admin@dataroom.com",
            username="admin",
            full_name="Admin User",
            is_verified=True,
        )
        admin.set_password("Admin@123")
        db.session.add(admin)
        db.session.commit()
        print("✓ Default admin user created!")
        print("  Email: admin@dataroom.com")
        print("  Password: Admin@123")
        print("  ⚠️  Please change the password after first login!")

    # CLEANUP ORPHANED FILES ON STARTUP
    cleanup_orphaned_files()

if __name__ == "__main__":
    print("=" * 60)
    print("🚀 Starting Data Room API Server...")
    print("=" * 60)
    print(f"📁 Upload folder: {app.config['UPLOAD_FOLDER']}")
    print(f"💾 Database: {app.config['SQLALCHEMY_DATABASE_URI']}")
    print(f"🔒 Max file size: {app.config['MAX_CONTENT_LENGTH'] / 1024 / 1024}MB")
    print(f"🌐 CORS origins: {os.environ.get('CORS_ORIGINS', '*')}")
    print("=" * 60)
    print("📚 API Documentation: http://localhost:5000/api")
    print("❤️  Health Check: http://localhost:5000/api/health")
    print("=" * 60)

    app.run(
        debug=os.environ.get("FLASK_DEBUG", "True") == "True",
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
    )
