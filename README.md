# Data Room Backend

Flask-based REST API for the Data Room application.

## Features

- Complete CRUD operations for Data Rooms, Folders, and Files
- Nested folder structure support
- PDF file upload and storage
- Automatic duplicate name handling
- Cascade delete for folders
- RESTful API design

## Setup Instructions

1. Install Python dependencies:
```bash
pip install -r requirements.txt
```

2. Run the application:
```bash
python app.py
```

The server will start on http://localhost:5000

## API Endpoints

### Data Rooms
- POST /api/datarooms - Create data room
- GET /api/datarooms - List all data rooms
- GET /api/datarooms/:id - Get data room with contents
- DELETE /api/datarooms/:id - Delete data room

### Folders
- POST /api/folders - Create folder
- GET /api/folders/:id - Get folder with contents
- PUT /api/folders/:id - Update folder name
- DELETE /api/folders/:id - Delete folder (cascade)

### Files
- POST /api/files/upload - Upload file
- GET /api/files/:id - Get file metadata
- GET /api/files/:id/download - Download/view file
- PUT /api/files/:id - Update file name
- DELETE /api/files/:id - Delete file

## Database Schema

- datarooms: id, name, created_at
- folders: id, name, parent_id, dataroom_id, created_at
- files: id, name, original_name, folder_id, dataroom_id, file_path, size, mime_type, created_at

## Design Decisions

1. **SQLite for simplicity** - Easy to set up, can migrate to PostgreSQL
2. **UUID-based file storage** - Prevents filename conflicts
3. **Cascade deletes** - Automatically clean up nested content
4. **Auto-rename duplicates** - Better UX than rejecting uploads
5. **Separate routes** - Modular and maintainable code structure
