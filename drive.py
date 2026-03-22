"""Google Drive integration — upload/update files using service account credentials."""

from pathlib import Path

from google.oauth2.service_account import Credentials
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload

CREDENTIALS_FILE = Path(__file__).parent / "sheets_credentials.json"
FOLDER_ID = "1n5mRnvwg3910-HRpSErol57E3FELmbgk"
SCOPES = [
    "https://www.googleapis.com/auth/drive.file",
]


def _get_service():
    creds = Credentials.from_service_account_file(str(CREDENTIALS_FILE), scopes=SCOPES)
    return build("drive", "v3", credentials=creds)


def upload_or_update(local_path: str, drive_filename: str, mime_type: str = "application/octet-stream", file_id: str | None = None) -> dict:
    """Upload a file to Drive (or update existing by file_id).
    Returns dict with 'id' and 'webViewLink'.
    """
    service = _get_service()
    media = MediaFileUpload(local_path, mimetype=mime_type, resumable=False)

    if file_id:
        # Update existing file
        file = service.files().update(
            fileId=file_id,
            media_body=media,
            fields="id,webViewLink",
        ).execute()
    else:
        # Create new file
        metadata = {"name": drive_filename, "parents": [FOLDER_ID]}
        file = service.files().create(
            body=metadata,
            media_body=media,
            fields="id,webViewLink",
        ).execute()
        # Make it readable by anyone with link
        service.permissions().create(
            fileId=file["id"],
            body={"type": "anyone", "role": "reader"},
        ).execute()

    return file


if __name__ == "__main__":
    import sys
    import json

    local = "contest/setups/fuzzing_strategy.drawio"
    result = upload_or_update(
        local_path=local,
        drive_filename="fuzzing_strategy.drawio",
        mime_type="application/octet-stream",
    )
    print(f"File ID : {result['id']}")
    print(f"View URL: {result.get('webViewLink', '')}")
    print(f"draw.io : https://app.diagrams.net/#G{result['id']}")
