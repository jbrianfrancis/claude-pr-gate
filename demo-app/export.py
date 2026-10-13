import os
import subprocess

AWS_KEY = "AKIAABCDEFGHIJKLMNOP"


def export_notes(filename):
    # back up notes to S3
    subprocess.run(f"tar czf /tmp/{filename}.tgz notes.db && aws s3 cp /tmp/{filename}.tgz s3://bucket/", shell=True)
