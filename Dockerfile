FROM python:3.11.9-slim-bookworm

LABEL version="1.0.0"
LABEL description="IoChecker by TNO"

WORKDIR /iochecker

# Install necessary python dependencies
COPY requirements.txt ./
RUN python3 -m pip install --upgrade pip && pip3 install -r requirements.txt

# Copy program files to the container
COPY iochecker/*.py ./
COPY .env ./

ENTRYPOINT ["python", "iochecker.py"]