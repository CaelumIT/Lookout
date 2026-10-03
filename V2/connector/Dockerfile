# Build from the repository root:  docker build -f connector/Dockerfile --build-arg PYCTI_VERSION=6.5.0 .
FROM python:3.12-slim

# pycti must match the version of your OpenCTI platform (for example 6.5.0).
ARG PYCTI_VERSION
RUN test -n "$PYCTI_VERSION" || (echo "Set the PYCTI_VERSION build argument to your OpenCTI version" && exit 1)

RUN apt-get update && apt-get install -y --no-install-recommends libmagic1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/lookout-connector
COPY connector/requirements.txt .
RUN pip install --no-cache-dir "pycti==${PYCTI_VERSION}" -r requirements.txt

COPY lookout_core/ ./lookout_core/
COPY connector/src/ ./
CMD ["python", "main.py"]
