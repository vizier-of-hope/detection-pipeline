# Detection pipeline: reproducible validation + multi-SIEM compilation.
#
# Build:  docker build -t detection-pipeline .
# Run:    docker run --rm detection-pipeline                 # full gate suite
#         docker run --rm detection-pipeline pytest -q       # one step (override command)
#         docker run --rm -it detection-pipeline bash        # interactive shell
# See docs/ci/pipeline-docker.md for the full guide.
FROM python:3.13-slim

# Unbuffered output; UTF-8 everywhere (windash emits en/em dashes).
ENV PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING=utf-8 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /work

# Install pinned dependencies first so this layer is cached until requirements change.
COPY requirements.txt ./
RUN pip install -r requirements.txt

# Copy the detection content and tooling (.dockerignore keeps out .venv/build/caches/.git).
COPY . .

# Default command: the full gate suite. Override it to run a single tool
# (e.g. `docker run <img> python -m dettools.translate rules/.../foo.yml`).
CMD ["sh", "docker/gates.sh"]
