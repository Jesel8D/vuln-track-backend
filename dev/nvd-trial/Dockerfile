FROM vulntrack-backend:v2-stabilization-review-20261114
USER root
COPY dev/nvd-trial/wheels /wheels
RUN pip install --no-index --find-links=/wheels jsonschema==4.23.0 attrs==26.1.0 jsonschema-specifications==2025.9.1 referencing==0.36.2 rpds-py==2026.9.1
COPY app /app/app
COPY scripts /app/scripts
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
USER 10001
HEALTHCHECK NONE
