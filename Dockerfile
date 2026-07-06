# scopeward — stdlib-only, no runtime dependencies.
FROM python:3.12-slim

WORKDIR /app
COPY . /app

# Editable install exposes the `scopeward` console script.
RUN pip install --no-cache-dir -e .

# Run as a non-root user; scopeward never needs elevated privileges.
RUN useradd --create-home scopeward
USER scopeward

ENTRYPOINT ["scopeward"]
CMD ["--help"]
