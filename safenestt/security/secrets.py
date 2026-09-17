"""Secrets management — env-based with KMS upgrade path.

This module provides secrets resolution with:
1. Development: .env files / environment variables
2. Production: AWS KMS, GCP KMS, or Azure Key Vault

Usage:
    from safenestt.security.secrets import get_secret
    
    api_key = get_secret("OPENROUTED_API_KEY")
    db_password = get_secret("DB_PASSWORD")
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any

logger = logging.getLogger(__name__)

# Cache for resolved secrets
_cache: dict[str, str] = {}


def get_secret(name: str, default: str | None = None, required: bool = False) -> str | None:
    """Resolve a secret by name with caching.
    
    Resolution order:
    1. Environment variable (highest priority)
    2. Docker secrets (/run/secrets/<name>)
    3. AWS SSM Parameter Store (if AWS_REGION set)
    4. Google Cloud Secret Manager (if GCP_PROJECT set)
    5. Default value
    """
    if name in _cache:
        return _cache[name]
    
    # 1. Environment variable
    value = os.getenv(name)
    if value:
        _cache[name] = value
        return value
    
    # 2. Docker secrets
    docker_secret_path = f"/run/secrets/{name.lower()}"
    if os.path.exists(docker_secret_path):
        try:
            with open(docker_secret_path) as f:
                value = f.read().strip()
            _cache[name] = value
            return value
        except Exception as exc:
            logger.warning("Failed to read Docker secret %s: %s", name, exc)
    
    # 3. AWS SSM Parameter Store
    aws_region = os.getenv("AWS_REGION")
    if aws_region:
        try:
            import boto3
            ssm = boto3.client("ssm", region_name=aws_region)
            response = ssm.get_parameter(
                Name=f"/safenestt/{os.getenv('ENV', 'production')}/{name}",
                WithDecryption=True
            )
            value = response["Parameter"]["Value"]
            _cache[name] = value
            return value
        except Exception as exc:
            logger.debug("AWS SSM lookup failed for %s: %s", name, exc)
    
    # 4. Google Cloud Secret Manager
    gcp_project = os.getenv("GCP_PROJECT")
    if gcp_project:
        try:
            from google.cloud import secretmanager
            client = secretmanager.SecretManagerServiceClient()
            secret_path = f"projects/{gcp_project}/secrets/{name}/versions/latest"
            response = client.access_secret_version(request={"name": secret_path})
            value = response.payload.data.decode("UTF-8")
            _cache[name] = value
            return value
        except Exception as exc:
            logger.debug("GCP Secret Manager lookup failed for %s: %s", name, exc)
    
    if required and default is None:
        raise RuntimeError(
            f"Required secret '{name}' not found. "
            "Set environment variable, Docker secret, or configure KMS."
        )
    
    return default


def clear_cache() -> None:
    """Clear the secrets cache. Useful for testing."""
    _cache.clear()


def validate_required_secrets() -> list[str]:
    """Check that all required production secrets are configured.
    
    Returns list of missing secrets (empty = all good).
    """
    required = [
        "SAFENESTT_ENCRYPTION_KEY",
        "SAFENESTT_DB_PASSWORD",
        "OPENROUTER_API_KEY",
    ]
    
    missing = []
    for name in required:
        value = get_secret(name)
        if not value:
            missing.append(name)
    
    return missing
