#!/bin/bash
# Deploy AEGIS-IR to Google Cloud Run
# Usage: ./deploy.sh [project-id]

set -e

PROJECT_ID="${1:-projectl-488105}"
REGION="us-central1"
SERVICE_NAME="aegis-ir"
IMAGE="gcr.io/${PROJECT_ID}/${SERVICE_NAME}"

echo "=== AEGIS-IR Cloud Deployment ==="
echo "Project: ${PROJECT_ID}"
echo "Region:  ${REGION}"
echo "Service: ${SERVICE_NAME}"
echo ""

# Step 1: Enable required APIs
echo "→ Enabling APIs..."
gcloud services enable \
    run.googleapis.com \
    cloudbuild.googleapis.com \
    artifactregistry.googleapis.com \
    aiplatform.googleapis.com \
    secretmanager.googleapis.com \
    --project=${PROJECT_ID} --quiet

# Step 2: Create secrets (if not exist)
echo "→ Setting up secrets..."
echo -n "${SPLUNK_TOKEN}" | gcloud secrets create splunk-token \
    --data-file=- --project=${PROJECT_ID} 2>/dev/null || true
echo -n "${PHOENIX_API_KEY}" | gcloud secrets create phoenix-api-key \
    --data-file=- --project=${PROJECT_ID} 2>/dev/null || true

# Step 3: Build container
echo "→ Building container..."
gcloud builds submit --tag ${IMAGE}:latest --project=${PROJECT_ID}

# Step 4: Deploy to Cloud Run
echo "→ Deploying to Cloud Run..."
gcloud run deploy ${SERVICE_NAME} \
    --image=${IMAGE}:latest \
    --region=${REGION} \
    --platform=managed \
    --allow-unauthenticated \
    --memory=4Gi \
    --cpu=2 \
    --timeout=3600 \
    --max-instances=10 \
    --min-instances=0 \
    --set-env-vars="GOOGLE_GENAI_USE_VERTEXAI=1,GOOGLE_CLOUD_PROJECT=${PROJECT_ID},GOOGLE_CLOUD_LOCATION=${REGION},GEMINI_MODEL=gemini-2.5-flash,PHOENIX_MODE=cloud,PHOENIX_PROJECT_NAME=aegis-ir,SIFT_MODE=cloud" \
    --set-secrets="SPLUNK_TOKEN=splunk-token:latest,PHOENIX_API_KEY=phoenix-api-key:latest" \
    --project=${PROJECT_ID}

# Get URL
URL=$(gcloud run services describe ${SERVICE_NAME} --region=${REGION} --project=${PROJECT_ID} --format="value(status.url)")

echo ""
echo "=== Deployment Complete ==="
echo "Dashboard: ${URL}"
echo "Health:    ${URL}/api/health"
echo "Webhook:   ${URL}/api/splunk-alert"
echo "API Docs:  ${URL}/api/docs"
echo ""
